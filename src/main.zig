const std = @import("std");
const fmt = std.fmt;
const heap = std.heap;
const io = std.io;
const json = std.json;
const log = std.log;
const os = std.os;
const posix = std.posix;
const process = std.process;
const time = std.time;

const cova = @import("cova");
const cli = @import("cli.zig");

const art = @import("art.zig");
const dhcp = @import("dhcp.zig");
const netdata = @import("netdata.zig");
const nl = @import("nl.zig");
const sys = @import("sys.zig");
const utils = @import("utils.zig");
const wpa = @import("wpa.zig");

const address = netdata.address;
const MACF = address.MACFormatter;
const IPF = address.IPFormatter;
const c = utils.toStruct;
const NetworkInterface = @import("NetworkInterface.zig");

pub fn main() !void {
    const stdout_file = io.getStdOut().writer();
    var stdout_bw = io.bufferedWriter(stdout_file);
    defer stdout_bw.flush() catch log.warn("Couldn't flush stdout before exiting!", .{});
    const stdout = stdout_bw.writer().any();

    var gpa = heap.GeneralPurposeAllocator(.{ .thread_safe = true }){};
    defer if (gpa.detectLeaks()) log.err("Memory leak detected!", .{});
    const alloc = gpa.allocator();

    // Get NL80211 Control Info
    try nl._80211.initCtrlInfo(alloc);
    defer nl._80211.deinitCtrlInfo(alloc);

    // Parse Args
    var main_cmd = try cli.setup_cmd.init(alloc, .{});
    defer main_cmd.deinit();
    var args_iter = try cova.ArgIteratorGeneric.init(alloc);
    defer args_iter.deinit();
    cova.parseArgs(
        &args_iter,
        cli.CommandT,
        main_cmd,
        stdout,
        .{},
    ) catch |err| {
        try stdout_bw.flush();
        switch (err) {
            error.UsageHelpCalled => return,
            error.TooManyValues,
            error.UnrecognizedArgument,
            error.UnexpectedArgument,
            error.CouldNotParseOption => {},
            else => |parse_err| return parse_err,
        }
    };

    //const main_opts = try main_cmd.getOpts(.{});
    const main_vals = try main_cmd.getVals(.{});

    // No Interface Needed
    // - Generate Key
    if (main_cmd.matchSubCmd("gen-key")) |gen_key_cmd| {
        const gen_key_vals = try gen_key_cmd.getVals(.{});
        const key = try gen_key_cmd.callAs(wpa.genKey, null, [32]u8);
        var key_buf: [64]u8 = undefined;
        const end: usize = switch (try (gen_key_vals.get("protocol").?).getAs(wpa.Protocol)) {
            .wpa2 => 32,
            .wep => 13,
            else => 0,
        };
        for (key[0..end], 0..) |byte, idx| _ = try fmt.bufPrint(key_buf[(idx * 2)..(idx * 2 + 2)], "{X:0<2}", .{ byte });
        try stdout.print(
            \\Generated Key:
            \\ - Protocol:   {s}
            \\ - SSID:       {s}
            \\ - Passphrase: {s}
            \\ - Key:        {s}
            \\
            \\
            , .{
                @tagName(try (gen_key_vals.get("protocol").?).getAs(wpa.Protocol)),
                try (gen_key_vals.get("ssid").?).getAs([]const u8),
                try (gen_key_vals.get("passphrase").?).getAs([]const u8),
                key_buf[0..],
            }
        );
        try stdout_bw.flush();
        return;
    }
    // - System
    if (main_cmd.matchSubCmd("system")) |sys_cmd| {
        checkRoot(stdout_file.any());
        if (sys_cmd.matchSubCmd("set")) |set_cmd| {
            const set_opts = try set_cmd.getOpts(.{});
            if (set_opts.get("hostname")) |hn_opt| newHN: {
                const new_hn = hn_opt.val.getAs([]const u8) catch break :newHN;
                try stdout_file.print("Setting the hostname to {s}...\n", .{ new_hn });
                try sys.setHostName(new_hn);
            }
        }
    }

    // DHCP Info
    var dhcp_info: ?dhcp.Info = null;
    // Interface
    var raw_net_if = netIF: {
        const if_name = (main_vals.get("interface").?).getAs([]const u8) catch break :netIF null;
        break :netIF NetworkInterface.get(if_name) catch |err| switch (err) {
            error.NoInterfaceFound => {
                log.err("Netlink request timed out. Could not find the '{s}' interface.", .{ if_name });
                return;
            },
            else => return err,
        };
    };
    defer if (main_cmd.matchSubCmd("connect")) |connect_cmd| cleanup: {
        var net_if = raw_net_if orelse break :cleanup;
        net_if.update() catch break :cleanup;
        if (connect_cmd.checkFlag("dhcp")) dhcp: {
            const d_info = dhcp_info orelse break :dhcp;
            dhcp.releaseDHCP(
                net_if.name,
                net_if.index,
                net_if.route_info.mac,
                d_info.server_id,
                d_info.assigned_ip,
            ) catch log.warn("Could not release DHCP lease for `{s}`!", .{ d_info.assigned_ip });
        }
        for (net_if.route_info.ips, net_if.route_info.cidrs) |_ip, _cidr| {
            const ip = _ip orelse continue;
            const cidr = _cidr orelse 24;
            defer nl.route.deleteIP(
                alloc,
                net_if.route_info.index,
                ip,
                cidr,
            ) catch |err| switch (err) {
                error.ADDRNOTAVAIL => {},
                else => log.warn("Could not remove IP `{s}`!", .{ IPF{ .bytes = ip[0..] } }),
            };
        }
    };

    // Single Use
    // - Set
    if (main_cmd.matchSubCmd("set")) |set_cmd| {
        checkRoot(stdout_file.any());
        checkIF(raw_net_if, stdout_file.any());
        const net_if: NetworkInterface = raw_net_if.?;
        const set_if_opts = try set_cmd.getOpts(.{});
        if (set_if_opts.get("mac")) |mac_opt| setMAC: {
            const new_mac = mac_opt.val.getAs([6]u8) catch break :setMAC;
            try stdout_file.print("Setting the MAC for {s}...\n", .{ net_if.name });
            nl.route.setMAC(net_if.route_info.index, new_mac) catch |err| switch (err) {
                error.OutOfMemory => {
                    log.err("Out of Memory!", .{});
                    return err;
                },
                error.BUSY => {
                    log.err("The interface '{s}' is busy so the MAC could not be set.", .{ net_if.name });
                    break :setMAC;
                },
                else => {
                    log.err("Netlink request error. The MAC for interface '{s}' could not be set.", .{ net_if.name });
                    return;
                },
            };
            var mac_buf: [17]u8 = .{ ':' } ** 17;
            for (new_mac, 0..6) |byte, idx| {
                const start = if (idx == 0) 0 else idx * 3;
                const end = start + 2;
                _ = try fmt.bufPrint(mac_buf[start..end], "{X:0>2}", .{ byte });
            }
            try stdout_file.print("Set the MAC for {s} to {s}.\n", .{ net_if.name, mac_buf });
        }
        if (set_if_opts.get("state")) |state_opt| setState: {
            const new_state, const flag_name = newState: {
                const states = state_opt.val.getAllAs(nl.route.IFF) catch break :setState;
                var new_state: u32 = 0;
                for (states) |state| new_state |= @intFromEnum(state);
                break :newState .{
                    new_state,
                    if (states.len == 1) @tagName(states[0]) else "Combined-State",
                };
            };
            try stdout_file.print("Setting the State for {s}...\n", .{ net_if.name });
            nl.route.setState(net_if.route_info.index, new_state) catch |err| switch (err) {
                error.OutOfMemory => {
                    log.err("Out of Memory!", .{});
                    return err;
                },
                error.BUSY => {
                    log.err("The interface '{s}' is busy so the State could not be set.", .{ net_if.name });
                    break :setState;
                },
                else => {
                    log.err("Netlink request error. The State for interface '{s}' could not be set.", .{ net_if.name });
                    return;
                },
            };
            try stdout_file.print("Set the State for {s} to {s}.\n", .{ net_if.name, flag_name });
        }
        if (set_if_opts.get("mode")) |mode_opt| setMode: {
            const new_mode = mode_opt.val.getAs(nl._80211.IFTYPE) catch break :setMode;
            try stdout_file.print("Setting the Mode for {s}...\n", .{ net_if.name });
            nl.route.setState(net_if.route_info.index, c(nl.route.IFF).DOWN) catch { 
                log.warn("Unable to set the interface down.", .{});
            };
            defer nl.route.setState(net_if.route_info.index, c(nl.route.IFF).UP) catch {
                log.warn("Unable to set the interface up.", .{});
            };
            time.sleep(100 * time.ns_per_ms);
            nl._80211.setMode(net_if.route_info.index, @intFromEnum(new_mode)) catch |err| switch (err) {
                error.OutOfMemory => {
                    log.err("Out of Memory!", .{});
                    return err;
                },
                error.BUSY => {
                    log.err("The interface '{s}' is busy so the Mode could not be set.", .{ net_if.name });
                    break :setMode;
                },
                else => {
                    log.err("Netlink request error. The Mode for interface '{s}' could not be set.", .{ net_if.name });
                    return;
                },
            };
            try stdout_file.print("Set the Mode for {s} to {s}.\n", .{ net_if.name, @tagName(new_mode) });
        }
        if (set_if_opts.get("channel")) |chan_opt| setChannel: {
            const new_ch = chan_opt.val.getAs(usize) catch break :setChannel;
            const new_ch_width = newChMain: {
                const new_ct_opt = set_if_opts.get("channel-width") orelse break :newChMain nl._80211.CHANNEL_WIDTH.@"20_NOHT";
                break :newChMain new_ct_opt.val.getAs(nl._80211.CHANNEL_WIDTH) catch nl._80211.CHANNEL_WIDTH.@"20_NOHT";
            };
            try stdout_file.print("Setting the Channel for {s}...\n", .{ net_if.name });
            nl.route.setState(net_if.route_info.index, c(nl.route.IFF).DOWN) catch { 
                log.warn("Unable to set the interface down.", .{});
            };
            time.sleep(100 * time.ns_per_ms);
            try nl._80211.setMode(net_if.route_info.index, c(nl._80211.IFTYPE).MONITOR);
            nl.route.setState(net_if.route_info.index, c(nl.route.IFF).UP) catch {
                log.warn("Unable to set the interface up.", .{});
            };
            time.sleep(100 * time.ns_per_ms);
            nl._80211.setChannel(net_if.route_info.index, new_ch, new_ch_width) catch |err| switch (err) {
                error.OutOfMemory => {
                    log.err("Out of Memory!", .{});
                    return err;
                },
                error.BUSY => {
                    log.err("The interface '{s}' is busy so the Channel could not be set.", .{ net_if.name });
                    break :setChannel;
                },
                error.InvalidChannel, error.InvalidFrequency => {
                    log.err("The channel '{d}' is invalid.", .{ new_ch });
                    break :setChannel;
                },
                else => {
                    log.err("Netlink request error. The Channel for interface '{s}' could not be set.", .{ net_if.name });
                    return err;
                },
            };
            try stdout_file.print("Set the Channel for {s} to {d}.\n", .{ net_if.name, new_ch });
        }
        if (set_if_opts.get("frequency")) |freq_opt| setFreq: {
            const new_freq = freq_opt.val.getAs(usize) catch break :setFreq;
            const new_ch_width = newChMain: {
                const new_ct_opt = set_if_opts.get("channel-width") orelse break :newChMain nl._80211.CHANNEL_WIDTH.@"20_NOHT";
                break :newChMain new_ct_opt.val.getAs(nl._80211.CHANNEL_WIDTH) catch nl._80211.CHANNEL_WIDTH.@"20_NOHT";
            };
            try stdout_file.print("Setting the Channel for {s}...\n", .{ net_if.name });
            try nl._80211.setMode(net_if.route_info.index, c(nl._80211.IFTYPE).MONITOR);
            nl.route.setState(net_if.route_info.index, c(nl.route.IFF).UP) catch {
                log.warn("Unable to set the interface up.", .{});
            };
            time.sleep(100 * time.ns_per_ms);
            nl._80211.setFreq(net_if.route_info.index, new_freq, new_ch_width) catch |err| switch (err) {
                error.OutOfMemory => {
                    log.err("Out of Memory!", .{});
                    return err;
                },
                error.BUSY => {
                    log.err("The interface '{s}' is busy so the Frequency could not be set.", .{ net_if.name });
                    break :setFreq;
                },
                error.InvalidFrequency => {
                    log.err("The Frequency '{d}'MHz is invalid.", .{ new_freq });
                    break :setFreq;
                },
                else => {
                    log.err("Netlink request error. The Frequency for interface '{s}' could not be set.", .{ net_if.name });
                    return err;
                },
            };
            try stdout_file.print("Set the Frequency for {s} to {d}.\n", .{ net_if.name, new_freq });
        }
        raw_net_if = try NetworkInterface.get(net_if.name);
    }
    if (main_cmd.matchSubCmd("add")) |add_cmd| {
        checkRoot(stdout_file.any());
        checkIF(raw_net_if, stdout_file.any());
        const net_if: NetworkInterface = raw_net_if.?;
        const add_opts = try add_cmd.getOpts(.{});
        //const cidr = try (add_opts.get("subnet").?).val.getAs(u8);
        if (add_opts.get("ip")) |ip_opt| setIP: {
            const ip = try ip_opt.val.getAs(address.IPv4);
            try stdout_file.print("Adding new IP Address '{s}'...\n", .{ ip });
            nl.route.addIP(
                alloc,
                net_if.route_info.index,
                ip.addr,
                ip.cidr,
            ) catch |err| switch (err) {
                error.EXIST => {
                    try stdout_file.print("The IP Address '{s}' is already set.\n", .{ ip });
                    break :setIP;
                },
                else => return err,
            };
            try stdout_file.print("Added new IP Address '{s}'.\n", .{ ip });
        }
        if (add_opts.get("route")) |route_opt| setRoute: {
            const route = try route_opt.val.getAs(address.IPv4);
            try stdout_file.print("Adding new Route '{s}'...\n", .{ route });
            const gateway = gw: {
                break :gw if (add_opts.get("gateway")) |gw_opt|
                    (gw_opt.val.getAs(address.IPv4) catch break :gw null).addr
                else null;
            };
            nl.route.addRoute(
                alloc,
                net_if.route_info.index,
                route.addr,
                .{ 
                    .cidr = route.cidr,
                    .gateway = gateway,
                },
            ) catch |err| switch (err) {
                error.EXIST => {
                    try stdout_file.print("The Route '{s}' is already set.\n", .{ route });
                    break :setRoute;
                },
                error.NETUNREACH => {
                    try stdout_file.print("The Gateway '{?s}' is invalid.\n", .{ gateway });
                    break :setRoute;
                },
                else => return err,
            };
            try stdout_file.print("Added new Route '{s}'.\n", .{ route });
        }
        time.sleep(100 * time.ns_per_ms);
    }
    if (main_cmd.matchSubCmd("delete")) |del_cmd| {
        checkRoot(stdout_file.any());
        checkIF(raw_net_if, stdout_file.any());
        const net_if: NetworkInterface = raw_net_if.?;
        const del_opts = try del_cmd.getOpts(.{});
        //const cidr = try (del_opts.get("subnet").?).val.getAs(u8);
        if (del_opts.get("ip")) |ip_opt| setIP: {
            const ip = try ip_opt.val.getAs(address.IPv4);
            try stdout_file.print("Deleting the IP Address '{s}'...\n", .{ ip });
            nl.route.deleteIP(
                alloc,
                net_if.route_info.index,
                ip.addr,
                ip.cidr,
            ) catch |err| switch (err) {
                error.ADDRNOTAVAIL => {
                    try stdout_file.print("The IP Address '{s}' could not be found.\n", .{ ip });
                    break :setIP;
                },
                else => return err,
            };
            try stdout_file.print("Deleted the IP Address '{s}'.\n", .{ ip });
        }
        if (del_opts.get("route")) |route_opt| delRoute: {
            const route = try route_opt.val.getAs(address.IPv4);
            try stdout_file.print("Deleting Route '{s}'...\n", .{ route });
            const gateway = gw: {
                break :gw if (del_opts.get("gateway")) |gw_opt|
                    (gw_opt.val.getAs(address.IPv4) catch break :gw null).addr
                else null;
            };
            nl.route.deleteRoute(
                alloc,
                net_if.route_info.index,
                route.addr,
                .{ 
                    .cidr = route.cidr,
                    .gateway = gateway,
                },
            ) catch |err| switch (err) {
                error.ADDRNOTAVAIL,
                error.SRCH => {
                    try stdout_file.print("The Route '{s}' could not be found.\n", .{ route });
                    break :delRoute;
                },
                else => return err,
            };
            try stdout_file.print("Deleted Route '{s}'.\n", .{ route });
        }
        time.sleep(100 * time.ns_per_ms);
    }
    if (main_cmd.matchSubCmd("connect")) |connect_cmd| {
        checkRoot(stdout_file.any());
        checkIF(raw_net_if, stdout_file.any());
        const net_if: NetworkInterface = raw_net_if.?;
        const connect_vals = try connect_cmd.getVals(.{});
        const connect_opts = try connect_cmd.getOpts(.{});
        const ssid = (connect_vals.get("ssid").?).getAs([]const u8) catch {
            log.err("DisCo needs to know the SSID of the network to connect.", .{});
            return;
        };
        const security,
        const pass = security: {
            const security = try (connect_opts.get("security").?).val.getAs(wpa.Protocol);
            break :security switch (security) {
                .open => .{ security, "" },
                .wep, .wpa2 => .{
                    security,
                    (connect_opts.get("passphrase").?).val.getAs([]const u8) catch {
                        log.err("The {s} protocol requires a passhprase.", .{ @tagName(security) });
                        return;
                    }
                },
            };
        };
        const freqs = freqs: {
            const ch_opt = connect_opts.get("channels") orelse break :freqs null;
            if (!ch_opt.val.isSet()) break :freqs null;
            const channels = try ch_opt.val.getAllAs(usize);
            var freqs_buf = try std.ArrayListUnmanaged(u32).initCapacity(alloc, 1);
            for (channels) |ch|
                try freqs_buf.append(alloc, @intCast(try nl._80211.freqFromChannel(ch)));
            break :freqs try freqs_buf.toOwnedSlice(alloc);
        };
        defer if (freqs) |_freqs| alloc.free(_freqs);
        try stdout_file.print("Connecting to {s}...\n", .{ ssid });
        switch (security) {
            .open, .wep => {
                log.info("WIP!", .{});
                return;
            },
            .wpa2 => {
                const pmk = try wpa.genKey(.wpa2, ssid, pass);
                _ = try nl._80211.connectWPA2(
                    alloc,
                    net_if.route_info.index,
                    ssid,
                    pmk,
                    wpa.handle4WHS,
                    .{ .freqs = freqs },
                );
                try stdout_file.print("Connected to {s}.\n", .{ ssid });
            }, 
        }
        if (connect_cmd.checkFlag("dhcp")) dhcp: {
            try stdout_file.print("Obtaining an IP Address via DHCP...\n", .{});
            const gateway = connect_cmd.checkFlag("gateway");
            dhcp_info = dhcp.handleDHCP(
                net_if.name,
                net_if.route_info.index,
                net_if.route_info.mac,
                .{},
            ) catch |err| switch (err) {
                error.WouldBlock => {
                    log.warn("The DHCP process timed out.", .{});
                    break :dhcp;
                },
                else => return err,
            };
            const dhcp_cidr = address.cidrFromSubnet(dhcp_info.?.subnet_mask);
            nl.route.addIP(
                alloc,
                net_if.route_info.index,
                dhcp_info.?.assigned_ip,
                dhcp_cidr,
            ) catch |err| switch (err) {
                error.EXIST => {
                    log.warn("The Interface already has an IP.", .{});
                    break :dhcp;
                },
                else => return err,
            };
            if (gateway) {
                try nl.route.addRoute(
                    alloc,
                    net_if.route_info.index,
                    address.IPv4.default.addr,
                    .{
                        .cidr = address.IPv4.default.cidr,
                        .gateway = dhcp_info.?.router,
                    }
                );
            }
        }
        time.sleep(10 * time.ns_per_s);
    }

    // System Details
    var hn_buf: [64]u8 = .{ 0 } ** 64;
    const hostname = try posix.gethostname(hn_buf[0..]);
    try stdout.print(
        \\
        \\System Details:
        \\ - Hostname: {s}
        \\
        \\
        , .{
            hostname,
        },
    );
    // Interface Details
    if (raw_net_if) |net_if| {
        try stdout.print(
            \\Interface Details:
            \\{s}
            \\
            , .{ net_if }
        );

    }
    try stdout.print("\n", .{});
    try stdout_bw.flush();

}

/// Check for Root 
fn checkRoot(stdout: io.AnyWriter) void {
    if (os.linux.getuid() != 0) {
        stdout.print("{s}\n\n                          DisCo must be run as sudo!\n", .{ art.sudo }) catch { 
            log.err("DisCo must be run as sudo! (There was also an issue writing to stdout.)", .{});
        };
        process.exit(1);
    }
}

/// Check that there's an Interface
fn checkIF(net_if: ?NetworkInterface, stdout: io.AnyWriter) void {
    if (net_if) |_| return;
    stdout.print("{s}\n\n   DisCo needs to know which interface to use. (Ex: disco wlan0)\n", .{ art.wifi_card }) catch {
        log.err("DisCo needs to know which interface to use. (Ex: disco wlan0)", .{});
    };
    process.exit(0);
}
