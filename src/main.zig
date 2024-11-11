const std = @import("std");
const fmt = std.fmt;
const heap = std.heap;
const io = std.io;
const json = std.json;
const log = std.log;
const os = std.os;
const posix = std.posix;
const process = std.process;

const cova = @import("cova");
const cli = @import("cli.zig");

const art = @import("art.zig");
const nl = @import("nl.zig");
const sys = @import("sys.zig");
const wpa = @import("wpa.zig");

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

    // Single Use
    // - Set
    if (main_cmd.matchSubCmd("set")) |set_cmd| {
        checkRoot(stdout_file.any());
        const set_opts = try set_cmd.getOpts(.{});
        if (set_opts.get("hostname")) |hn_opt| newHN: {
            const new_hn = hn_opt.val.getAs([]const u8) catch break :newHN;
            try stdout_file.print("Setting the hostname to {s}...\n", .{ new_hn });
            try sys.setHostName(new_hn);
        }
        // Set Interface
        if (set_cmd.matchSubCmd("interface")) |set_if_cmd| {
            checkIF(raw_net_if, stdout_file.any());
            const net_if: NetworkInterface = raw_net_if.?;
            const set_if_opts = try set_if_cmd.getOpts(.{});
            if (set_if_opts.get("mac")) |mac_opt| changeMAC: {
                try stdout_file.print("Setting the MAC for {s}...\n", .{ net_if.name });
                const new_mac = mac_opt.val.getAs([6]u8) catch break :changeMAC;
                nl.route.setMAC(net_if.route_info.index, new_mac) catch |err| switch (err) {
                    error.BUSY => {
                        log.err("The interface '{s}' is busy so the MAC could not be set.", .{ net_if.name });
                        return;
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
            if (set_if_opts.get("state")) |state_opt| changeState: {
                try stdout_file.print("Setting the State for {s}...\n", .{ net_if.name });
                const new_state = state_opt.val.getAs(nl.route.IFF) catch break :changeState;
                nl.route.setState(net_if.route_info.index, @intFromEnum(new_state)) catch |err| switch (err) {
                    error.BUSY => {
                        log.err("The interface '{s}' is busy so the State could not be set.", .{ net_if.name });
                        return;
                    },
                    else => {
                        log.err("Netlink request error. The State for interface '{s}' could not be set.", .{ net_if.name });
                        return;
                    },
                };
                try stdout_file.print("Set the State for {s} to {s}.\n", .{ net_if.name, @tagName(new_state) });
            }
            if (set_if_opts.get("mode")) |mode_opt| changeMode: {
                try stdout_file.print("Setting the Mode for {s}...\n", .{ net_if.name });
                const new_mode = mode_opt.val.getAs(nl._80211.IFTYPE) catch break :changeMode;
                nl._80211.setMode(net_if.route_info.index, @intFromEnum(new_mode)) catch |err| switch (err) {
                    error.BUSY => {
                        log.err("The interface '{s}' is busy so the Mode could not be set.", .{ net_if.name });
                        return;
                    },
                    else => {
                        log.err("Netlink request error. The Mode for interface '{s}' could not be set.", .{ net_if.name });
                        return;
                    },
                };
                try stdout_file.print("Set the Mode for {s} to {s}.\n", .{ net_if.name, @tagName(new_mode) });
            }
            raw_net_if = try NetworkInterface.get(net_if.name);
        }
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
        try stdout_file.print("Connecting to {s}...\n", .{ ssid });
        switch (security) {
            .open, .wep => {
                log.info("WIP!", .{});
                return;
            },
            .wpa2 => {
                const pmk = try wpa.genKey(.wpa2, ssid, pass);
                try nl._80211.connectWPA2(
                    alloc, 
                    net_if.route_info.index, 
                    ssid, 
                    pmk,
                    wpa.handle4WHS,
                );
            }, 
        }
    }

    // System Details
    var hn_buf: [64]u8 = .{ 0 } ** 64;
    const hostname = try posix.gethostname(hn_buf[0..]);
    try stdout.print(
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
