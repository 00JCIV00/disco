const std = @import("std");
const crypto = std.crypto;
const fmt = std.fmt;
const fs = std.fs;
const heap = std.heap;
const io = std.io;
const json = std.json;
const log = std.log;
const mem = std.mem;
const os = std.os;
const posix = std.posix;
const process = std.process;
const time = std.time;

const cova = @import("cova");
const cli = @import("cli.zig");

const config_fields = @embedFile("config_fields");

const art = @import("art.zig");
const core = @import("core.zig");
const netdata = @import("netdata.zig");
const nl = @import("netlink.zig");
const proto = @import("protocols.zig");
const sys = @import("sys.zig");
const utils = @import("utils.zig");

const dhcp = proto.dhcp;
const serve = proto.serve;
const wpa = proto.wpa;
const address = netdata.address;
const oui = netdata.oui;
const MACF = address.MACFormatter;
const IPF = address.IPFormatter;
const masks_map = core.profiles.Mask.map;
const c = utils.toStruct;

// Cleaning Hang Protection
var cleaning: bool = false;
// Forcing Close
var forcing_close: bool = false;
// Panic Messaging
var panicking: bool = false;
// Core Context
var _core_ctx: ?core.Core = null;
// TODO: Pull these into Core context
// Active
var active: bool = false;
// Connect
var connected: bool = false;
// DHCP Info
var dhcp_info: ?dhcp.Info = null;
// Interface
var raw_net_if: ?core.interfaces.Interface = null;

pub fn main() !void {
    // Catch Forced Close
    try posix.sigaction(
        posix.SIG.INT,
        &.{
            .handler = .{ .handler = forceClose },
            .mask = posix.empty_sigset,
            .flags = 0,
        },
        null,
    );

    const stdout_file = io.getStdOut().writer();
    var stdout_bw = io.bufferedWriter(stdout_file);
    defer stdout_bw.flush() catch log.warn("Couldn't flush stdout before exiting!", .{});
    const stdout = stdout_bw.writer().any();
    try stdout_file.print("{s}\n", .{ art.logo });

    var gpa = heap.GeneralPurposeAllocator(.{ .thread_safe = true, .stack_trace_frames = 25 }){};
    defer {
        if (@import("builtin").mode == .Debug and gpa.detectLeaks()) 
            log.err("Memory leak detected!", .{})
        else if (gpa.deinit() == .leak)
            log.err("Memory leak detected!", .{});
    }
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
            error.CouldNotParseOption => posix.exit(1),
            else => |parse_err| return parse_err,
        }
    };

    //const main_vals = try main_cmd.getVals(.{});

    // No Interface Needed
    // - Generate Key
    if (main_cmd.matchSubCmd("gen-key")) |gen_key_cmd| {
        const gen_key_vals = try gen_key_cmd.getVals(.{});
        const key = try gen_key_cmd.callAs(wpa.genKey, null, [32]u8);
        var key_buf: [64]u8 = undefined;
        const end: usize = switch (try (gen_key_vals.get("protocol").?).getAs(nl._80211.SecurityType)) {
            .wpa2, .wpa3t, .wpa3 => 32,
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
                @tagName(try (gen_key_vals.get("protocol").?).getAs(nl._80211.SecurityType)),
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
    // - List
    if (main_cmd.matchSubCmd("list")) |list_cmd| {
        const list_opts = try list_cmd.getOpts(.{});
        const list_vals = try list_cmd.getVals(.{});
        const item_list: []const []const u8 = itemList: { 
            if (list_vals.get("item_list")) |il_val|
                break :itemList try il_val.getAllAs([]const u8);
            break :itemList &.{};
        };
        const masks_val_set: bool =
            for (item_list) |item| {
                if (mem.eql(u8, item, "masks")) break true;
            }
            else false;
        if (list_opts.get("masks") != null or masks_val_set) {
            try stdout.print(
                \\Profile Masks:
                \\(Specify one of these with `--mask` to hide your System Details.)
                \\
                \\
                , .{},
            );
            for (masks_map.keys()) |key| {
                try stdout.print(
                    \\{s}
                    \\{s}
                    \\
                    , .{
                        key,
                        masks_map.get(key).?,
                    },
                );
            }
            try stdout_bw.flush();
        }
        const conflicts_val_set: bool =
            for (item_list) |item| {
                if (mem.eql(u8, item, "pids")) break true;
                if (mem.eql(u8, item, "conflict-pids")) break true;
                if (mem.eql(u8, item, "conflicts")) break true;
                if (mem.eql(u8, item, "procs")) break true;
                if (mem.eql(u8, item, "processes")) break true;
            }
            else false;
        if (list_opts.get("conflict_pids") != null or conflicts_val_set) {
            try stdout.print(
                \\Conflict PIDs:
                \\(You may want to kill these with `kill` or `pkill` to prevent issues with DisCo.)
                \\
                , .{}
            );
            try stdout_bw.flush();
            const core_conf: core.Core.Config = .{};
            try core.findConflictPIDs(
                alloc, 
                core_conf.conflict_proc_names,
                stdout,
                "- '{s}' process running {d} time(s) (PID(s): {d}).\n"
            );
            try stdout_bw.flush();
        }
        const config_val_set: bool =
            for (item_list) |item| {
                if (mem.eql(u8, item, "config")) break true;
                if (mem.eql(u8, item, "fields")) break true;
            }
            else false;
        if (list_opts.get("config") != null or config_val_set) {
            try stdout.print(
                \\These fields can be provided in a JSON file to configure DisCo using `-c` or `--config`.
                \\You can also create the file `/root/.configs/disco/config.json` to provide a persistent config.
                \\{s}
                , .{ config_fields }
            );
            try stdout_bw.flush();
        }
        posix.exit(0);
    }
    // - File Serve
    if (main_cmd.matchSubCmd("serve")) |serve_cmd| {
        const serve_opts = try serve_cmd.getOpts(.{});
        const port = try serve_opts.get("port").?.val.getAs(u16);
        const dir = try serve_opts.get("directory").?.val.getAs([]const u8);
        active = true;
        try serve.serveDir(port, dir, &active);
        while (active) {}
        return;
    }

    // Set up Core Data
    const main_opts = try main_cmd.getOpts(.{});
    var core_if_indexes: std.ArrayListUnmanaged(i32) = .{};
    defer core_if_indexes.deinit(alloc);
    var core_scan_confs: std.ArrayListUnmanaged(core.Core.Config.ScanConfig) = .{};
    defer core_scan_confs.deinit(alloc);
    const if_names: []const []const u8 = ifOpt: {
        if (main_opts.get("interfaces")) |if_opt| {
            const ssids = ssids: {
                const ssids_opt = main_opts.get("ssids").?;
                break :ssids try ssids_opt.val.getAllAs([]const u8);
            };
            const channels: ?[]const usize = getChs: {
                const ch_opt = main_opts.get("channels") orelse break :getChs null;
                break :getChs try ch_opt.val.getAllAs(usize);
            };
            const if_names = if_opt.val.getAllAs([]const u8) catch break :ifOpt &.{};
            for (if_names) |if_name| {
                try core_scan_confs.append(alloc, .{ 
                    .if_name = if_name,
                    .ssids = ssids,
                    .channels = channels,
                });
            }
            break :ifOpt if_names;
        }
        else break :ifOpt &.{};
    };
    const profile_mask: ?core.profiles.Mask = getMask: {
        if (main_cmd.checkArgGroup(.Command, "INTERFACE")) {
            var hn_buf: [posix.HOST_NAME_MAX]u8 = undefined;
            var mask = masks_map.get("intel windows 11 pc").?;
            mask.hostname = try posix.gethostname(hn_buf[0..]);
            break :getMask mask;
        }
        if (!main_cmd.checkArgGroup(.Option, "MASK")) {
            if (main_cmd.checkOpts(&.{ "config" }, .{})) break :getMask null;
            //if (main_opts.get("config")) |_| break :getMask null;
            const mask_idx = crypto.random.int(u16) % masks_map.keys().len;
            for (masks_map.keys(), 0..) |key, idx| {
                if (idx != mask_idx) continue;
                const mask = masks_map.get(key).?;
                log.info("No Profile Mask provided. Defaulting to a random '{s}' Profile Mask:\n{s}", .{ 
                    try oui.findOUI(.long, mask.oui.? ++ .{ 0, 0, 0 }),
                    mask,
                });
                break :getMask mask;
            }
        }
        if (main_opts.get("mask")) |mask_opt| {
            const mask = try mask_opt.val.getAs(core.profiles.Mask);
            log.info("Using the provided '{s}' Profile Mask:\n{s}", .{
                try oui.findOUI(.long, mask.oui.? ++ .{ 0, 0, 0 }),
                mask,
            });
            break :getMask mask;
        }
        const mask: core.profiles.Mask = .{
            .oui = getOUI: {
                if (main_opts.get("mask_oui")) |oui_opt| 
                    break :getOUI try oui_opt.val.getAs([3]u8);
                break :getOUI try oui.getOUI("Intel");
            },
            .hostname = getHN: {
                if (main_opts.get("mask_hostname")) |hn_opt|
                    break :getHN try hn_opt.val.getAs([]const u8);
                break :getHN "localhost";
            },
            .ttl = getTTL: {
                if (main_opts.get("mask_ttl")) |ttl_opt|
                    break :getTTL try ttl_opt.val.getAs(u8);
                break :getTTL 64;
            },
            .ua_str = getUA: {
                if (main_opts.get("mask_ua")) |ua_opt|
                    break :getUA try ua_opt.val.getAs([]const u8);
                break :getUA "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
            },
        };
        log.info("Using your Custom Profile Mask:\n{s}", .{ mask });
        break :getMask mask;
    };
    const core_conn_confs: []core.connections.Config = connConfs: {
        const conn_opt = main_opts.get("connect_info") orelse break :connConfs &.{};
        break :connConfs conn_opt.val.getAllAs(core.connections.Config) catch &.{};
    };
    // Initialize Core Context
    const core_config: core.Core.Config = config: {
        var config: core.Core.Config = .{};
        const cova_alloc = main_cmd._alloc orelse return error.CovaCommandUnitialized;
        defaultConf: {
            var user_buf: [100]u8 = .{ 0 } ** 100;
            const user = sys.getUser(user_buf[0..]) orelse break :defaultConf;
            log.debug("Current User: {s}", .{ user });
            var path_buf: [fs.max_path_bytes]u8 = .{ 0 } ** fs.max_path_bytes;
            const default_conf_path = confPath: {
                if (mem.eql(u8, user, "root")) break :confPath "/root/.config/disco/config.json";
                break :confPath fmt.bufPrint(path_buf[0..], "/home/{s}/.config/disco/config.json", .{ user }) catch break :defaultConf;
            };
            var cwd = fs.cwd();
            const default_conf = cwd.openFile(default_conf_path, .{}) catch {
                log.info("No Default Config found at: '{s}'", .{ default_conf_path });
                break :defaultConf;
            };
            const config_bytes = default_conf.readToEndAlloc(cova_alloc, 1_000_000) catch break :defaultConf;
            config = json.parseFromSliceLeaky(
                core.Core.Config,
                cova_alloc,
                config_bytes,
                .{
                    .duplicate_field_behavior = .use_first,
                    .allocate = .alloc_always,
                    //.ignore_unknown_fields = true,
                },
            ) catch |err| {
                log.warn("There was an error with the Default Config: {s}", .{ @errorName(err) });
                break :defaultConf;
            };
            log.info("Imported the Default Config at '{s}'!", .{ default_conf_path });
        }
        if (main_opts.get("config")) |config_opt| userConf: {
            const config_file = config_opt.val.getAs(fs.File) catch break :userConf;
            defer config_file.close();
            const config_bytes = config_file.readToEndAlloc(cova_alloc, 1_000_000) catch break :userConf;
            config = json.parseFromSliceLeaky(
                core.Core.Config,
                cova_alloc,
                config_bytes,
                .{
                    .duplicate_field_behavior = .use_first,
                    .allocate = .alloc_always,
                    //.ignore_unknown_fields = true,
                },
            ) catch |err| {
                log.warn("There was an error with the provided Config: {s}", .{ @errorName(err) });
                break :userConf;
            };
            log.info("Imported provided Config!", .{});
        }
        if (if_names.len > 0) config.avail_if_names = if_names;
        for (config.avail_if_names) |if_name| {
            const if_index = nl.route.getIfIdx(if_name) catch {
                log.warn("Could not find Interface '{s}'.", .{ if_name });
                continue;
            };
            try core_if_indexes.append(alloc, if_index);
        }
        if (core_if_indexes.items.len > 0) {
            //config.avail_if_indexes = try core_if_indexes.toOwnedSlice(alloc);
            config.avail_if_indexes = core_if_indexes.items; 
        }
        if (config.scan_configs.len == 0 and core_scan_confs.items.len == 0) {
            for (config.avail_if_names) |if_name| {
                try core_scan_confs.append(alloc, .{
                    .if_name = if_name,
                    .ssids = &.{},
                    .channels = &.{},
                });
            }
        }
        //if (core_scan_confs.items.len > 0) config.scan_configs = try core_scan_confs.toOwnedSlice(alloc);
        if (core_scan_confs.items.len > 0) config.scan_configs = core_scan_confs.items;
        if (main_cmd.checkOpts(&.{ "gateway" }, .{})) {
            for (core_conn_confs) |*conn_conf| conn_conf.add_gw = true;
        }
        if (core_conn_confs.len > 0) config.connect_configs = core_conn_confs;
        if (profile_mask) |pro_mask| config.profile_mask = pro_mask;
        break :config config;
    };
    _core_ctx = try core.Core.init(alloc, core_config);
    var core_ctx = _core_ctx orelse return error.CoreNotInitialized;
    // Start Core Context
    if (main_cmd.sub_cmd == null) {
        //try core_ctx.start();
        const core_thread = try std.Thread.spawn(.{}, core.Core.start, .{ &core_ctx });
        core_thread.detach();
        const stdin = io.getStdIn().reader();
        //var active: bool = true;
        //while (active) {
        //}
        const input = try stdin.readUntilDelimiterOrEofAlloc(alloc, '\n', 4096);
        defer if (input) |in| alloc.free(in);
        core_ctx.stop();
        return;
        //posix.exit(0);
    }
    const num_avail_ifs = numAvailIFs: {
        var if_iter = core_ctx.if_ctx.interfaces.iterator();
        defer if_iter.unlock();
        var count: usize = 0;
        while (if_iter.next()) |if_entry| {
            if (if_entry.value_ptr.usage == .unavailable) continue;
            count += 1;
        }
        break :numAvailIFs count;
    };
    defer cleanUp(0);

    // Single Use
    // - Set
    if (main_cmd.matchSubCmd("set")) |set_cmd| {
        checkRoot(stdout_file.any());
        const set_ifs = core_ctx.if_ctx.interfaces;
        if (num_avail_ifs == 0) checkIF(stdout, "set");
        var if_iter = set_ifs.iterator();
        defer {
            if_iter.unlock();
            core.interfaces.updInterfaces(
                alloc,
                &core_ctx.if_ctx,
                &core_ctx.config,
                &core_ctx.interval,
            ) catch |err|
                log.err("Could not retrieve updated Interface info: {s}", .{ @errorName(err) });
            core_ctx.printInfo(stdout) catch {};
            stdout_bw.flush() catch {};
            posix.exit(0);
        }
        while (if_iter.next()) |set_if_entry| {
            const set_if = set_if_entry.value_ptr;
            if (set_if.usage == .unavailable) continue;
            const set_if_opts = try set_cmd.getOpts(.{});
            if (set_if_opts.get("mac")) |mac_opt| setMAC: {
                try stdout_file.print("Setting the MAC for {s}...\n", .{ set_if.name });
                const new_mac: [6]u8 = newMAC: {
                    var new_mac: [6]u8 = 
                        if (mac_opt.val.isEmpty()) .{ 0 } ** 6
                        else mac_opt.val.getAs([6]u8) catch break :setMAC;
                    if (set_if_opts.get("random_mac")) |rand_mac_opt| randMAC: {
                        if (!rand_mac_opt.val.isSet() and rand_mac_opt.val.isEmpty()) break :randMAC;
                        const rand_kind = try rand_mac_opt.val.getAs(address.RandomMACKind);
                        break :newMAC address.getRandomMAC(rand_kind);
                    }
                    if (set_if_opts.get("oui")) |oui_opt| {
                        const new_oui: [3]u8 = try oui_opt.val.getAs([3]u8);
                        new_mac[0..3].* = new_oui;
                    }
                    break :newMAC new_mac;
                };
                nl.route.setMAC(set_if.index, new_mac) catch |err| switch (err) {
                    error.OutOfMemory => {
                        log.err("Out of Memory!", .{});
                        return err;
                    },
                    error.BUSY => {
                        log.err("The interface '{s}' is busy so the MAC could not be set.", .{ set_if.name });
                        break :setMAC;
                    },
                    else => {
                        log.err("Netlink request error. The MAC for interface '{s}' could not be set.", .{ set_if.name });
                        return;
                    },
                };
                try stdout_file.print("Set the MAC for {s} to {s}.\n", .{ set_if.name, MACF{ .bytes = new_mac[0..] } });
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
                try stdout_file.print("Setting the State for {s}...\n", .{ set_if.name });
                nl.route.setState(set_if.index, new_state) catch |err| switch (err) {
                    error.OutOfMemory => {
                        log.err("Out of Memory!", .{});
                        return err;
                    },
                    error.BUSY => {
                        log.err("The interface '{s}' is busy so the State could not be set.", .{ set_if.name });
                        break :setState;
                    },
                    else => {
                        log.err("Netlink request error. The State for interface '{s}' could not be set.", .{ set_if.name });
                        return;
                    },
                };
                try stdout_file.print("Set the State for {s} to {s}.\n", .{ set_if.name, flag_name });
            }
            if (set_if_opts.get("mode")) |mode_opt| setMode: {
                const new_mode = mode_opt.val.getAs(nl._80211.IFTYPE) catch break :setMode;
                try stdout_file.print("Setting the Mode for {s}...\n", .{ set_if.name });
                nl.route.setState(set_if.index, c(nl.route.IFF).DOWN) catch { 
                    log.warn("Unable to set the interface down.", .{});
                };
                defer nl.route.setState(set_if.index, c(nl.route.IFF).UP) catch {
                    log.warn("Unable to set the interface up.", .{});
                };
                time.sleep(100 * time.ns_per_ms);
                nl._80211.setMode(set_if.index, @intFromEnum(new_mode)) catch |err| switch (err) {
                    error.OutOfMemory => {
                        log.err("Out of Memory!", .{});
                        return err;
                    },
                    error.BUSY => {
                        log.err("The interface '{s}' is busy so the Mode could not be set.", .{ set_if.name });
                        break :setMode;
                    },
                    else => {
                        log.err("Netlink request error. The Mode for interface '{s}' could not be set.", .{ set_if.name });
                        return;
                    },
                };
                try stdout_file.print("Set the Mode for {s} to {s}.\n", .{ set_if.name, @tagName(new_mode) });
            }
            if (set_if_opts.get("channel")) |chan_opt| setChannel: {
                const new_ch = chan_opt.val.getAs(usize) catch break :setChannel;
                const new_ch_width = newChMain: {
                    const new_ct_opt = set_if_opts.get("channel-width") orelse break :newChMain nl._80211.CHANNEL_WIDTH.@"20_NOHT";
                    break :newChMain new_ct_opt.val.getAs(nl._80211.CHANNEL_WIDTH) catch nl._80211.CHANNEL_WIDTH.@"20_NOHT";
                };
                try stdout_file.print("Setting the Channel for {s}...\n", .{ set_if.name });
                nl.route.setState(set_if.index, c(nl.route.IFF).DOWN) catch { 
                    log.warn("Unable to set the interface down.", .{});
                };
                time.sleep(100 * time.ns_per_ms);
                try nl._80211.setMode(set_if.index, c(nl._80211.IFTYPE).MONITOR);
                nl.route.setState(set_if.index, c(nl.route.IFF).UP) catch {
                    log.warn("Unable to set the interface up.", .{});
                };
                time.sleep(100 * time.ns_per_ms);
                nl._80211.setChannel(set_if.index, new_ch, new_ch_width) catch |err| switch (err) {
                    error.OutOfMemory => {
                        log.err("Out of Memory!", .{});
                        return err;
                    },
                    error.BUSY => {
                        log.err("The interface '{s}' is busy so the Channel could not be set.", .{ set_if.name });
                        break :setChannel;
                    },
                    error.InvalidChannel, error.InvalidFrequency => {
                        log.err("The channel '{d}' is invalid.", .{ new_ch });
                        break :setChannel;
                    },
                    else => {
                        log.err("Netlink request error. The Channel for interface '{s}' could not be set.", .{ set_if.name });
                        return err;
                    },
                };
                try stdout_file.print("Set the Channel for {s} to {d}.\n", .{ set_if.name, new_ch });
            }
            if (set_if_opts.get("frequency")) |freq_opt| setFreq: {
                const new_freq = freq_opt.val.getAs(usize) catch break :setFreq;
                const new_ch_width = newChMain: {
                    const new_ct_opt = set_if_opts.get("channel-width") orelse break :newChMain nl._80211.CHANNEL_WIDTH.@"20_NOHT";
                    break :newChMain new_ct_opt.val.getAs(nl._80211.CHANNEL_WIDTH) catch nl._80211.CHANNEL_WIDTH.@"20_NOHT";
                };
                try stdout_file.print("Setting the Channel for {s}...\n", .{ set_if.name });
                try nl._80211.setMode(set_if.index, c(nl._80211.IFTYPE).MONITOR);
                nl.route.setState(set_if.index, c(nl.route.IFF).UP) catch {
                    log.warn("Unable to set the interface up.", .{});
                };
                time.sleep(100 * time.ns_per_ms);
                nl._80211.setFreq(set_if.index, new_freq, new_ch_width) catch |err| switch (err) {
                    error.OutOfMemory => {
                        log.err("Out of Memory!", .{});
                        return err;
                    },
                    error.BUSY => {
                        log.err("The interface '{s}' is busy so the Frequency could not be set.", .{ set_if.name });
                        break :setFreq;
                    },
                    error.InvalidFrequency => {
                        log.err("The Frequency '{d}'MHz is invalid.", .{ new_freq });
                        break :setFreq;
                    },
                    else => {
                        log.err("Netlink request error. The Frequency for interface '{s}' could not be set.", .{ set_if.name });
                        return err;
                    },
                };
                try stdout_file.print("Set the Frequency for {s} to {d}.\n", .{ set_if.name, new_freq });
            }
        }
    }
    // - Add
    if (main_cmd.matchSubCmd("add")) |add_cmd| {
        checkRoot(stdout_file.any());
        const add_ifs = core_ctx.if_ctx.interfaces;
        if (num_avail_ifs == 0)
            checkIF(stdout, "add");
        var if_iter = add_ifs.iterator();
        defer {
            if_iter.unlock();
            core.interfaces.updInterfaces(
                alloc,
                &core_ctx.if_ctx,
                &core_ctx.config,
                &core_ctx.interval,
            ) catch |err|
                log.err("Could not retrieve updated Interface info: {s}", .{ @errorName(err) });
            core_ctx.printInfo(stdout) catch {};
            stdout_bw.flush() catch {};
            posix.exit(0);
        }
        while (if_iter.next()) |add_if_entry| {
            const add_if = add_if_entry.value_ptr;
            if (add_if.usage == .unavailable) continue;
            const add_opts = try add_cmd.getOpts(.{});
            //const cidr = try (add_opts.get("subnet").?).val.getAs(u8);
            if (add_opts.get("ip")) |ip_opt| setIP: {
                const ip = try ip_opt.val.getAs(address.IPv4);
                try stdout_file.print("Adding new IP Address '{s}'...\n", .{ ip });
                nl.route.addIP(
                    alloc,
                    add_if.index,
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
                    add_if.index,
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
    }
    // - Delete
    if (main_cmd.matchSubCmd("delete")) |del_cmd| {
        checkRoot(stdout_file.any());
        const del_ifs = core_ctx.if_ctx.interfaces;
        if (num_avail_ifs == 0) checkIF(stdout, "del");
        var if_iter = del_ifs.iterator();
        defer {
            if_iter.unlock();
            core.interfaces.updInterfaces(
                alloc,
                &core_ctx.if_ctx,
                &core_ctx.config,
                &core_ctx.interval,
            ) catch |err|
                log.err("Could not retrieve updated Interface info: {s}", .{ @errorName(err) });
            core_ctx.printInfo(stdout) catch {};
            stdout_bw.flush() catch {};
            posix.exit(0);
        }
        while (if_iter.next()) |del_if_entry| {
            const del_if = del_if_entry.value_ptr;
            if (del_if.usage == .unavailable) continue;
            const del_opts = try del_cmd.getOpts(.{});
            //const cidr = try (del_opts.get("subnet").?).val.getAs(u8);
            if (del_opts.get("ip")) |ip_opt| setIP: {
                const ip = try ip_opt.val.getAs(address.IPv4);
                try stdout_file.print("Deleting the IP Address '{s}'...\n", .{ ip });
                nl.route.deleteIP(
                    alloc,
                    del_if.index,
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
                    del_if.index,
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
    }
    // Active
    // - Connect
    if (main_cmd.matchSubCmd("connect")) |connect_cmd| {
        checkRoot(stdout_file.any());
        try core.interfaces.updInterfaces(
            alloc,
            &core_ctx.if_ctx,
            &core_ctx.config,
            &core_ctx.interval,
        );
        const conn_ifs = core_ctx.if_ctx.interfaces;
        if (num_avail_ifs == 0) checkIF(stdout, "connect");
        var if_iter = conn_ifs.iterator();
        defer {
            if_iter.unlock();
            if (conn_ifs.count() > 0) {
                core.interfaces.updInterfaces(
                    alloc,
                    &core_ctx.if_ctx,
                    &core_ctx.config,
                    &core_ctx.interval,
                ) catch |err|
                    log.err("Could not retrieve updated Interface info: {s}", .{ @errorName(err) });
            }
        }
        const conn_if = connIF: while (if_iter.next()) |conn_if_entry| {
            const conn_if = conn_if_entry.value_ptr;
            if (conn_if.usage != .unavailable) break :connIF conn_if;
        } else return error.NoAvailableInterfaces;
        raw_net_if = conn_if.*;
        const connect_vals = try connect_cmd.getVals(.{});
        const connect_opts = try connect_cmd.getOpts(.{});
        const ssid = (connect_vals.get("ssid").?).getAs([]const u8) catch {
            log.err("DisCo needs to know the SSID of the network to connect.", .{});
            return;
        };
        const security,
        const pass = security: {
            const security = try (connect_opts.get("security").?).val.getAs(nl._80211.SecurityType);
            break :security switch (security) {
                .open => .{ security, "" },
                .wep, .wpa1, .wpa2, .wpa3t, .wpa3 => .{
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
            .open, .wep, .wpa1, .wpa3 => {
                log.info("WIP!", .{});
                return;
            },
            .wpa2, .wpa3t => {
                const pmk = try wpa.genKey(.wpa2, ssid, pass);
                _ = try nl._80211.connectWPA2(
                    alloc,
                    conn_if.index,
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
                conn_if.name,
                conn_if.index,
                conn_if.mac,
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
                conn_if.index,
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
                    conn_if.index,
                    address.IPv4.default.addr,
                    .{
                        .cidr = address.IPv4.default.cidr,
                        .gateway = dhcp_info.?.router,
                    }
                );
            }
        }
        //time.sleep(10 * time.ns_per_s);
        //if_iter.unlock();
        connected = true;
        const stdin = io.getStdIn().reader();
        _ = try stdin.readUntilDelimiterOrEofAlloc(alloc, '\n', 4096);
    }

    // System Details
    try core_ctx.printInfo(stdout);
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

/// Ask the user to Check that there's an Interface.
fn checkIF(stdout: io.AnyWriter, cmd_name: []const u8) void {
    stdout.print("{s}\n\n   `disco {s}` needs to know which interface(s) to use. (Ex: disco -i wlan0 {s})\n", .{ art.wifi_card, cmd_name, cmd_name }) catch {
        log.err("DisCo needs to know which interface to use. (Ex: disco wlan0)", .{});
    };
    process.exit(1);
    //cleanUp(0);
}

/// Cleanup
fn cleanUp(_: i32) callconv(.C) void {
    if (cleaning) {
        log.warn("Forced close. Couldn't finish cleaning up.", .{});
        posix.exit(1);
    }
    cleaning = true;
    if (panicking) log.err("Runtime Panic! Attempting to close gracefully...", .{})
    else if (forcing_close) log.info("Forced close! Attempting to close gracefully...", .{})
    else log.info("Closing gracefully...\n(Force close w/ `ctrl + c`.)", .{});
    if (connected) cleanup: {
        active = false;
        //const core_ctx = _core_ctx orelse break :cleanup;
        //raw_net_if = core_ctx.if_maps.interfaces.get(net_if.index);
        const net_if = raw_net_if orelse break :cleanup;
        if (dhcp_info) |d_info| {
            dhcp.releaseDHCP(
                net_if.name,
                net_if.index,
                net_if.mac,
                d_info.server_id,
                d_info.assigned_ip,
            ) catch log.warn("Could not release DHCP lease for `{s}`!", .{ d_info.assigned_ip });
        }
        //for (net_if.ips, net_if.cidrs) |_ip, _cidr| {
        //    const ip = _ip orelse continue;
        //    const cidr = _cidr orelse 24;
        //    var fba_buf: [2048]u8 = undefined;
        //    var fba = heap.FixedBufferAllocator.init(fba_buf[0..]);
        //    defer nl.route.deleteIP(
        //        //alloc,
        //        fba.allocator(),
        //        net_if.index,
        //        ip,
        //        cidr,
        //    ) catch |err| switch (err) {
        //        error.ADDRNOTAVAIL => {},
        //        else => log.warn("Could not remove IP `{s}`!", .{ IPF{ .bytes = ip[0..] } }),
        //    };
        //}
    }
    if (_core_ctx) |*core_ctx| {
        if (panicking or forcing_close)
            core_ctx.forced_close = true;
        core_ctx.stop();
        core_ctx._mutex.lock();
    }
    if (panicking) return;
    log.info("Exit!", .{});
    posix.exit(1);
}

/// Force Close
pub fn forceClose(errno: i32) callconv(.C) void {
    forcing_close = true;
    cleanUp(errno);
}

/// Attempt to recover from Panics gracefully.
pub fn panic(msg: []const u8, trace: ?*std.builtin.StackTrace, ret_addr: ?usize) noreturn {
    @setCold(true);
    if (!cleaning and !panicking) {
        panicking = true;
        cleanUp(1);
    }
    log.err("Panic Report: ({d}) {s}", .{ ret_addr orelse 0, msg });
    if (@import("builtin").mode == .Debug)
        std.builtin.default_panic(msg, trace, ret_addr)
    else posix.exit(1);
}
