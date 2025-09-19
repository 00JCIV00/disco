const builtin = @import("builtin");
const std = @import("std");
const atomic = std.atomic;
const crypto = std.crypto;
const debug = std.debug;
const fmt = std.fmt;
const fs = std.fs;
const heap = std.heap;
const io = std.io;
const json = std.json;
const log = std.log.scoped(.disco);
const mem = std.mem;
const os = std.os;
const posix = std.posix;
const process = std.process;
const testing = std.testing;
const time = std.time;
const ArrayList = std.ArrayList;
const Io = std.Io;
const Thread = std.Thread;

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

const serve = core.serve;
const dhcp = proto.dhcp;
const wpa = proto.wpa;
const address = netdata.address;
const oui = netdata.oui;
const MACF = address.MACFormatter;
const IPF = address.IPFormatter;
const masks_map = core.profiles.Mask.map;
const c = utils.toStruct;
const SlicesF = utils.SliceFormatter([]const u8, "{s}");

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
var active: atomic.Value(bool) = atomic.Value(bool).init(false);
// Connect
var connected: bool = false;
// DHCP Info
var dhcp_info: ?dhcp.Info = null;
// Interface
var raw_net_if: ?core.interfaces.Interface = null;

pub fn main() !void {
    // Catch Forced Close
    posix.sigaction(
        posix.SIG.INT,
        &.{
            .handler = .{ .handler = forceClose },
            .mask = posix.sigemptyset(),
            .flags = 0,
        },
        null,
    );
    var stdout_file = fs.File.stdout();
    var stdout_buf: [4096]u8 = undefined;
    var stdout_writer = stdout_file.writer(stdout_buf[0..]);
    const stdout = &stdout_writer.interface;
    defer stdout.flush() catch {};

    var gpa: heap.DebugAllocator(.{ .thread_safe = true, .stack_trace_frames = 50 }) = .init;
    defer if (builtin.mode == .Debug and gpa.detectLeaks()) //
        log.err("Memory leak detected!", .{});
    //const gpa_alloc = switch (builtin.mode) {
    //    .Debug => gpa.allocator(),
    //    else => heap.smp_allocator,
    //};
    //var sfba = heap.stackFallback(1_000_000, gpa_alloc);
    //const alloc = sfba.get();
    const alloc = switch (builtin.mode) {
        .Debug => gpa.allocator(),
        else => heap.smp_allocator,
    };

    // Get NL80211 Control Info
    try nl._80211.initCtrlInfo(alloc);
    defer nl._80211.deinitCtrlInfo(alloc);

    // Parse Args
    //var main_cmd = try cli.setup_cmd.init(gpa_alloc, .{});
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
        try stdout.flush();
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
        try stdout.flush();
        return;
    }
    // - System
    if (main_cmd.matchSubCmd("system")) |sys_cmd| {
        checkRoot(stdout);
        if (sys_cmd.matchSubCmd("set")) |set_cmd| {
            const set_opts = try set_cmd.getOpts(.{});
            if (set_opts.get("hostname")) |hn_opt| newHN: {
                const new_hn = hn_opt.val.getAs([]const u8) catch break :newHN;
                try stdout.print("Setting the hostname to {s}...\n", .{ new_hn });
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
                    \\{f}
                    \\
                    , .{
                        key,
                        masks_map.get(key).?,
                    },
                );
            }
            try stdout.flush();
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
            try stdout.flush();
            const core_conf: core.Core.Config = .{};
            _ = try core.findConflictPIDs(
                alloc, 
                core_conf.profile.conflict_processes,
                stdout,
                "- '{s}' process running {d} time(s) (PID(s): {f}).\n"
            );
            try stdout.flush();
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
                \\You can also create the following files to provide a persistent config:
                \\ * /etc/disco/config.json
                \\ * /root/.configs/disco/config.json
                \\Config Fields:
                \\{s}
                , .{ config_fields }
            );
            try stdout.flush();
        }
        if (!list_cmd.checkFlag("interfaces")) posix.exit(0);
    }
    // - File Serve
    if (main_cmd.matchSubCmd("serve")) |serve_cmd| {
        const serve_opts = try serve_cmd.getOpts(.{});
        const ip = try serve_opts.get("ip").?.val.getAs(address.IPv4);
        const port = try serve_opts.get("port").?.val.getAs(u16);
        const dir = try serve_opts.get("directory").?.val.getAs([]const u8);
        const protos = try serve_opts.get("protocols").?.val.getAllAs(core.serve.Protocol);
        active.store(true, .seq_cst);
        //try serve.serveDir(port, dir, &active);
        const conf: core.serve.Config = .{
            .ip = ip.addr,
            .port = port,
            .serve_path = dir,
            .protocols = protos,
        };
        var ctx = try core.serve.Context.init(alloc);
        defer ctx.deinit(alloc);
        ctx.conf.* = conf;
        serve.serveDir(
            alloc,
            &ctx,
            &active,
        );
        while (active.load(.acquire)) {}
        return;
    }

    // Set up Core Data
    const cova_alloc = main_cmd._alloc orelse return error.CovaCommandUnitialized;
    const main_opts = try main_cmd.getOpts(.{});
    var core_if_indexes: ArrayList(i32) = .{};
    defer core_if_indexes.deinit(alloc);
    var core_scan_confs: ArrayList(core.Core.Config.ScanConfig) = .{};
    defer core_scan_confs.deinit(alloc);
    const if_names: []const []const u8 = ifOpt: {
        if (main_opts.get("interfaces")) |if_opt| {
            const ssids = ssids: {
                const ssids_opt = main_opts.get("ssids").?;
                break :ssids try ssids_opt.val.getAllAs([]const u8);
            };
            const channels: ?[]const usize = getChs: {
                if (main_opts.get("channels")) |ch_opt|
                    break :getChs try ch_opt.val.getAllAs(usize)
                else if (main_opts.get("bands")) |band_opt| {
                    var ch_list: ArrayList(usize) = .empty;
                    const bands = try band_opt.val.getAllAs(u8);
                    for (bands) |band| switch (band) {
                        2 => try ch_list.appendSlice(cova_alloc, nl._80211.Channels.band_2G),
                        5 => try ch_list.appendSlice(cova_alloc, nl._80211.Channels.band_5G),
                        else => {},
                    };
                    break :getChs try ch_list.toOwnedSlice(cova_alloc);
                }
                break :getChs null;
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
        if (!main_cmd.checkArgGroup(.Option, "MASK") or main_cmd.checkFlag("no_mask")) break :getMask null;
        if (main_opts.get("mask")) |mask_opt| {
            const mask = try mask_opt.val.getAs(core.profiles.Mask);
            log.info("Using the provided '{s}' Profile Mask:\n{f}", .{
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
        log.info("Using your Custom Profile Mask:\n{f}", .{ mask });
        break :getMask mask;
    };
    const core_conn_confs: []core.connections.Config = connConfs: {
        const conn_opt = main_opts.get("connect_info") orelse break :connConfs &.{};
        break :connConfs conn_opt.val.getAllAs(core.connections.Config) catch &.{};
    };
    if (main_cmd.checkFlag("no_conflict_pids")) //
        log.info("Skipping Conflict PIDs check.", .{});
    // Initialize Core Context
    const core_config: core.Core.Config = config: {
        var config: core.Core.Config = importConf: {
            var config: core.Core.Config = .{
                .avail_if_names = if_names,
                .profile = .{
                    .require_conflicts_ack = !main_cmd.checkFlag("no_conflict_pids"),
                },
            };
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
                    log.warn("There was an error with the provided Config: {t}", .{ err });
                    break :userConf;
                };
                log.info("Imported provided Config!", .{});
                break :importConf config;
            }
            defaultConf: {
                if (main_cmd.checkFlag("no_default_config")) {
                    log.info("Skipping Default Config check.", .{});
                    break :defaultConf;
                }
                var user_buf: [100]u8 = undefined;
                const user = sys.getUser(user_buf[0..]) orelse break :defaultConf;
                log.debug("Current User: {s}", .{ user });
                var path_buf: [fs.max_path_bytes]u8 = undefined;
                const user_conf_path = confPath: {
                    if (mem.eql(u8, user, "root")) break :confPath "/root/.config/disco/config.json";
                    break :confPath fmt.bufPrint(path_buf[0..], "/home/{s}/.config/disco/config.json", .{ user }) catch break :defaultConf;
                };
                var cwd = fs.cwd();
                const default_conf_paths: []const []const u8 = &.{ "/etc/disco/config.json", user_conf_path };
                for (default_conf_paths) |default_conf_path| {
                    const default_conf = cwd.openFile(default_conf_path, .{}) catch {
                        log.info("No Default Config found at: '{s}'", .{ default_conf_path });
                        continue;
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
                        log.warn("There was an error with the Default Config: {t}", .{ err });
                        break :defaultConf;
                    };
                    log.info("Imported the Default Config at '{s}'!", .{ default_conf_path });
                    break :importConf config;
                }
            }
            break :importConf config;
        };
        if (main_cmd.matchSubCmd("connect")) |connect_cmd| {
            const connect_vals = try connect_cmd.getVals(.{});
            const ssid = try (connect_vals.get("ssid").?).getAs([]const u8);
            const connect_opts = try connect_cmd.getOpts(.{});
            const security = security: {
                const security_opt = connect_opts.get("security") orelse break :security null;
                break :security try security_opt.val.getAs(nl._80211.SecurityType);
            };
            const pass = pass: {
                const pass_opt = connect_opts.get("passphrase") orelse {
                    if (security != null and security.? != .open) //
                        log.err("The {t} protocol requires a passhprase.", .{ security.? })
                    else //
                        log.warn("No passphrase provided. This will only work with Open Networks.", .{});
                    break :pass "";
                };
                break :pass try pass_opt.val.getAs([]const u8);
            };
            const freqs = freqs: {
                const ch_opt = connect_opts.get("channels") orelse break :freqs null;
                if (!ch_opt.val.isSet()) break :freqs null;
                const channels = try ch_opt.val.getAllAs(usize);
                var freqs_buf = try ArrayList(u32).initCapacity(alloc, 1);
                for (channels) |ch|
                    try freqs_buf.append(alloc, @intCast(try nl._80211.freqFromChannel(ch)));
                break :freqs try freqs_buf.toOwnedSlice(alloc);
            };
            defer if (freqs) |_freqs| alloc.free(_freqs);
            config.connect_configs = &.{
                .{
                    .ssid = ssid,
                    .passphrase = pass,
                    .security = security,
                    .dhcp = if (connect_cmd.checkFlag("dhcp")) .{} else null,
                    .add_gw = connect_cmd.checkFlag("gateway"),
                },
            };
            config.profile.require_conflicts_ack = false;
        }
        if (if_names.len > 0) config.avail_if_names = if_names;
        if (config.scan_configs.len == 0 and core_scan_confs.items.len == 0) {
            for (config.avail_if_names) |if_name| {
                try core_scan_confs.append(alloc, .{
                    .if_name = if_name,
                    .ssids = &.{},
                    .channels = &.{},
                });
            }
        }
        if (core_scan_confs.items.len > 0) config.scan_configs = core_scan_confs.items;
        if (profile_mask) |pro_mask| config.profile.mask = pro_mask;
        config.profile.use_random_mask = !main_cmd.checkFlag("no_mask");
        for (core_conn_confs) |*conn_conf| {
            if (main_cmd.checkOpts(&.{ "gateway" }, .{})) conn_conf.add_gw = true;
            if (config.profile.mask) |pro_mask| setHostname: {
                var dhcp_conf = &(conn_conf.dhcp orelse break :setHostname);
                if (dhcp_conf.hostname) |_| break :setHostname;
                dhcp_conf.hostname = pro_mask.hostname;
            }
            //if (conn_conf.if_names.len == 0)
            //    conn_conf.if_names = config.avail_if_names;
        }
        if (core_conn_confs.len > 0) config.connect_configs = core_conn_confs;
        break :config config;
    };
    var core_ctx: core.Core = try .init(alloc, core_config);
    // Start Core Context
    const run_core: bool = runCore: {
        break :runCore //
            main_cmd.sub_cmd == null or //
            main_cmd.matchSubCmd("connect") != null;
    };
    if (run_core) {
        checkRoot(stdout);
        const core_thread = try Thread.spawn(.{}, core.Core.start, .{ &core_ctx });
        core_thread.detach();
        while (!(&core_ctx).active.load(.acquire)) //
            Thread.sleep(10 * time.ns_per_ms);
        var stdin_file = fs.File.stdin();
        var stdin_buf: [16]u8 = undefined;
        var stdin_reader = stdin_file.reader(stdin_buf[0..]);
        const stdin = &stdin_reader.interface;
        _ = try stdin.discardDelimiterExclusive('\n');
        core_ctx.stop();
        return;
        //posix.exit(0);
    }
    defer cleanUp(0);

    // Single Use
    const list_interfaces: core.Core.RunCondition = .{ .list_interfaces = .{} };
    // - Set
    if (main_cmd.matchSubCmd("set")) |set_cmd| {
        checkRoot(stdout);
        try core_ctx.runTo(list_interfaces);
        const set_ifs = core_ctx.if_ctx.interfaces;
        var if_iter = set_ifs.iterator();
        defer {
            if_iter.unlock();
            core_ctx.runTo(list_interfaces) catch {};
        }
        while (if_iter.next()) |set_if_entry| {
            const set_if = set_if_entry.value_ptr;
            if (set_if.usage == .unavailable) continue;
            const set_if_opts = try set_cmd.getOpts(.{});
            if (set_if_opts.get("mac")) |mac_opt| setMAC: {
                try stdout.print("Setting the MAC for {s}...\n", .{ set_if.name });
                const new_mac: [6]u8 = newMAC: {
                    var new_mac: [6]u8 = //
                        if (mac_opt.val.isEmpty()) @splat(0) //
                        else mac_opt.val.getAs([6]u8) catch break :setMAC;
                    if (set_if_opts.get("random_mac")) |rand_mac_opt| randMAC: {
                        if (!rand_mac_opt.val.isSet() and rand_mac_opt.val.isEmpty()) break :randMAC;
                        const rand_kind = try rand_mac_opt.val.getAs(address.RandomMACKind);
                        new_mac = address.getRandomMAC(rand_kind);
                    }
                    if (set_if_opts.get("oui")) |oui_opt| setOUI: {
                        if (!oui_opt.val.isSet()) break :setOUI;
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
                try stdout.print("Set the MAC for {s} to {f}.\n", .{ set_if.name, MACF{ .bytes = new_mac[0..] } });
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
                try stdout.print("Setting the State for {s}...\n", .{ set_if.name });
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
                try stdout.print("Set the State for {s} to {s}.\n", .{ set_if.name, flag_name });
            }
            if (set_if_opts.get("mode")) |mode_opt| setMode: {
                const new_mode = mode_opt.val.getAs(nl._80211.IFTYPE) catch break :setMode;
                try stdout.print("Setting the Mode for {s}...\n", .{ set_if.name });
                nl.route.setState(set_if.index, c(nl.route.IFF).DOWN) catch { 
                    log.warn("Unable to set the interface down.", .{});
                };
                defer nl.route.setState(set_if.index, c(nl.route.IFF).UP) catch {
                    log.warn("Unable to set the interface up.", .{});
                };
                Thread.sleep(100 * time.ns_per_ms);
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
                try stdout.print("Set the Mode for {s} to {t}.\n", .{ set_if.name, new_mode });
            }
            if (set_if_opts.get("channel")) |chan_opt| setChannel: {
                const new_ch = chan_opt.val.getAs(usize) catch break :setChannel;
                const new_ch_width = newChMain: {
                    const new_ct_opt = set_if_opts.get("channel-width") orelse break :newChMain nl._80211.CHANNEL_WIDTH.@"20_NOHT";
                    break :newChMain new_ct_opt.val.getAs(nl._80211.CHANNEL_WIDTH) catch nl._80211.CHANNEL_WIDTH.@"20_NOHT";
                };
                try stdout.print("Setting the Channel for {s}...\n", .{ set_if.name });
                nl.route.setState(set_if.index, c(nl.route.IFF).DOWN) catch { 
                    log.warn("Unable to set the interface down.", .{});
                };
                Thread.sleep(100 * time.ns_per_ms);
                try nl._80211.setMode(set_if.index, c(nl._80211.IFTYPE).MONITOR);
                nl.route.setState(set_if.index, c(nl.route.IFF).UP) catch {
                    log.warn("Unable to set the interface up.", .{});
                };
                Thread.sleep(100 * time.ns_per_ms);
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
                try stdout.print("Set the Channel for {s} to {d}.\n", .{ set_if.name, new_ch });
            }
            if (set_if_opts.get("frequency")) |freq_opt| setFreq: {
                const new_freq = freq_opt.val.getAs(usize) catch break :setFreq;
                const new_ch_width = newChMain: {
                    const new_ct_opt = set_if_opts.get("channel-width") orelse break :newChMain nl._80211.CHANNEL_WIDTH.@"20_NOHT";
                    break :newChMain new_ct_opt.val.getAs(nl._80211.CHANNEL_WIDTH) catch nl._80211.CHANNEL_WIDTH.@"20_NOHT";
                };
                try stdout.print("Setting the Channel for {s}...\n", .{ set_if.name });
                try nl._80211.setMode(set_if.index, c(nl._80211.IFTYPE).MONITOR);
                nl.route.setState(set_if.index, c(nl.route.IFF).UP) catch {
                    log.warn("Unable to set the interface up.", .{});
                };
                Thread.sleep(100 * time.ns_per_ms);
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
                try stdout.print("Set the Frequency for {s} to {d}.\n", .{ set_if.name, new_freq });
            }
        }
    }
    // - Add
    if (main_cmd.matchSubCmd("add")) |add_cmd| {
        checkRoot(stdout);
        try core_ctx.runTo(list_interfaces);
        const add_ifs = core_ctx.if_ctx.interfaces;
        if (add_ifs.count() == 0) checkIF(stdout, "add");
        var if_iter = add_ifs.iterator();
        defer {
            if_iter.unlock();
            core_ctx.runTo(list_interfaces) catch {};
        }
        while (if_iter.next()) |add_if_entry| {
            const add_if = add_if_entry.value_ptr;
            if (add_if.usage == .unavailable) continue;
            const add_opts = try add_cmd.getOpts(.{});
            if (add_opts.get("ip")) |ip_opt| setIP: {
                const ip = try ip_opt.val.getAs(address.IPv4);
                try stdout.print("Adding IP Address '{f}' to Interface '{s}'...\n", .{ ip, add_if.name });
                nl.route.addIP(
                    alloc,
                    add_if.index,
                    ip.addr,
                    ip.cidr,
                ) catch |err| switch (err) {
                    error.EXIST => {
                        try stdout.print("The IP Address '{f}' is already set on Interface '{s}'.\n", .{ ip, add_if.name });
                        break :setIP;
                    },
                    else => return err,
                };
                try stdout.print("Added IP Address '{f}' to Interface '{s}'.\n", .{ ip, add_if.name });
            }
            if (add_opts.get("route")) |route_opt| setRoute: {
                const route = try route_opt.val.getAs(address.IPv4);
                try stdout.print("Adding Route '{f}' to Interface '{s}'...\n", .{ route, add_if.name });
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
                        try stdout.print("The Route '{f}' is already set on Interface '{s}'.\n", .{ route, add_if.name });
                        break :setRoute;
                    },
                    error.NETUNREACH => {
                        try stdout.print("The Gateway '{?s}' is invalid.\n", .{ gateway });
                        break :setRoute;
                    },
                    else => return err,
                };
                try stdout.print("Added Route '{f}' to Interface '{s}'.\n", .{ route, add_if.name });
            }
            Thread.sleep(100 * time.ns_per_ms);
        }
    }
    // - Delete
    if (main_cmd.matchSubCmd("delete")) |del_cmd| {
        checkRoot(stdout);
        try core_ctx.runTo(list_interfaces);
        const del_ifs = core_ctx.if_ctx.interfaces;
        var if_iter = del_ifs.iterator();
        defer {
            if_iter.unlock();
            core_ctx.runTo(list_interfaces) catch {};
        }
        while (if_iter.next()) |del_if_entry| {
            const del_if = del_if_entry.value_ptr;
            if (del_if.usage == .unavailable) continue;
            const del_opts = try del_cmd.getOpts(.{});
            if (del_opts.get("ip")) |ip_opt| setIP: {
                const ip = try ip_opt.val.getAs(address.IPv4);
                try stdout.print("Deleting the IP Address '{f}'...\n", .{ ip });
                nl.route.deleteIP(
                    alloc,
                    del_if.index,
                    ip.addr,
                    ip.cidr,
                ) catch |err| switch (err) {
                    error.ADDRNOTAVAIL => {
                        try stdout.print("The IP Address '{f}' could not be found.\n", .{ ip });
                        break :setIP;
                    },
                    else => return err,
                };
                try stdout.print("Deleted the IP Address '{f}'.\n", .{ ip });
            }
            if (del_opts.get("route")) |route_opt| delRoute: {
                const route = try route_opt.val.getAs(address.IPv4);
                try stdout.print("Deleting Route '{f}'...\n", .{ route });
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
                        try stdout.print("The Route '{f}' could not be found.\n", .{ route });
                        break :delRoute;
                    },
                    else => return err,
                };
                try stdout.print("Deleted Route '{f}'.\n", .{ route });
            }
            Thread.sleep(100 * time.ns_per_ms);
        }
    }
    // - Scan
    if (main_cmd.matchSubCmd("scan")) |scan_cmd| {
        _ = scan_cmd;
        log.info("Scanning for WiFi Networks...", .{});
        try core_ctx.runTo(.{ .network_scan = .{} });
        var networks_iter = core_ctx.network_ctx.networks.iterator();
        defer core_ctx.network_ctx.networks.mutex.unlock();
        try stdout.print("WiFi Networks:\n\n", .{});
        while (networks_iter.next()) |network_entry| {
            const network = network_entry.value_ptr;
            try stdout.print(
                \\{f}
                \\-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
                \\
                \\
                , .{ network.* },
            );
        }
        try stdout.flush();
    }

    // Print Config
    const print_config: core.Core.PrintConfig = printConf: {
        const sub_cmd = main_cmd.sub_cmd orelse break :printConf .{};
        const cmd_group = sub_cmd.cmd_group orelse break :printConf .{};
        if (mem.eql(u8, cmd_group, "INTERFACE")) break :printConf .{
            .sys_info = false,
            .if_info = .available,
        };
        if (main_cmd.matchSubCmd("list")) |list_cmd| {
            if (list_cmd.checkFlag("interfaces")) {
                log.debug("Printing Interfaces...", .{});
                try core_ctx.runTo(list_interfaces);
                break :printConf .{ .sys_info = false };
            }
        }
        if (main_cmd.checkFlag("scan")) break :printConf .{
            .sys_info = false,
            .if_info = .none,
        };
        break :printConf .{};
    };
    // System Details
    try core_ctx.printInfo(stdout, print_config);
    try stdout.flush();
    posix.exit(0);
}

/// Check for Root 
fn checkRoot(stdout: *Io.Writer) void {
    if (os.linux.getuid() != 0) {
        stdout.print("{s}\n\n                          DisCo must be run as sudo!\n", .{ art.sudo }) catch { 
            log.err("DisCo must be run as sudo! (There was also an issue writing to stdout.)", .{});
        };
        process.exit(1);
    }
}

/// Ask the user to Check that there's an Interface.
fn checkIF(stdout: *Io.Writer, cmd_name: []const u8) void {
    stdout.print("{s}\n\n   `disco {s}` needs to know which interface(s) to use. (Ex: disco -i wlan0 {s})\n", .{ art.wifi_card, cmd_name, cmd_name }) catch {
        log.err("DisCo needs to know which interface to use. (Ex: disco wlan0)", .{});
    };
    process.exit(1);
    //cleanUp(0);
}

/// Cleanup
fn cleanUp(_: i32) callconv(.c) void {
    if (cleaning) {
        log.warn("Forced close. Couldn't finish cleaning up.", .{});
        posix.exit(1);
    }
    cleaning = true;
    if (panicking) log.err("Runtime Panic! Attempting to close gracefully...", .{})
    else if (forcing_close) log.info("Forced close! Attempting to close gracefully...", .{})
    else log.info("Closing gracefully...\n(Force close w/ `ctrl + c`.)", .{});
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
pub fn forceClose(errno: i32) callconv(.c) void {
    forcing_close = true;
    cleanUp(errno);
}

/// Attempt to recover from Panics gracefully.
fn panicFn(msg: []const u8, ret_addr: ?usize) noreturn {
    @branchHint(.cold);
    if (!cleaning and !panicking) {
        panicking = true;
        cleanUp(1);
    }
    log.err("Panic Report: ({d}) {s}", .{ ret_addr orelse 0, msg });
    if (@import("builtin").mode == .Debug)
    debug.defaultPanic(msg, ret_addr)
    else posix.exit(1);
}
pub const panic = debug.FullPanic(panicFn);

test "disco" {
    @setEvalBranchQuota(10_000);
    testing.refAllDeclsRecursive(@This());
}
