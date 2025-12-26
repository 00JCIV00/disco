//! Network Tracking

const std = @import("std");
const atomic = std.atomic;
const fmt = std.fmt;
const heap = std.heap;
const linux = std.os.linux;
const log = std.log.scoped(.networks);
const math = std.math;
const mem = std.mem;
const meta = std.meta;
const posix = std.posix;
const time = std.time;
const ArrayList = std.ArrayList;
const Io = std.Io;
const Thread = std.Thread;

const zeit = @import("zeit");

const netdata = @import("../netdata.zig");
const address = netdata.address;
const wifi = netdata.l2.wifi;
const chs = wifi.channels;
const MACF = address.MACFormatter;
const IPF = address.IPFormatter;
const core = @import("../core.zig");
const nl = @import("../netlink.zig");
const proto = @import("../protocols.zig");
const wpa = proto.wpa;
const utils = @import("../utils.zig");
const ansi = utils.ansi;
const c = utils.toStruct;
const ThreadHashMap = utils.ThreadHashMap;
const RSSI = core.devices.RSSI;
const SliceF = utils.SliceFormatter;


/// Network Info
pub const Network = struct {
    // Details
    bssid: [6]u8,
    ssid: []const u8,
    security: wifi.SecurityType,
    auth: wifi.AuthType,
    channel: u32,
    freq: u32,
    //beacon_interval: ?u16 = null,
    //bss_tsf: ?u64 = null,
    net_meta: *ThreadHashMap([6]u8, Meta),
    bss: nl._80211.BasicServiceSet,

    /// ID of a Network
    pub const ID = union(enum) {
        bssid: [6]u8,
        ssid: []const u8,

        pub fn deinit(self: *const @This(), alloc: mem.Allocator) void {
            switch (self.*) {
                .ssid => |ssid| alloc.free(ssid),
                else => {},
            }
        }

        pub fn clone(self: *const @This(), alloc: mem.Allocator) mem.Allocator.Error!@This() {
            return switch (self.*) {
                .ssid => |ssid| .{ .ssid = try alloc.dupe(u8, ssid) },
                .bssid => self.*,
            };
        }

        pub fn eql(self: @This(), other: @This()) bool {
            if (meta.activeTag(self) != meta.activeTag(other)) //
                return false;
            return switch (self) {
                .ssid => mem.eql(u8, self.ssid, other.ssid),
                .bssid => mem.eql(u8, self.bssid[0..], other.bssid[0..]),
            };
        }

        pub fn format(self: @This(), writer: *Io.Writer) Io.Writer.Error!void {
            switch (self) {
                .bssid => |bssid| try writer.print("{f}", .{ MACF{ .bytes = bssid[0..] } }),
                .ssid => |ssid| try writer.print("{s}", .{ ssid }),
            }
        }
    };

    /// Simple Network
    pub const Simple = struct {
        bssid: [6]u8,
        ssid: []const u8,
        security: wifi.SecurityType,
        auth: wifi.AuthType,
        channel: u32,
        freq: u32,
        net_meta: []const Meta,

        pub fn deinit(self: *const @This(), alloc: mem.Allocator) void {
            alloc.free(self.ssid);
            for (self.net_meta) |nm| //
                nm.deinit(alloc);
            alloc.free(self.net_meta);
        }

        pub fn from(alloc: mem.Allocator, from_net: Network) @This() {
            return .{
                .bssid = from_net.bssid,
                .ssid = alloc.dupe(u8, from_net.ssid) catch @panic("OOM"),
                .security = from_net.security,
                .auth = from_net.auth,
                .channel = from_net.channel,
                .freq = from_net.freq,
                .net_meta = netMeta: {
                    var nm_list: ArrayList(Meta) = .empty;
                    var nm_iter = from_net.net_meta.iterator();
                    defer nm_iter.unlock();
                    while (nm_iter.next()) |nm_entry| //
                        nm_list.append(alloc, nm_entry.value_ptr.clone(alloc)) catch @panic("OOM");
                    break :netMeta nm_list.toOwnedSlice(alloc) catch @panic("OOM");
                },
            };
        }

        pub fn format(self: @This(), writer: *Io.Writer) Io.Writer.Error!void {
            try formatGen(@This(), self, writer, false);
        }

        pub fn formatANSI(self: @This(), writer: *Io.Writer) Io.Writer.Error!void {
            try formatGen(@This(), self, writer, true);
        }
    };

    /// Meta Information about how a Network was Seen
    pub const Meta = struct {
        seen_by: []const u8,
        last_seen: zeit.Instant,
        rssi: i32,
        frame_nums: []const usize = &.{},

        pub fn deinit(self: *const @This(), alloc: mem.Allocator) void {
            alloc.free(self.seen_by);
            if (self.frame_nums.len > 0)
                alloc.free(self.frame_nums);
        }

        pub fn clone(self: *const @This(), alloc: mem.Allocator) @This() {
            return .{
                .seen_by = alloc.dupe(u8, self.seen_by) catch @panic("OOM"),
                .last_seen = self.last_seen,
                .rssi = self.rssi,
                .frame_nums = alloc.dupe(usize, self.frame_nums) catch @panic("OOM"),
            };
        }

        pub fn calcRxQual(self: *const @This()) usize {
            if (self.frame_nums.len < 2) //
                return 0;
            const first = self.frame_nums[0];
            const last = self.frame_nums[self.frame_nums.len - 1];
            const total: f128 = @floatFromInt(last - first);
            return @intFromFloat(@divFloor(@as(f128, @floatFromInt(self.frame_nums.len)), total) * 100);
        }

        pub fn format(self: @This(), writer: *Io.Writer) Io.Writer.Error!void {
            var last_ts_buf: [50]u8 = undefined;
            const last_ts = self.last_seen.time().bufPrint(last_ts_buf[0..], .rfc3339) catch "[Time Format Error]";
            try writer.print(
                \\- {s}Seen By{s}:   {s}
                \\- {s}RSSI{s}:      {f}{s} dBm
                \\- {s}Rx Qual{s}:   {d}
                \\- {s}Last Seen{s}: {s}
                \\
                , .{
                    ansi.fmt.underline, ansi.reset, self.seen_by,
                    ansi.fmt.underline, ansi.reset, RSSI{ .strength = self.rssi }, ansi.reset,
                    ansi.fmt.underline, ansi.reset, self.calcRxQual(),
                    ansi.fmt.underline, ansi.reset, last_ts,
                },
            );
        }
    };

    pub fn deinit(self: *const @This(), alloc: mem.Allocator) void {
        alloc.free(self.ssid);
        var meta_iter = self.net_meta.iterator();
        while (meta_iter.next()) |meta_entry| //
            meta_entry.value_ptr.deinit(alloc);
        self.net_meta.mutex.unlock();
        self.net_meta.deinit(alloc);
        nl.parse.freeBytes(alloc, nl._80211.BasicServiceSet, self.bss);
        alloc.destroy(self.net_meta);
    }

    pub fn format(self: @This(), writer: *Io.Writer) Io.Writer.Error!void {
        try formatGen(@This(), self, writer, false);
    }

    pub fn formatANSI(self: @This(), writer: *Io.Writer) Io.Writer.Error!void {
        try formatGen(@This(), self, writer, true);
    }

    pub fn formatGen(
        T: type,
        self: T,
        writer: *Io.Writer,
        use_ansi: bool,
    ) Io.Writer.Error!void {
        // Setup Writer
        var filter_writer: ansi.FilterWriter = .init(writer);
        const w: *Io.Writer = //
            if (use_ansi) writer //
            else &filter_writer.io_writer;
        // ANSI Resets
        try w.print("{s}", .{ ansi.reset });
        defer w.print("{s}", .{ ansi.reset }) catch {};
        // Format
        const ssid: []const u8 = ssid: {
            if (//
                self.ssid.len > 0 and //
                !mem.eql(u8, self.ssid, &.{ 0 }) //
            ) break :ssid self.ssid;
            break :ssid "[HIDDEN NETWORK] (DisCo)";
        };
        try writer.print(
            \\{s}{s}{s}
            \\- {s}BSSID{s}:     {f} ({s})
            \\- {s}Security{s}:  {t}
            \\- {s}Auth{s}:      {t}
            \\- {s}Channel{s}:   {d} ({d} MHz)
            \\
            , .{
                ansi.fmt.bold, ssid, ansi.reset,
                ansi.fmt.underline, ansi.reset, MACF{ .bytes = self.bssid[0..] }, netdata.oui.findOUI(.short, self.bssid) catch "OUI Unavailable",
                ansi.fmt.underline, ansi.reset, self.security,
                ansi.fmt.underline, ansi.reset, self.auth,
                ansi.fmt.underline, ansi.reset, self.channel, self.freq,
            },
        );
        if (T == Network) {
            var meta_iter = self.net_meta.iterator();
            defer self.net_meta.mutex.unlock();
            while (meta_iter.next()) |meta_entry| {
                try writer.print(
                    \\----------
                    \\{f}
                    , .{ meta_entry.value_ptr }
                );
            }
        } //
        else {
            for (self.net_meta) |nm| {
                try writer.print(
                    \\----------
                    \\{f}
                    , .{ nm }
                );
            }
        }
    }
};

/// Network Scan Context
pub const ScanContext = union(enum) {
    /// Monitor Mode Scan
    monitor: struct {
        /// Netlink Route Request Context
        req_ctx_rt: nl.io.RequestContext,
        /// Netlink 80211 Request Context
        req_ctx_80211: nl.io.RequestContext,
        /// Netlink Request State
        nl_state: core.AsyncState,
        /// Allowed Channels
        allowed_chans: []const chs.Channel,
        /// Current Channel Index
        ch_idx: usize = 1_000,
        /// Dwell Time for each Channel in Nanoseconds (ns)
        dwell: u64 = 1_000 * time.ns_per_ms,
        /// Timer
        timer: time.Timer,
        /// Monitor Mode Setup
        setup: enum { down, mon, up, done } = .down,
    },
    /// Netlink Scan
    netlink: struct {
        /// Netlink Request Context
        req_ctx: nl.io.RequestContext,
        /// Netlink Scan State
        scan_state: enum {
            trigger,
            results,
        },
        /// Netlink Request State
        nl_state: core.AsyncState,
        /// Timer
        timer: time.Timer,
        //scan_config: nl._80211.TriggerScanConfig,
    },
};

/// Network Contextrtnetlink_handler
pub const Context = struct {
    /// Arena
    _arena: *heap.ArenaAllocator,
    /// Arena Allocator
    _a_alloc: mem.Allocator,
    /// Global Netlink Scan Config
    global_nl_scan_config: nl._80211.TriggerScanConfig,
    /// Netlink Scan Configs for Interfaces
    nl_scan_configs: *ThreadHashMap([]const u8, nl._80211.TriggerScanConfig),
    /// List of all Networks seen
    networks: *ThreadHashMap([6]u8, Network),

    /// Initialize all Maps.
    pub fn init(core_ctx: *core.Core) !@This() {
        var self: @This() = undefined;
        self._arena = core_ctx.alloc.create(heap.ArenaAllocator) catch @panic("OOM");
        self._arena.* = .init(core_ctx.alloc);
        self._a_alloc = self._arena.allocator();
        self.global_nl_scan_config = globalConf: {
            const freqs: ?[]const u32 = freqs: {
                if (core_ctx.config.global_scan_config.channels.len == 0) //
                    break :freqs null;
                var freqs_list: ArrayList(u32) = .empty;
                errdefer freqs_list.deinit(core_ctx.alloc);
                for (core_ctx.config.global_scan_config.channels) |ch| {
                    const freq = try ch.toFreq();
                    freqs_list.append(core_ctx.alloc, @truncate(freq)) catch @panic("OOM");
                }
                break :freqs freqs_list.toOwnedSlice(core_ctx.alloc) catch @panic("OOM");
            };
            break :globalConf .{
                .freqs = freqs,
                .ssids = core_ctx.config.global_scan_config.ssids,
            };
        };
        self.nl_scan_configs = core_ctx.alloc.create(ThreadHashMap([]const u8, nl._80211.TriggerScanConfig)) catch @panic("OOM");
        self.nl_scan_configs.* = .empty;
        for (core_ctx.config.scan_configs) |config| {
            log.debug("Added Scan Config for '{s}'", .{ config.if_name });
            const freqs: ?[]const u32 = freqs: {
                const channels = config.channels orelse break :freqs null;
                var freqs_list: ArrayList(u32) = .empty;
                errdefer freqs_list.deinit(core_ctx.alloc);
                for (channels) |ch| {
                    const freq = try ch.toFreq();
                    try freqs_list.append(core_ctx.alloc, @truncate(freq));
                }
                break :freqs try freqs_list.toOwnedSlice(core_ctx.alloc);
            };
            const trigger_config: nl._80211.TriggerScanConfig = .{
                .freqs = freqs,
                .ssids = config.ssids,
            };
            self.nl_scan_configs.put(core_ctx.alloc, config.if_name, trigger_config) catch @panic("OOM");
        }
        log.debug("Total Scan Configs: {d}", .{ self.nl_scan_configs.count() });
        //log.debug("Global Scan Channels:\n{f}", .{ SliceF(chs.Channel, "- {f}"){ .slice = core_ctx.config.global_scan_config.channels, .separator = "\n" } });
        self.networks = core_ctx.alloc.create(ThreadHashMap([6]u8, Network)) catch @panic("OOM");
        self.networks.* = .empty;
        const nl80211_info = nl._80211.ctrl_info orelse @panic("Netlink 802.11 (nl80211) not Initialized!");
        const nl80211_scan = nl80211_info.MCAST_GROUPS.get("scan") orelse @panic("Netlink 802.11 (nl80211) not Initialized!");
        try posix.setsockopt(
            core_ctx.nl80211_handler.nl_sock,
            posix.SOL.NETLINK,
            nl.NETLINK_OPT.ADD_MEMBERSHIP,
            mem.toBytes(nl80211_scan)[0..],
        );
        core_ctx.nl80211_handler.trackCommand(c(nl._80211.CMD).NEW_SCAN_RESULTS) catch @panic("OOM");
        return self;
    }

    /// Deinitialize all Maps.
    pub fn deinit(self: *@This(), alloc: mem.Allocator) void {
        var scan_conf_iter = self.nl_scan_configs.iterator();
        while (scan_conf_iter.next()) |scan_conf| //
            alloc.free(scan_conf.value_ptr.freqs orelse continue);
        scan_conf_iter.unlock();
        self.nl_scan_configs.deinit(alloc);
        alloc.destroy(self.nl_scan_configs);
        if (self.global_nl_scan_config.freqs) |freqs|
            alloc.free(freqs);
        if (self.global_nl_scan_config.ssids) |ssids|
            alloc.free(ssids);
        var nw_iter = self.networks.iterator();
        while (nw_iter.next()) |nw_entry| //
            nw_entry.value_ptr.deinit(alloc);
        nw_iter.unlock();
        self.networks.deinit(alloc);
        alloc.destroy(self.networks);
        self._arena.deinit();
        alloc.destroy(self._arena);
        //alloc.destroy(self._arena_fba);
    }

    /// Update Networks
    pub fn update(self: *@This(), core_ctx: *core.Core) !void {
        if (core_ctx.run_condition) |*condition| {
            switch (condition.*) {
                .list_interfaces,
                .mod_interfaces,
                => return,
                .network_scan => |*scan_cond| {
                    scan_cond._cur_iter +|= 1;
                    const usable_ifs: u8 = usableIFs: {
                        var usable_ifs: u8 = 0;
                        defer core_ctx.if_ctx.interfaces.mutex.unlock();
                        var if_iter = core_ctx.if_ctx.interfaces.iterator();
                        while (if_iter.next()) |check_if_entry| {
                            const check_if = check_if_entry.value_ptr;
                            switch (check_if.usage) {
                                .inactive, .err => continue,
                                else => usable_ifs += 1,
                            }
                        }
                        //log.debug("Usable IFs: {d}", .{ usable_ifs });
                        break :usableIFs usable_ifs;
                    };
                    if ( //
                        scan_cond._cur_iter >= 250 and //
                        usable_ifs == 0 //
                    ) {
                        log.err("No usable Interfaces found.", .{});
                        return error.NoUsableInterfaces;
                    }
                },
            }
        }
        //defer _ = self._arena.reset(.retain_capacity);
        if (self._arena.state.end_index > 1_000)
            _ = self._arena.reset(.retain_capacity);
        //log.debug("Network Arena Capacity: {d}B", .{ self._arena.queryCapacity() });
        const scan_result_resps = core_ctx.nl80211_handler.getCmdResponses(c(nl._80211.CMD).NEW_SCAN_RESULTS) catch @panic("OOM");
        defer {
            for (scan_result_resps) |resp| {
                const data = resp catch continue;
                core_ctx.alloc.free(data);
            }
            core_ctx.alloc.free(scan_result_resps);
        }
        var if_iter = core_ctx.if_ctx.interfaces.iterator();
        defer core_ctx.if_ctx.interfaces.mutex.unlock();
        var scan_list: ArrayList(i32) = .empty;
        defer scan_list.deinit(core_ctx.alloc);
        while (if_iter.next()) |scan_if_entry| {
            const scan_if = scan_if_entry.value_ptr;
            scanIf: switch (scan_if.usage) {
                .active => {
                    scan_if.usage = switch (core_ctx.config.global_scan_config.mode) {
                        .netlink => .{
                            .scan = .{
                                .netlink = .{
                                    .req_ctx = try .init(.{ .handler = .{ .handler = core_ctx.nl80211_handler } }),
                                    .nl_state = .ready,
                                    .scan_state = .trigger,
                                    .timer = try .start(),
                                },
                            },
                        },
                        .monitor => .{
                            .scan = .{
                                .monitor = .{
                                    .req_ctx_rt = try .init(.{ .handler = .{ .handler = core_ctx.rtnetlink_handler } }),
                                    .req_ctx_80211 = try .init(.{ .handler = .{ .handler = core_ctx.nl80211_handler } }),
                                    .nl_state = .ready,
                                    .timer = try .start(),
                                    .allowed_chans = allowedChans: {
                                        for (core_ctx.config.scan_configs) |scan_conf| {
                                            if (!mem.eql(u8, scan_conf.if_name, scan_if.name)) //
                                                continue;
                                            const conf_chans = scan_conf.channels orelse &.{};
                                            if (conf_chans.len != 0) //
                                                break :allowedChans conf_chans;
                                            if (core_ctx.config.global_scan_config.channels.len > 0) //
                                                break :allowedChans core_ctx.config.global_scan_config.channels;
                                            break :allowedChans scan_if.supported_chans;
                                        } //
                                        if (core_ctx.config.global_scan_config.channels.len > 0) //
                                            break :allowedChans core_ctx.config.global_scan_config.channels;
                                        break :allowedChans scan_if.supported_chans;
                                    },
                                    .dwell = core_ctx.config.global_scan_config.dwell * time.ns_per_ms,
                                },
                            },
                        },
                    };
                    continue :scanIf scan_if.usage;
                },
                .scan => |*scan_ctx| {
                    switch (scan_ctx.*) {
                        .netlink => |*nl_ctx| {
                            const scan_results_ready: bool = resultsReady: {
                                for (scan_result_resps) |response| {
                                    const data = response catch continue;
                                    //log.debug("Scan Results Len: {d}B", .{ data.len });
                                    const results = try nl._80211.handleScanResultsBuf(self._a_alloc, data);
                                    for (results) |result| {
                                        if (result.IFINDEX != scan_if.index) //
                                            continue;
                                        //log.debug("Found New Scan Results! ({s})", .{ scan_if.name });
                                        break :resultsReady true;
                                    }
                                }
                                break :resultsReady false;
                            };
                            nlState: switch (nl_ctx.nl_state) {
                                .ready, .request => {
                                    nl_ctx.req_ctx.nextSeqID();
                                    switch (nl_ctx.scan_state) {
                                        .trigger => {
                                            if (scan_if.checkPenalty()) continue;
                                            defer self.nl_scan_configs.mutex.unlock();
                                            const scan_config = scanConfig: {
                                                const scan_config_entry = self.nl_scan_configs.getEntry(scan_if.name) orelse {
                                                    break :scanConfig self.global_nl_scan_config;
                                                };
                                                break :scanConfig scan_config_entry.value_ptr.*;
                                            };
                                            //const scan_config = self.global_scan_config;
                                            try nl._80211.requestTriggerScan(
                                                core_ctx.alloc,
                                                &nl_ctx.req_ctx,
                                                scan_if.index,
                                                scan_config,
                                            );
                                        },
                                        .results => {
                                            if (nl_ctx.timer.read() > 10 * time.ns_per_s) {
                                                log.warn("Scan timed out on Interface '{s}'.", .{ scan_if.name });
                                                scan_if.usage = .active;
                                                continue;
                                            }
                                            if (!scan_results_ready) continue;
                                            try nl._80211.requestScanResults(
                                                core_ctx.alloc,
                                                &nl_ctx.req_ctx,
                                                scan_if.index,
                                            );
                                        },
                                    }
                                    nl_ctx.nl_state = .await_response;
                                },
                                .await_response => {
                                    if (!nl_ctx.req_ctx.checkResponse()) continue;
                                    nl_ctx.nl_state = .parse;
                                    continue :nlState nl_ctx.nl_state;
                                },
                                .parse => {
                                    switch (nl_ctx.scan_state) {
                                        .trigger => {
                                            if (nl_ctx.req_ctx.getResponse()) |trigger_resp| {
                                                if (trigger_resp) |resp_data| {
                                                    core_ctx.alloc.free(resp_data);
                                                    log.debug("Triggered a scan.", .{});
                                                    scan_if.subtractPenalty();
                                                    nl_ctx.scan_state = .results;
                                                    nl_ctx.nl_state = .request;
                                                }
                                                else |err| {
                                                    log.warn("Could not trigger scan w/ Interface '{s}': {t}", .{ scan_if.name, err });
                                                    scan_if.addPenalty();
                                                    scan_if.usage = .active;
                                                }
                                            }
                                        },
                                        .results => results: {
                                            defer resUpd: {
                                                scan_if.usage = .active;
                                                const condition: *core.Core.RunCondition = &(core_ctx.run_condition orelse break: resUpd);
                                                switch (condition.*) {
                                                    .network_scan => |*scan_cond| scan_cond._cur_passes += 1,
                                                    else => {}
                                                }
                                            }
                                            var parse_time: time.Timer = try .start();
                                            defer log.debug("Parse Time: {d}ms", .{ @divFloor(parse_time.read(), time.ns_per_ms) });
                                            const scan_result_data: []const u8 = nl_ctx.req_ctx.getResponse().? catch |err| {
                                                log.warn("Could not get Scan Results for Interface '{s}': {t}", .{ scan_if.name, err });
                                                break :results;
                                            };
                                            defer core_ctx.alloc.free(scan_result_data);
                                            const scan_results = try nl._80211.handleScanResultsBuf(self._a_alloc, scan_result_data);
                                            log.debug("Parsing {d} Scan Results for '{s}'.", .{ scan_results.len, scan_if.name });
                                            for (scan_results) |result| {
                                                const bss = result.BSS orelse continue;
                                                const new_network: Network = newNetwork: {
                                                    const old_network_entry = self.networks.getEntry(bss.BSSID);
                                                    defer self.networks.mutex.unlock();
                                                    var valid: bool = false;
                                                    const sec_info = try bss.getSecurityInfo();
                                                    const ies = bss.INFORMATION_ELEMENTS orelse continue;
                                                    const ssid = core_ctx.alloc.dupe(u8, ies.SSID orelse "[HIDDEN NETWORK]") catch @panic("OOM");
                                                    defer if (!valid) //
                                                        core_ctx.alloc.free(ssid);
                                                    const if_name = core_ctx.alloc.dupe(u8, scan_if.name) catch @panic("OOM");
                                                    defer if (!valid) //
                                                        core_ctx.alloc.free(if_name);
                                                    const net_meta: Network.Meta = .{
                                                        .seen_by = if_name,
                                                        .last_seen = try zeit.instant(.{}),
                                                        .rssi = @divFloor(bss.SIGNAL_MBM orelse continue, 100),
                                                    };
                                                    var net_meta_map: *ThreadHashMap([6]u8, Network.Meta) = netMetaMap: {
                                                        const entry = old_network_entry orelse {
                                                            const new_meta_map = core_ctx.alloc.create(ThreadHashMap([6]u8, Network.Meta)) catch @panic("OOM");
                                                            new_meta_map.* = .empty;
                                                            break :netMetaMap new_meta_map;
                                                        };
                                                        break :netMetaMap entry.value_ptr.net_meta;
                                                    };
                                                    {
                                                        const old_meta_entry = net_meta_map.getEntry(scan_if.og_mac);
                                                        defer net_meta_map.mutex.unlock();
                                                        if (old_meta_entry) |entry| {
                                                            const old_meta = entry.value_ptr;
                                                            old_meta.deinit(core_ctx.alloc);
                                                        }
                                                    }
                                                    net_meta_map.put(core_ctx.alloc, scan_if.og_mac, net_meta) catch @panic("OOM");
                                                    const new_network: Network = .{
                                                        .bssid = bss.BSSID,
                                                        .ssid = ssid,
                                                        .security = sec_info.type,
                                                        .auth = sec_info.auth,
                                                        .freq = bss.FREQUENCY,
                                                        .channel = channel: {
                                                            // TODO: Properly pull the Channel Width
                                                            const bw: chs.Bandwidth = @enumFromInt(bss.CHAN_WIDTH orelse 20);
                                                            const ch: chs.Channel = try .fromFreqBW(bss.FREQUENCY, bw);
                                                            break :channel ch.pri;
                                                        },
                                                        .net_meta = net_meta_map,
                                                        .bss = bss: {
                                                            if (old_network_entry) |entry| //
                                                                break :bss entry.value_ptr.bss;
                                                            break :bss try nl.parse.clone(core_ctx.alloc, nl._80211.BasicServiceSet, bss);
                                                        },
                                                    };
                                                    //log.debug("{f}===================\n", .{ new_network });
                                                    core_ctx.conn_ctx.configs.mutex.lock();
                                                    defer core_ctx.conn_ctx.configs.mutex.unlock();
                                                    confs: for (core_ctx.conn_ctx.configs.list.items) |conf| {
                                                        switch (conf.id) {
                                                            .bssid => |bssid| {
                                                                if (!mem.eql(u8, bssid[0..], new_network.bssid[0..])) //
                                                                    continue;
                                                            },
                                                            .ssid => |conf_ssid| {
                                                                if (!mem.eql(u8, conf_ssid, new_network.ssid)) //
                                                                    continue;
                                                            },
                                                        }
                                                        log.info("{f}===================\n", .{ new_network });
                                                        break :confs;
                                                    }
                                                    valid = true;
                                                    if (old_network_entry) |entry| {
                                                        const old_network = entry.value_ptr;
                                                        core_ctx.alloc.free(old_network.ssid);
                                                    }
                                                    break :newNetwork new_network;
                                                };
                                                self.networks.put(core_ctx.alloc, bss.BSSID, new_network) catch @panic("OOM");
                                            }
                                        },
                                    }
                                },
                            }
                        },
                        .monitor => |*mon_ctx| {
                            monSetup: switch (mon_ctx.setup) {
                                .down,
                                .up,
                                => setIFF: switch (mon_ctx.nl_state) {
                                    .ready, .request => {
                                        if (mon_ctx.timer.read() < 100 * time.ns_per_ms) //
                                            continue;
                                        const set_state = //
                                            if (mon_ctx.setup == .down) //
                                                c(nl.route.IFF).DOWN //
                                            else //
                                                c(nl.route.IFF).UP;
                                        mon_ctx.req_ctx_rt.nextSeqID();
                                        try nl.route.requestSetState(
                                            core_ctx.alloc,
                                            &mon_ctx.req_ctx_rt,
                                            scan_if.index,
                                            set_state,
                                        );
                                        mon_ctx.nl_state = .await_response;
                                        continue :setIFF mon_ctx.nl_state;
                                    },
                                    .await_response => {
                                        if (!mon_ctx.req_ctx_rt.checkResponse()) //
                                            continue;
                                        mon_ctx.nl_state = .parse;
                                        continue :setIFF mon_ctx.nl_state;
                                    },
                                    .parse => {
                                        const set_tag = //
                                            if (mon_ctx.setup == .down) //
                                                nl.route.IFF.DOWN //
                                            else //
                                                nl.route.IFF.UP;
                                        const mod_resp = mon_ctx.req_ctx_rt.getResponse() orelse continue;
                                        if (mod_resp) |resp_data| {
                                            core_ctx.alloc.free(resp_data);
                                            log.info("Set '{s} ({d})' to {t}", .{ scan_if.name, scan_if.index, set_tag });
                                        } //
                                        else |err| {
                                            log.warn("Unable to set '{s}' to {t}: {t}", .{ scan_if.name, set_tag, err });
                                            scan_if.usage = .{ .err = err };
                                        }
                                        mon_ctx.nl_state = .ready;
                                        mon_ctx.setup = //
                                            if (mon_ctx.setup == .down) .mon //
                                            else .done;
                                        mon_ctx.timer.reset();
                                        continue :monSetup mon_ctx.setup;
                                    },
                                },
                                .mon => setMon: switch (mon_ctx.nl_state) {
                                    .ready, .request => {
                                        if (mon_ctx.timer.read() < 100 * time.ns_per_ms) //
                                            continue;
                                        log.debug("Switching Interface '{s}' to Monitor Mode.", .{ scan_if.name });
                                        mon_ctx.req_ctx_80211.nextSeqID();
                                        try nl._80211.requestSetMode(
                                            core_ctx.alloc,
                                            &mon_ctx.req_ctx_80211,
                                            scan_if.index,
                                            c(nl._80211.IFTYPE).MONITOR,
                                        );
                                        mon_ctx.nl_state = .await_response;
                                        continue :setMon mon_ctx.nl_state;
                                    },
                                    .await_response => {
                                        if (!mon_ctx.req_ctx_80211.checkResponse()) //
                                            continue;
                                        mon_ctx.nl_state = .parse;
                                        continue :setMon mon_ctx.nl_state;
                                    },
                                    .parse => {
                                        const mod_resp = mon_ctx.req_ctx_80211.getResponse() orelse continue;
                                        if (mod_resp) |resp_data| {
                                            core_ctx.alloc.free(resp_data);
                                            log.info("Switched '{s} ({d})' to Monitor Mode", .{ scan_if.name, scan_if.index });
                                            mon_ctx.timer.reset();
                                        } //
                                        else |err| {
                                            log.warn("Unable to switch '{s}' to Monitor Mode: {t}", .{ scan_if.name, err });
                                            scan_if.usage = .{ .err = err };
                                            continue;
                                        }
                                        mon_ctx.nl_state = .ready;
                                        mon_ctx.setup = .up;
                                        continue :monSetup mon_ctx.setup;
                                    },
                                },
                                //.up,
                                .done => {},
                            }
                            mon: switch (mon_ctx.nl_state) {
                                .ready, .request => {
                                    //log.debug("Timer: {d}/{d}ms, Allowed Chans: {d}", .{ @divFloor(mon_ctx.timer.read(), time.ns_per_ms), @divFloor(mon_ctx.rate, time.ns_per_ms), mon_ctx.allowed_chans.len });
                                    //log.debug("Allowed Chans: {d}", .{ mon_ctx.allowed_chans.len });
                                    const single_ch: bool = singleCh: {
                                        const if_ch = scan_if.channel orelse break :singleCh false;
                                        break :singleCh mon_ctx.allowed_chans.len == 1 and meta.eql(mon_ctx.allowed_chans[mon_ctx.ch_idx], if_ch);
                                    };
                                    if ( //
                                        single_ch or //
                                        mon_ctx.timer.read() < mon_ctx.dwell or //
                                        mon_ctx.allowed_chans.len == 0 //
                                    ) //
                                        continue;
                                    mon_ctx.ch_idx +|= 1;
                                    if (mon_ctx.ch_idx >= mon_ctx.allowed_chans.len) //
                                        mon_ctx.ch_idx = 0;
                                    const ch = mon_ctx.allowed_chans[mon_ctx.ch_idx];
                                    //log.debug("Updating Channel of Interface '{s}' to {f}...", .{ scan_if.name, ch });
                                    mon_ctx.req_ctx_80211.nextSeqID();
                                    nl._80211.requestSetFreq(
                                        core_ctx.alloc,
                                        &mon_ctx.req_ctx_80211,
                                        scan_if.index,
                                        try ch.toFreq(),
                                        nl._80211.CHANNEL_WIDTH.fromBW(ch.bw),
                                    ) catch |err| {
                                        log.warn("Unable to change Channel of '{s}': {t}", .{ scan_if.name, err });
                                        continue;
                                    };
                                    mon_ctx.nl_state = .await_response;
                                    continue :mon mon_ctx.nl_state;
                                },
                                .await_response => {
                                    if (!mon_ctx.req_ctx_80211.checkResponse()) //
                                        continue;
                                    mon_ctx.nl_state = .parse;
                                    continue :mon mon_ctx.nl_state;
                                },
                                .parse => {
                                    const mod_resp = mon_ctx.req_ctx_80211.getResponse().?;
                                    if (mod_resp) |resp_data| {
                                        core_ctx.alloc.free(resp_data);
                                        log.debug("Changed Channel of '{s}' to '{f}'", .{ scan_if.name, mon_ctx.allowed_chans[mon_ctx.ch_idx] });
                                        mon_ctx.timer.reset();
                                    } //
                                    else |err| //
                                        log.warn("Unable to change Channel of '{s}': {t}", .{ scan_if.name, err });
                                    mon_ctx.nl_state = .ready;
                                    continue :mon mon_ctx.nl_state;
                                },
                            }
                        },
                    }
                },
                else => {},
            }
        }
    }
};
