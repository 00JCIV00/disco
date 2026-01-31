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
    net_meta: *ThreadHashMap([6]u8, core.devices.Meta),
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
        net_meta: []const core.devices.Meta,

        pub fn deinit(self: *const @This(), alloc: mem.Allocator) void {
            alloc.free(self.ssid);
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
                    var nm_list: ArrayList(core.devices.Meta) = .empty;
                    var nm_iter = from_net.net_meta.iterator();
                    defer nm_iter.unlock();
                    while (nm_iter.next()) |nm_entry| //
                        nm_list.append(alloc, nm_entry.value_ptr.*) catch @panic("OOM");
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

    pub fn deinit(self: *const @This(), alloc: mem.Allocator) void {
        alloc.free(self.ssid);
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
        allowed_chans: []chs.Channel,
        /// Current Channel Index
        ch_idx: usize = 1_000,
        /// Dwell Time for each Channel in Nanoseconds (ns)
        dwell: u64 = 1_000 * time.ns_per_ms,
        /// Timer
        timer: time.Timer,
        /// Monitor Mode Setup
        setup: enum { down, mon, ch, up, roc, ps, done } = .down,
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

/// Network Context
pub const Context = struct {
    /// Arena f/ Scans
    _scan_arena: *heap.ArenaAllocator,
    /// Arena Allocator f/ Scans
    _scan_alloc: mem.Allocator,
    /// Global Netlink Scan Config
    global_nl_scan_config: nl._80211.TriggerScanConfig,
    /// Netlink Scan Configs for Interfaces
    nl_scan_configs: *ThreadHashMap([]const u8, nl._80211.TriggerScanConfig),
    /// List of all Networks seen
    networks: *ThreadHashMap([6]u8, Network),

    /// Initialize the Network Context.
    pub fn init(core_ctx: *core.Core) !@This() {
        var self: @This() = undefined;
        self._scan_arena = core_ctx.alloc.create(heap.ArenaAllocator) catch @panic("OOM");
        self._scan_arena.* = .init(core_ctx.alloc);
        self._scan_alloc = self._scan_arena.allocator();
        self.global_nl_scan_config = globalConf: {
            const freqs: ?[]const u32 = freqs: {
                if (core_ctx.config.global_scan_config.channels.len == 0) //
                    break :freqs null;
                var freqs_list: ArrayList(u32) = .empty;
                errdefer freqs_list.deinit(core_ctx.alloc);
                for (core_ctx.config.global_scan_config.channels) |ch| {
                    const freq: u32 = @truncate(try ch.toFreq());
                    freqs_list.append(core_ctx.alloc, freq) catch @panic("OOM");
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
            const freqs: ?[]const u32 = freqs: {
                const channels = config.channels orelse break :freqs null;
                var freqs_list: ArrayList(u32) = .empty;
                errdefer freqs_list.deinit(core_ctx.alloc);
                for (channels) |ch| {
                    const freq: u32 = @truncate(try ch.toFreq());
                    freqs_list.append(core_ctx.alloc, freq) catch @panic("OOM");
                }
                break :freqs freqs_list.toOwnedSlice(core_ctx.alloc) catch @panic("OOM");
            };
            const trigger_config: nl._80211.TriggerScanConfig = .{
                .freqs = freqs,
                .ssids = config.ssids,
            };
            self.nl_scan_configs.put(core_ctx.alloc, config.if_name, trigger_config) catch @panic("OOM");
            log.debug("Added Scan Config for '{s}'", .{ config.if_name });
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
        if (self.global_nl_scan_config.freqs) |freqs| //
            alloc.free(freqs);
        if (self.global_nl_scan_config.ssids) |ssids| //
            alloc.free(ssids);
        var nw_iter = self.networks.iterator();
        while (nw_iter.next()) |nw_entry| //
            nw_entry.value_ptr.deinit(alloc);
        nw_iter.unlock();
        self.networks.deinit(alloc);
        alloc.destroy(self.networks);
        self._scan_arena.deinit();
        alloc.destroy(self._scan_arena);
        //alloc.destroy(self._arena_fba);
    }

    /// Update Networks
    pub fn update(self: *@This()) !void {
        const core_ctx: *core.Core = @alignCast(@fieldParentPtr("network_ctx", self));
        //const core_ctx: *core.Core = @fieldParentPtr("network_ctx", self);
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
        if (self._scan_arena.state.end_index > 1_000) //
            _ = self._scan_arena.reset(.retain_capacity);
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
                                    .timer = time.Timer.start() catch @panic("Time Issue"),
                                    .allowed_chans = allowedChans: {
                                        const conf_chans: []const chs.Channel = confChans: {
                                            for (core_ctx.config.scan_configs) |scan_conf| {
                                                if (!mem.eql(u8, scan_conf.if_name, scan_if.name)) //
                                                    continue;
                                                const conf_chans = scan_conf.channels orelse &.{};
                                                if (conf_chans.len != 0) //
                                                    break :confChans conf_chans;
                                                break;
                                            }
                                            if (core_ctx.config.global_scan_config.channels.len > 0) //
                                                break :confChans core_ctx.config.global_scan_config.channels;
                                            break :confChans scan_if.supported_chans;
                                        };
                                        var allowed_chans: ArrayList(chs.Channel) = .empty;
                                        addChs: for (conf_chans) |allow_ch| {
                                            for (scan_if.supported_chans) |sup_ch| {
                                                if (!meta.eql(allow_ch, sup_ch)) //
                                                    continue;
                                                allowed_chans.append(self._scan_alloc, allow_ch) catch @panic("OOM");
                                                continue :addChs;
                                            }
                                        }
                                        break :allowedChans allowed_chans.toOwnedSlice(self._scan_alloc) catch @panic("OOM");
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
                                    log.debug("Scan Results Len: {d}B", .{ data.len });
                                    const results = try nl._80211.handleScanResultsBuf(self._scan_alloc, data);
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
                                    switch (nl_ctx.scan_state) {
                                        .trigger => {
                                            if (scan_if.checkPenalty()) //
                                                continue;
                                            defer self.nl_scan_configs.mutex.unlock();
                                            const scan_config = scanConfig: {
                                                const scan_config_entry = self.nl_scan_configs.getEntry(scan_if.name) orelse {
                                                    break :scanConfig self.global_nl_scan_config;
                                                };
                                                break :scanConfig scan_config_entry.value_ptr.*;
                                            };
                                            nl_ctx.req_ctx.nextSeqID();
                                            //const scan_config = self.global_scan_config;
                                            try nl._80211.requestTriggerScan(
                                                core_ctx.alloc,
                                                &nl_ctx.req_ctx,
                                                scan_if.index,
                                                scan_config,
                                            );
                                        },
                                        .results => {
                                            if (nl_ctx.timer.read() < time.ns_per_s) //
                                                continue;
                                            if (nl_ctx.timer.read() > 10 * time.ns_per_s) {
                                                log.warn("Scan timed out on Interface '{s}'.", .{ scan_if.name });
                                                scan_if.usage = .active;
                                                continue;
                                            }
                                            if (!scan_results_ready) //
                                                continue;
                                            nl_ctx.req_ctx.nextSeqID();
                                            try nl._80211.requestScanResults(
                                                core_ctx.alloc,
                                                &nl_ctx.req_ctx,
                                                scan_if.index,
                                            );
                                            nl_ctx.timer.reset();
                                        },
                                    }
                                    nl_ctx.nl_state = .await_response;
                                },
                                .await_response => {
                                    if (!nl_ctx.req_ctx.checkResponse()) //
                                        continue;
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
                                            const scan_results = try nl._80211.handleScanResultsBuf(self._scan_alloc, scan_result_data);
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
                                                    const net_meta: core.devices.Meta = .{
                                                        .if_mac = scan_if.og_mac,
                                                        .mac = bss.BSSID,
                                                        .last_seen = try zeit.instant(.{}),
                                                        .rssi = @divFloor(bss.SIGNAL_MBM orelse continue, 100),
                                                    };
                                                    var net_meta_map: *ThreadHashMap([6]u8, core.devices.Meta) = netMetaMap: {
                                                        const entry = old_network_entry orelse {
                                                            const new_meta_map = core_ctx.alloc.create(ThreadHashMap([6]u8, core.devices.Meta)) catch @panic("OOM");
                                                            new_meta_map.* = .empty;
                                                            break :netMetaMap new_meta_map;
                                                        };
                                                        break :netMetaMap entry.value_ptr.net_meta;
                                                    };
                                                    net_meta_map.put(core_ctx.alloc, scan_if.og_mac, net_meta) catch @panic("OOM");
                                                    const new_network: Network = .{
                                                        .bssid = bss.BSSID,
                                                        .ssid = ssid,
                                                        .security = sec_info.type,
                                                        .auth = sec_info.auth,
                                                        .freq = bss.FREQUENCY,
                                                        .channel = channel: {
                                                            // TODO: Properly pull the Channel Width
                                                            const ch_width: u8 = chWidth: {
                                                                const width = bss.CHAN_WIDTH orelse break :chWidth 20;
                                                                if (width == 0) //
                                                                    break :chWidth 20;
                                                                break :chWidth width;
                                                            };
                                                            //log.debug("Channel Width: {d}", .{ ch_width });
                                                            const bw: chs.Bandwidth = @enumFromInt(ch_width);
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
                                                c(nl.route.IFF).UP | c(nl.route.IFF).PROMISC;
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
                                            else .roc;
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
                                            &.{
                                                //c(nl._80211.MntrFlags).ACTIVE,
                                                c(nl._80211.MntrFlags).OTHER_BSS,
                                                c(nl._80211.MntrFlags).CONTROL,
                                                //c(nl._80211.MntrFlags).FCSFAIL,
                                                //c(nl._80211.MntrFlags).PLCPFAIL,
                                            },
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
                                        mon_ctx.setup = .ch;
                                        continue :monSetup mon_ctx.setup;
                                    },
                                },
                                .ch => ch: switch (mon_ctx.nl_state) {
                                    .ready, .request => {
                                        mon_ctx.req_ctx_80211.nextSeqID();
                                        nl._80211.requestSetFreq(
                                            core_ctx.alloc,
                                            &mon_ctx.req_ctx_80211,
                                            scan_if.index,
                                            chs.Frequencies.band_2G_20[0],
                                            nl._80211.CHANNEL_WIDTH.@"20",
                                        ) catch |err| {
                                            log.warn("Unable to change Channel of '{s}': {t}", .{ scan_if.name, err });
                                            continue;
                                        };
                                        mon_ctx.nl_state = .await_response;
                                        continue :ch mon_ctx.nl_state;
                                    },
                                    .await_response => {
                                        if (!mon_ctx.req_ctx_80211.checkResponse()) //
                                            continue;
                                        mon_ctx.nl_state = .parse;
                                        continue :ch mon_ctx.nl_state;
                                    },
                                    .parse => {
                                        const mod_resp = mon_ctx.req_ctx_80211.getResponse().?;
                                        if (mod_resp) |resp_data| {
                                            core_ctx.alloc.free(resp_data);
                                            log.debug("Reset Channel Context of '{s}'", .{ scan_if.name });
                                            mon_ctx.timer.reset();
                                        } //
                                        else |err| //
                                            log.warn("Unable to Reset Channel Context of '{s}': {t}", .{ scan_if.name, err });
                                        mon_ctx.nl_state = .ready;
                                        mon_ctx.setup = .up;
                                        continue :monSetup mon_ctx.setup;
                                    },
                                },
                                .roc => disROC: switch (mon_ctx.nl_state) {
                                    .ready, .request => {
                                        if (!scan_if.checkCommand(.REMAIN_ON_CHANNEL)) {
                                            mon_ctx.setup = .ps;
                                            continue :monSetup mon_ctx.setup;
                                        }
                                        if (mon_ctx.timer.read() < 100 * time.ns_per_ms) //
                                            continue;
                                        log.debug("Disabling Remain-on-Channel (ROC) on Interface '{s}'...", .{ scan_if.name });
                                        mon_ctx.req_ctx_80211.nextSeqID();
                                        const info = nl._80211.ctrl_info orelse return error.NL80211ControlInfoNotInitialized;
                                        try nl.io.request(
                                            core_ctx.alloc,
                                            nl.generic.Request,
                                            .{
                                                .nlh = .{
                                                    .len = 0,
                                                    .type = info.FAMILY_ID,
                                                    .flags = c(nl.NLM_F).REQUEST | c(nl.NLM_F).ACK,
                                                    .seq = 0,
                                                    .pid = 0,
                                                },
                                                .msg = .{
                                                    .cmd = c(nl._80211.CMD).CANCEL_REMAIN_ON_CHANNEL,
                                                    .version = 1,
                                                },
                                            },
                                            &.{
                                                .{ .hdr = .{ .type = c(nl._80211.ATTR).IFINDEX }, .data = mem.toBytes(scan_if.index)[0..] },
                                                .{ .hdr = .{ .type = c(nl._80211.ATTR).COOKIE }, .data = mem.toBytes(@as(u64, 1234321))[0..] },
                                            },
                                            &mon_ctx.req_ctx_80211,
                                        );
                                        mon_ctx.nl_state = .await_response;
                                        continue :disROC mon_ctx.nl_state;
                                    },
                                    .await_response => {
                                        if (!mon_ctx.req_ctx_80211.checkResponse()) //
                                            continue;
                                        mon_ctx.nl_state = .parse;
                                        continue :disROC mon_ctx.nl_state;
                                    },
                                    .parse => {
                                        const mod_resp = mon_ctx.req_ctx_80211.getResponse() orelse continue;
                                        if (mod_resp) |resp_data| {
                                            core_ctx.alloc.free(resp_data);
                                            log.info("Disabled Remain-on-Channel (ROC) on Interface '{s}'.", .{ scan_if.name });
                                            mon_ctx.timer.reset();
                                        } //
                                        else |err| {
                                            log.warn("Unable to disable Remain-on-Channel (ROC) on Interface '{s}': {t}", .{ scan_if.name, err });
                                            //scan_if.usage = .{ .err = err };
                                            //continue;
                                        }
                                        mon_ctx.nl_state = .ready;
                                        mon_ctx.setup = .ps;
                                        continue :monSetup mon_ctx.setup;
                                    },
                                },
                                .ps => disPS: switch (mon_ctx.nl_state) {
                                    .ready, .request => {
                                        if (mon_ctx.timer.read() < 100 * time.ns_per_ms) //
                                            continue;
                                        log.debug("Disabling Power Save (PS) on Interface '{s}'...", .{ scan_if.name });
                                        mon_ctx.req_ctx_80211.nextSeqID();
                                        try nl._80211.requestSetPowerSave(
                                            core_ctx.alloc,
                                            &mon_ctx.req_ctx_80211,
                                            scan_if.index,
                                            false,
                                        );
                                        mon_ctx.nl_state = .await_response;
                                        continue :disPS mon_ctx.nl_state;
                                    },
                                    .await_response => {
                                        if (!mon_ctx.req_ctx_80211.checkResponse()) //
                                            continue;
                                        mon_ctx.nl_state = .parse;
                                        continue :disPS mon_ctx.nl_state;
                                    },
                                    .parse => {
                                        const mod_resp = mon_ctx.req_ctx_80211.getResponse() orelse continue;
                                        if (mod_resp) |resp_data| {
                                            core_ctx.alloc.free(resp_data);
                                            log.info("Disabled Power Save (PS) on Interface '{s}'.", .{ scan_if.name });
                                            mon_ctx.timer.reset();
                                        } //
                                        else |err| {
                                            log.warn("Unable to disable Power Save (PS) on Interface '{s}': {t}", .{ scan_if.name, err });
                                            //scan_if.usage = .{ .err = err };
                                            //continue;
                                        }
                                        mon_ctx.nl_state = .ready;
                                        mon_ctx.setup = .done;
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
                                    const ch: chs.Channel = ch: {
                                        mon_ctx.ch_idx +|= 1;
                                        if (mon_ctx.ch_idx >= mon_ctx.allowed_chans.len) //
                                            mon_ctx.ch_idx = 0;
                                        break :ch mon_ctx.allowed_chans[mon_ctx.ch_idx];
                                    };
                                    //log.debug("Updating Channel of Interface '{s}' to {f}...", .{ scan_if.name, ch });
                                    mon_ctx.req_ctx_80211.nextSeqID();
                                    nl._80211.requestSetFreq(
                                        core_ctx.alloc,
                                        &mon_ctx.req_ctx_80211,
                                        scan_if.index,
                                        try ch.toFreq(),
                                        nl._80211.CHANNEL_WIDTH.fromBW(ch.bw),
                                    ) catch |err| {
                                        log.warn("Unable to change Channel of '{s}' to {f}: {t}", .{ scan_if.name, ch, err });
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
                                    else |err| {
                                        const rm_ch: chs.Channel = mon_ctx.allowed_chans[mon_ctx.ch_idx];
                                        log.warn("Unable to change Channel of '{s}' to {f}: {t}", .{ scan_if.name, rm_ch, err });
                                        var allow_ch_list: ArrayList(chs.Channel) = .fromOwnedSlice(mon_ctx.allowed_chans);
                                        _ = allow_ch_list.orderedRemove(mon_ctx.ch_idx);
                                        mon_ctx.allowed_chans = allow_ch_list.toOwnedSlice(self._scan_alloc) catch @panic("OOM");
                                        var sup_ch_list: ArrayList(chs.Channel) = .fromOwnedSlice(scan_if.supported_chans);
                                        var sup_freq_list: ArrayList(u32) = .fromOwnedSlice(scan_if.supported_freqs);
                                        for (sup_ch_list.items, 0..) |ch, idx| {
                                            if (!meta.eql(ch, rm_ch)) //
                                                continue;
                                            _ = sup_ch_list.orderedRemove(idx);
                                            _ = sup_freq_list.orderedRemove(idx);
                                            log.warn("Removed Channel {f} from Supported Channels of '{s}'.", .{ rm_ch, scan_if.name });
                                            break;
                                        }
                                        scan_if.supported_chans = sup_ch_list.toOwnedSlice(core_ctx.alloc) catch @panic("OOM");
                                        scan_if.supported_freqs = sup_freq_list.toOwnedSlice(core_ctx.alloc) catch @panic("OOM");
                                    }
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
