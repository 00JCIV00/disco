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
const MACF = address.MACFormatter;
const IPF = address.IPFormatter;
const core = @import("../core.zig");
const nl = @import("../netlink.zig");
const proto = @import("../protocols.zig");
const wpa = proto.wpa;
const utils = @import("../utils.zig");
const c = utils.toStruct;
const ThreadHashMap = utils.ThreadHashMap;


/// Network Info
pub const Network = struct {
    // Details
    bssid: [6]u8,
    ssid: []const u8,
    security: nl._80211.SecurityType,
    auth: nl._80211.AuthType,
    channel: u32,
    freq: u32,
    //beacon_interval: ?u16 = null,
    //bss_tsf: ?u64 = null,
    net_meta: *ThreadHashMap([6]u8, Meta),
    scan_result: nl._80211.ScanResults,

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

        pub fn calcRxQual(self: *const @This()) usize {
            if (self.frame_nums.len < 2) return 0;
            const first = self.frame_nums[0];
            const last = self.frame_nums[self.frame_nums.len - 1];
            const total: usize = last - first;
            return @intFromFloat(@as(f128, @floatFromInt(@divFloor(self.frame_nums.len, total))) * 100);
        }

        pub fn format(self: @This(), writer: *Io.Writer) Io.Writer.Error!void {
            var last_ts_buf: [50]u8 = undefined;
            const last_ts = self.last_seen.time().bufPrint(last_ts_buf[0..], .rfc3339) catch "[Time Format Error]";
            try writer.print(
                \\- Seen By:   {s}
                \\- RSSI:      {d} dBm
                \\- Rx Qual:   {d}
                \\- Last Seen: {s}
                \\
                , .{
                    self.seen_by,
                    self.rssi,
                    self.calcRxQual(),
                    last_ts,
                },
            );
        }
    };

    pub fn deinit(self: *const @This(), alloc: mem.Allocator) void {
        alloc.free(self.ssid);
        var meta_iter = self.net_meta.iterator();
        while (meta_iter.next()) |meta_entry|
            meta_entry.value_ptr.deinit(alloc);
        self.net_meta.mutex.unlock();
        self.net_meta.deinit(alloc);
        nl.parse.freeBytes(alloc, nl._80211.ScanResults, self.scan_result);
        alloc.destroy(self.net_meta);
    }

    pub fn format(self: @This(), writer: *Io.Writer) Io.Writer.Error!void {
        const ssid: []const u8 = ssid: {
            if (//
                self.ssid.len > 0 and //
                !mem.eql(u8, self.ssid, &.{ 0 }) //
            ) break :ssid self.ssid;
            break :ssid "[HIDDEN NETWORK] (DisCo)";
        };
        try writer.print(
            \\{s}
            \\- BSSID:     {f} ({s})
            \\- Security:  {t}
            \\- Auth:      {t}
            \\- Channel:   {d} ({d} MHz)
            \\
            , .{
                ssid,
                MACF{ .bytes = self.bssid[0..] }, netdata.oui.findOUI(.short, self.bssid) catch "OUI Unavailable",
                self.security,
                self.auth,
                self.channel, self.freq,
            },
        );
        var meta_iter = self.net_meta.iterator();
        defer self.net_meta.mutex.unlock();
        while (meta_iter.next()) |meta_entry| {
            try writer.print(
                \\----------
                \\{f}
                , .{ meta_entry.value_ptr }
            );
        }
    }
};

/// Network Scan Context
pub const NetworkScanContext = union(enum) {
    /// Monitor Mode Scan
    /// TODO: WIP
    monitor,
    /// Netlink Scan
    netlink: struct {
        req_ctx: nl.io.RequestContext,
        scan_state: enum {
            trigger,
            results,
        },
        nl_state: core.AsyncState,
        timer: time.Timer,
        //scan_config: nl._80211.TriggerScanConfig,
    },
};

/// Network Contextrtnetlink_handler
pub const Context = struct {
    /// Buffer
    /// TODO: Figure out StackFallback for this or a way to Stream through the data while parsing. (Or move back to Heap Allocation) 
    _buffer: [666_000]u8 = undefined,
    /// Fixed Buffer Allocator
    _arena_fba: *heap.FixedBufferAllocator,
    /// Arena
    _arena: *heap.ArenaAllocator,
    /// Arena Allocator
    _a_alloc: mem.Allocator,
    /// Scan Configs for Interfaces
    scan_configs: *ThreadHashMap([]const u8, nl._80211.TriggerScanConfig),
    /// List of all Networks seen
    networks: *ThreadHashMap([6]u8, Network),

    /// Initialize all Maps.
    pub fn init(core_ctx: *core.Core) !@This() {
        var self: @This() = undefined;
        self._arena_fba = core_ctx.alloc.create(heap.FixedBufferAllocator) catch @panic("OOM");
        self._arena_fba.* = .init(self._buffer[0..]);
        self._arena = core_ctx.alloc.create(heap.ArenaAllocator) catch @panic("OOM");
        self._arena.* = .init(self._arena_fba.allocator());
        //self._arena.* = .init(core_ctx.alloc);
        self._a_alloc = self._arena.allocator();
        self.scan_configs = core_ctx.alloc.create(ThreadHashMap([]const u8, nl._80211.TriggerScanConfig)) catch @panic("OOM");
        self.scan_configs.* = .empty;
        for (core_ctx.config.scan_configs) |config| {
            log.debug("Added Scan Config for '{s}'", .{ config.if_name });
            const freqs: ?[]const u32 = freqs: {
                const channels = config.channels orelse break :freqs null;
                var freqs_list: ArrayList(u32) = .empty;
                errdefer freqs_list.deinit(core_ctx.alloc);
                for (channels) |ch| {
                    const freq = try nl._80211.freqFromChannel(ch);
                    try freqs_list.append(core_ctx.alloc, @truncate(freq));
                }
                break :freqs try freqs_list.toOwnedSlice(core_ctx.alloc);
            };
            const trigger_config: nl._80211.TriggerScanConfig = .{
                .freqs = freqs,
                .ssids = config.ssids,
            };
            self.scan_configs.put(core_ctx.alloc, config.if_name, trigger_config) catch @panic("OOM");
        }
        log.debug("Total Scan Configs: {d}", .{ self.scan_configs.count() });
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
        var scan_conf_iter = self.scan_configs.iterator();
        while (scan_conf_iter.next()) |scan_conf| alloc.free(scan_conf.value_ptr.freqs orelse continue);
        scan_conf_iter.unlock();
        self.scan_configs.deinit(alloc);
        alloc.destroy(self.scan_configs);
        var nw_iter = self.networks.iterator();
        while (nw_iter.next()) |nw_entry| nw_entry.value_ptr.deinit(alloc);
        nw_iter.unlock();
        self.networks.deinit(alloc);
        alloc.destroy(self.networks);
        self._arena.deinit();
        alloc.destroy(self._arena);
        alloc.destroy(self._arena_fba);
    }

    /// Update Networks
    pub fn update(self: *@This(), core_ctx: *core.Core) !void {
        if (core_ctx.run_condition) |condition| {
            switch (condition) {
                .list_interfaces, 
                .mod_interfaces,
                => return,
                else => {},
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
            const scan_results_ready: bool = resultsReady: {
                for (scan_result_resps) |response| {
                    const data = response catch continue;
                    //log.debug("Scan Results Len: {d}B", .{ data.len });
                    const results = try nl._80211.handleScanResultsBuf(self._a_alloc, data);
                    for (results) |result| {
                        if (result.IFINDEX != scan_if.index) continue;
                        //log.debug("Found New Scan Results! ({s})", .{ scan_if.name });
                        break :resultsReady true;
                    }
                }
                break :resultsReady false;
            };
            scanIf: switch (scan_if.usage) {
                .available => {
                    scan_if.usage = .{
                        .scan = .{
                            .netlink = .{
                                .req_ctx = try .init(.{ .handler = .{ .handler = core_ctx.nl80211_handler } }),
                                .nl_state = .ready,
                                .scan_state = .trigger,
                                .timer = try .start(),
                            },
                        },
                    };
                    continue :scanIf scan_if.usage;
                },
                .scan => |*scan_ctx| {
                    switch (scan_ctx.*) {
                        .netlink => |*nl_ctx| {
                            nlState: switch (nl_ctx.nl_state) {
                                .ready, .request => {
                                    nl_ctx.req_ctx.nextSeqID();
                                    switch (nl_ctx.scan_state) {
                                        .trigger => {
                                            if (scan_if.checkPenalty()) continue;
                                            defer self.scan_configs.mutex.unlock();
                                            const scan_config_entry = self.scan_configs.getEntry(scan_if.name) orelse continue;
                                            const scan_config = scan_config_entry.value_ptr.*;
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
                                                scan_if.usage = .available;
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
                                                    scan_if.usage = .available;
                                                }
                                            }
                                        },
                                        .results => results: {
                                            defer resUpd: {
                                                scan_if.usage = .available;
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
                                                    defer if (!valid) core_ctx.alloc.free(ssid);
                                                    const if_name = core_ctx.alloc.dupe(u8, scan_if.name) catch @panic("OOM");
                                                    defer if (!valid) core_ctx.alloc.free(if_name);
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
                                                        .channel = @intCast(try nl._80211.channelFromFreq(bss.FREQUENCY)),
                                                        .net_meta = net_meta_map,
                                                        .scan_result = try nl.parse.clone(core_ctx.alloc, nl._80211.ScanResults, result),
                                                    };
                                                    //log.debug("{s}===================\n", .{ new_network });
                                                    confs: for (core_ctx.config.connect_configs) |conf| {
                                                        if (mem.eql(u8, conf.ssid, new_network.ssid)) {
                                                            log.debug("{f}===================\n", .{ new_network });
                                                            break :confs;
                                                        }
                                                    }
                                                    valid = true;
                                                    if (old_network_entry) |entry| {
                                                        const old_network = entry.value_ptr;
                                                        core_ctx.alloc.free(old_network.ssid);
                                                        nl.parse.freeBytes(core_ctx.alloc, nl._80211.ScanResults, old_network.scan_result);
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
                        .monitor => {},
                    }
                },
                else => {},
            }
        }
    }
};
