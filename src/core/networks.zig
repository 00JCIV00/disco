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
const ArrayList = std.ArrayListUnmanaged;

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

    /// Meta Information about how a Network was Seen
    pub const Meta = struct {
        seen_by: []const u8,
        last_seen: zeit.Instant,
        rssi: i32,
        frame_nums: []const usize = &.{},

        pub fn deinit(self: *const @This(), alloc: mem.Allocator) void {
            alloc.free(self.seen_by);
            alloc.free(self.frame_nums);
        }

        pub fn calcRxQual(self: *const @This()) usize {
            if (self.frame_nums.len < 2) return 0;
            const first = self.frame_nums[0];
            const last = self.frame_nums[self.frame_nums.len - 1];
            const total: usize = last - first;
            return @intFromFloat(@as(f128, @floatFromInt(@divFloor(self.frame_nums.len, total))) * 100);
        }

        pub fn format(
            self: @This(),
            _: []const u8,
            _: fmt.FormatOptions,
            writer: anytype,
        ) !void {
            var last_ts_buf: [50]u8 = undefined;
            const last_ts = try self.last_seen.time().bufPrint(last_ts_buf[0..], .rfc3339);
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
        defer self.net_meta.mutex.unlock();
        while (meta_iter.next()) |meta_entry| 
            meta_entry.value_ptr.deinit(alloc);
        self.net_meta.deinit(alloc);
        alloc.destroy(self.net_meta);
    }

    pub fn format(
        self: @This(),
        _: []const u8,
        _: fmt.FormatOptions,
        writer: anytype,
    ) !void {
        try writer.print(
            \\{s}
            \\- BSSID:     {s} ({s})
            \\- Security:  {s}
            \\- Auth:      {s}
            \\- Channel:   {d} ({d} MHz)
            \\
            , .{
                self.ssid,
                MACF{ .bytes = self.bssid[0..] }, try netdata.oui.findOUI(.short, self.bssid),
                @tagName(self.security),
                @tagName(self.auth),
                self.channel, self.freq,
            },
        );
        var meta_iter = self.net_meta.iterator();
        defer self.net_meta.mutex.unlock();
        while (meta_iter.next()) |meta_entry| {
            try writer.print(
                \\----------
                \\{s}
                \\
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
        req_ctx: nl.RequestContext,
        scan_state: enum {
            trigger,
            results,
        },
        nl_state: core.AsyncState,
        timer: time.Timer,
        //scan_config: nl._80211.TriggerScanConfig,
    },
};

/// Network Context
pub const Context = struct {
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
        self._arena = core_ctx.alloc.create(heap.ArenaAllocator) catch @panic("OOM");
        self._arena.* = .init(core_ctx.alloc);
        self._a_alloc = self._arena.allocator();
        self.scan_configs = core_ctx.alloc.create(ThreadHashMap([]const u8, nl._80211.TriggerScanConfig)) catch @panic("OOM");
        self.scan_configs.* = .empty;
        for (core_ctx.config.scan_configs) |config| {
            log.debug("Added Scan Config for '{s}'", .{ config.if_name });
            const trigger_config: nl._80211.TriggerScanConfig = .{
                .freqs = &.{},
                .ssids = config.ssids,
            };
            self.scan_configs.put(core_ctx.alloc, config.if_name, trigger_config) catch @panic("OOM");
        }
        log.debug("Total Scan Configs: {d}", .{ self.scan_configs.count() });
        self.networks = core_ctx.alloc.create(ThreadHashMap([6]u8, Network)) catch @panic("OOM");
        self.networks.* = .empty;
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
    }

    /// Update Networks
    pub fn update(self: *@This(), core_ctx: *core.Core) !void {
        var if_iter = core_ctx.if_ctx.interfaces.iterator();
        defer core_ctx.if_ctx.interfaces.mutex.unlock();
        var scan_list: ArrayList(i32) = .empty;
        defer scan_list.deinit(core_ctx.alloc);
        while (if_iter.next()) |scan_if_entry| {
            const scan_if = scan_if_entry.value_ptr;
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
                                            const scan_config_entry = self.scan_configs.getEntry(scan_if.name) orelse continue;
                                            defer self.scan_configs.mutex.unlock();
                                            const scan_config = scan_config_entry.value_ptr;
                                            try nl._80211.requestTriggerScan(
                                                core_ctx.alloc,
                                                &nl_ctx.req_ctx,
                                                scan_if.index,
                                                scan_config.*,
                                            );
                                        },
                                        .results => try nl._80211.requestScanResults(
                                            core_ctx.alloc,
                                            &nl_ctx.req_ctx,
                                            scan_if.index,
                                        ),
                                    }
                                    nl_ctx.nl_state = .await_response;
                                },
                                .await_response => {
                                    if (nl_ctx.req_ctx.checkResponse()) {
                                        nl_ctx.nl_state = .parse;
                                        continue :nlState nl_ctx.nl_state;
                                    }
                                },
                                .parse => {
                                    switch (nl_ctx.scan_state) {
                                        .trigger => {
                                            if (nl_ctx.req_ctx.getResponse()) |trigger_resp| _ = trigger_resp catch |err| {
                                                log.warn("Could not trigger scan w/ Interface '{s}': {s}", .{ scan_if.name, @errorName(err) });
                                                scan_if.usage = .available;
                                            };
                                            if (@divFloor(nl_ctx.timer.read(), time.ns_per_ms) >= 5000) {
                                                nl_ctx.scan_state = .results;
                                                nl_ctx.nl_state = .request;
                                            }
                                        },
                                        .results => results: {
                                            defer scan_if.usage = .available;
                                            _ = self._arena.reset(.retain_capacity);
                                            const scan_result_data: []const u8 = nl_ctx.req_ctx.getResponse().? catch |err| {
                                                log.warn("Could not get Scan Results for Interface '{s}': {s}", .{ scan_if.name, @errorName(err) });
                                                break :results;
                                            };
                                            const scan_results = try nl._80211.handleScanResultsBuf(self._a_alloc, scan_result_data);
                                            for (scan_results) |result| {
                                                const bss = result.BSS orelse continue;
                                                const new_network: Network = newNetwork: {
                                                    var valid: bool = false;
                                                    const old_network_entry = self.networks.getEntry(bss.BSSID);
                                                    defer self.networks.mutex.unlock();
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
                                                    net_meta_map.put(core_ctx.alloc, scan_if.og_mac, net_meta) catch @panic("OOM");
                                                    const new_network: Network = .{
                                                        //.if_index = result.IFINDEX,
                                                        .bssid = bss.BSSID,
                                                        .ssid = ssid,
                                                        .security = sec_info.type,
                                                        .auth = sec_info.auth,
                                                        .freq = bss.FREQUENCY,
                                                        .channel = @intCast(try nl._80211.channelFromFreq(bss.FREQUENCY)),
                                                        //.beacon_interval = bss.BEACON_INTERVAL,
                                                        //.bss_tsf = bss.TSF,
                                                        .net_meta = net_meta_map,
                                                    };
                                                    valid = true;
                                                    break :newNetwork new_network;
                                                };
                                                self.networks.put(core_ctx.alloc, bss.BSSID, new_network) catch @panic("OOM");
                                                log.debug("{s}\n===================", .{ new_network });
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


















//-----------------------------------------------
// Pre-Async
//-----------------------------------------------

/// Update an Interface's Scan Schedule Config and Status.
/// Unused
pub fn updScanSched(
    alloc: mem.Allocator,
    scan_if: *core.interfaces.Interface,
    network_ctx: *Context,
    new_config: ?nl._80211.SchedScanConfig,
) !void {
    const _old_conf = network_ctx.scan_configs.get(scan_if.index);
    switch (scan_if.usage) {
        .available => newScan: {
            const config = newConf: {
                if (new_config) |new_conf| {
                    try network_ctx.scan_configs.put(alloc, scan_if.index, new_conf);
                    break :newConf new_conf;
                }
                if (_old_conf) |old_conf| break :newConf old_conf;
                break :newScan;
            };
            nl._80211.startSchedScan(alloc, scan_if.index, config) catch |err| switch (err) {
                error.INPROGRESS => try nl._80211.stopSchedScan(alloc, scan_if.index),
                else => return err,
            };
            scan_if.usage = .scanning;
        },
        .scanning => newScan: {
            const config = new_config orelse break :newScan;
            if (_old_conf) |old_conf| {
                if (meta.eql(old_conf, config)) break :newScan;
            }
            try nl._80211.startSchedScan(alloc, scan_if.index, config);
            try network_ctx.scan_configs.put(alloc, scan_if.index, config);
            scan_if.usage = .scanning;
        },
        else => {
            if (_old_conf) |_| try nl._80211.stopSchedScan(alloc, scan_if.index);
        },
    }
}

/// Update an Interface's Trigger Scan Config and Status.
pub fn updScan(
    alloc: mem.Allocator,
    scan_if: *core.interfaces.Interface,
    network_ctx: *Context,
    trigger_config: ?nl._80211.TriggerScanConfig,
) !void {
    const _old_conf = network_ctx.scan_configs.get(scan_if.index);
    switch (scan_if.usage) {
        .available => triggerScan: {
            var config = triggerConf: {
                if (trigger_config) |new_conf| {
                    try network_ctx.scan_configs.put(alloc, scan_if.index, new_conf);
                    break :triggerConf new_conf;
                }
                if (_old_conf) |old_conf|
                    break :triggerConf old_conf;
                scan_if.usage = .available;
                break :triggerScan;
            };
            config.nl_sock = scan_if.nl_sock;
            nl._80211.triggerScan(alloc, scan_if.index, config) catch |err| switch (err) {
                //error.BUSY,
                error.NODEV => return,
                else => return err,
            };
            scan_if.usage = .scanning;
        },
        else => {},
    }
}

/// Start & Track Network Scans on available Interfaces.
pub fn trackScans(
    alloc: mem.Allocator,
    active: *const atomic.Value(bool),
    interval: *const usize,
    interfaces: *utils.ThreadHashMap(i32, core.interfaces.Interface),
    network_ctx: *Context,
    config: *core.Core.Config,
) void {
    log.debug("Tracking WiFi Scans!", .{});
    var track_count: u8 = 0;
    var err_count: usize = 0;
    const err_max: usize = 10;
    while (active.load(.acquire)) {
        defer {
            track_count +%= 1;
            if (track_count % err_max == 0) err_count -|= 1;
            if (err_count > err_max) @panic("WiFi Scan Tracking encountered too many errors to continue.");
            time.sleep(interval.* * @max(1, (err_count * err_count)));
        }
        for (config.scan_configs) |scan_conf| {
            const if_index = nl.route.getIfIdx(scan_conf.if_name) catch continue;
            if (network_ctx.scan_configs.get(if_index)) |_| continue;
            network_ctx.scan_configs.put(
                alloc,
                if_index,
                //scan_conf_entry.conf,
                .{
                    .ssids = scan_conf.ssids,
                    .freqs = freqs: {
                        const chs = scan_conf.channels orelse break :freqs null;
                        var freqs_list: ArrayList(u32) = .empty;
                        for (chs) |ch| freqs_list.append(alloc, @intCast(nl._80211.freqFromChannel(ch) catch continue)) catch continue;
                        break :freqs freqs_list.toOwnedSlice(alloc) catch @panic("OOM");
                    },
                },
            ) catch |err| {
                log.err("Could not add Scan Config for '{s}': {s}", .{ scan_conf.if_name, @errorName(err) });
                err_count += 1;
                continue;
            };
            log.debug("Updated Interface Index f/ Scan Config: {s} ({d})", .{ scan_conf.if_name, if_index });
        }
        var if_iter = interfaces.iterator();
        defer if_iter.unlock();
        while (if_iter.next()) |if_entry| {
            const scan_if = if_entry.value_ptr;
            updScan(alloc, scan_if, network_ctx, null) catch |err| {
                log.err("Could not update Scan Status for '{s}': {s}", .{ scan_if.name, @errorName(err) });
                err_count += 1;
                continue;
            };
        }
    }
    stopScans(alloc, interfaces, network_ctx);
}

/// Stop All Active Scans.
pub fn stopScans(
    alloc: mem.Allocator,
    interfaces: *utils.ThreadHashMap(i32, core.interfaces.Interface),
    network_ctx: *Context,
) void {
    var if_iter = interfaces.iterator();
    errdefer if_iter.unlock();
    while (if_iter.next()) |if_entry| {
        const scan_if = if_entry.value_ptr;
        updScan(alloc, scan_if, network_ctx, null) catch |err| {
            log.warn("Could not stop scans: {s}", .{ @errorName(err) });
        };
    }
    if_iter.unlock();
}

/// Track Networks
pub fn trackNetworks(
    alloc: mem.Allocator,
    active: *const atomic.Value(bool),
    interval: *const usize,
    interfaces: *utils.ThreadHashMap(i32, core.interfaces.Interface),
    network_ctx: *Context,
) void {
    log.debug("Tracking WiFi Networks!", .{});
    var track_count: u8 = 0;
    var err_count: usize = 0;
    const err_max: usize = 10;
    while (active.load(.acquire)) {
        defer {
            track_count +%= 1;
            if (track_count % err_max == 0) err_count -|= 1;
            if (err_count >= err_max) @panic("WiFi Network Tracking encountered too many errors to continue");
            time.sleep(interval.*);
        }
        //log.debug("Getting Scan Results...", .{});
        var job_count: u32 = 0;
        var if_iter = interfaces.iterator();
        errdefer if_iter.unlock();
        while (if_iter.next()) |if_entry| {
            const scan_if = if_entry.value_ptr;
            if (scan_if.usage == .scanning) job_count += 1;
        }
        if_iter.unlock();
        network_ctx.thread_pool.init(.{ .allocator = alloc, .n_jobs = job_count }) catch |err| {
            log.err("WiFi Network Tracking Error: {s}", .{ @errorName(err) });
            err_count += 1;
            continue;
        };
        defer {
            network_ctx.thread_pool.waitAndWork(network_ctx.wait_group);
            network_ctx.thread_pool.deinit();
            network_ctx.wait_group.reset();
        }
        if_iter = interfaces.iterator();
        defer if_iter.unlock();
        while (if_iter.next()) |if_entry| {
            const scan_if = if_entry.value_ptr;
            if (scan_if.usage != .scanning) continue;
            network_ctx.thread_pool.spawnWg(
                network_ctx.wait_group,
                trackNetworksIFNoErr,
                .{
                    alloc,
                    interfaces,
                    scan_if.index,
                    interval,
                    network_ctx,
                },
            );
        }
    }
}

/// Track Networks on the provided Scan Interface (`scan_if`) w/o bubbling up errors.
fn trackNetworksIFNoErr(
    alloc: mem.Allocator,
    interfaces: *utils.ThreadHashMap(i32, core.interfaces.Interface),
    if_index: i32,
    interval: *const usize,
    network_ctx: *Context,
) void {
    trackNetworksIF(
        alloc,
        interfaces,
        if_index,
        interval,
        network_ctx,
    ) catch |err| {
        log.err("WiFi Network Tracking Error: {s}", .{ @errorName(err) });
        return;
    };
}

/// Track Networks on the provided Scan Interface (`scan_if`)
fn trackNetworksIF(
    alloc: mem.Allocator,
    interfaces: *utils.ThreadHashMap(i32, core.interfaces.Interface),
    if_index: i32,
    interval: *const usize,
    network_ctx: *Context,
) !void {
    const scan_if = interfaces.get(if_index) orelse return error.InterfaceNotFound;
    if (scan_if.usage != .scanning) return;
    log.info("Scanning w/ ({d}) {s}", .{ scan_if.index, scan_if.name });
    defer {
        var set_if = interfaces.getEntry(if_index).?.value_ptr;
        set_if.usage = .available;
        interfaces.mutex.unlock();
    }
    try nl._80211.getScan(alloc, scan_if.index, scan_if.nl_sock);
    const scan_results = nl._80211.handleScanResults(alloc, scan_if.nl_sock) catch |err| {
        log.warn("Could not parse Scan Results: {s}", .{ @errorName(err) });
        return err;
    };
    defer alloc.free(scan_results);
    var result_idx: usize = 0;
    errdefer {
        for (scan_results[result_idx..]) |result|
            nl.parse.freeBytes(alloc, nl._80211.ScanResults, result);
    }
    if (scan_results.len == 0) return;
    log.debug("Parsing {d} Scan Results...", .{ scan_results.len });
    resLoop: for (scan_results) |result| {
        //log.debug("Result: {d}", .{ result.IFINDEX });
        var valid_result: bool = false;
        defer {
            if(!valid_result) nl.parse.freeBytes(alloc, nl._80211.ScanResults, result);
            result_idx += 1;
        }
        const bss = result.BSS orelse continue;
        const bssid = bss.BSSID;
        const sec_info = try bss.getSecurityInfo();
        //log.debug("Found Network: {s}", .{ MACF{ .bytes = bssid[0..] } });
        const ies = bss.INFORMATION_ELEMENTS orelse continue;
        const ssid = try alloc.dupe(u8, ies.SSID orelse "[HIDDEN NETWORK]");
        errdefer alloc.free(ssid);
        var new_network: Network = .{
            .if_index = result.IFINDEX,
            .last_seen = try zeit.instant(.{}),
            .bssid = bssid,
            .ssid = ssid,
            .security = sec_info.type,
            .auth = sec_info.auth,
            .freq = bss.FREQUENCY,
            .channel = @intCast(try nl._80211.channelFromFreq(bss.FREQUENCY)),
            .rssi = getRSSI: {
                const rssi_mbm = bss.SIGNAL_MBM orelse {
                    alloc.free(ssid);
                    continue;
                };
                break :getRSSI @divFloor(rssi_mbm, 100);
            },
            .beacon_interval = bss.BEACON_INTERVAL,
            .bss_tsf = bss.TSF,
        };
        valid_result = true;
        const _old_result = try network_ctx.scan_results.fetchPut(alloc, bssid, result);
        if (_old_result) |old| nl.parse.freeBytes(alloc, nl._80211.ScanResults, old.value);
        const _old_network = network_ctx.networks.getEntry(bssid);
        errdefer network_ctx.networks.mutex.unlock();
        if (_old_network) |old_nw_entry| {
            {
                const old_network = old_nw_entry.value_ptr;
                defer network_ctx.networks.mutex.unlock();
                new_network.rx_qual = calcRXQ: {
                    const prev_tsf = old_network.bss_tsf orelse break :calcRXQ null;
                    const cur_tsf = bss.TSF orelse break :calcRXQ null;
                    const b_interval = @as(u64, bss.BEACON_INTERVAL orelse break :calcRXQ null) * 1024;
                    const max_age = @divFloor(interval.*, time.ns_per_ms) * b_interval;
                    const age: u64 = @min(max_age, cur_tsf -| prev_tsf);
                    if (
                        old_network.if_index != new_network.if_index and
                        old_network.rssi > new_network.rssi and
                        @divFloor(age, time.us_per_s) < 1
                    ) {
                        //log.debug("Worse RSSI on Interface!", .{});
                        alloc.free(ssid);
                        continue :resLoop;
                    }
                    if (age == 0) {
                        new_network.last_seen = old_network.last_seen;
                        //log.debug("REPEAT NETWORK!", .{});
                        break :calcRXQ old_network.rx_qual;
                    }
                    const raw_qual = 100.0 * (1.0 - @as(f128, @floatFromInt(age)) / @as(f128, @floatFromInt(max_age)));
                    const bound_qual = @max(@min(raw_qual, 100), 0);
                    //log.debug("Raw Quality: {d}, Age: {d}, Interval: {d}, Max Age: {d}", .{ raw_qual, age, b_interval, max_age });
                    break :calcRXQ @intCast(@as(u8, @intFromFloat(bound_qual)));
                };
                old_network.deinit(alloc);
            }
            _ = network_ctx.networks.remove(old_nw_entry.key_ptr.*);
        }
        else network_ctx.networks.mutex.unlock();
        try network_ctx.networks.put(alloc, bssid, new_network);
        //log.debug("-------------\n{s}", .{ new_network });
    }
}
