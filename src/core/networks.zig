//! Network Tracking

const std = @import("std");
const atomic = std.atomic;
const fmt = std.fmt;
const linux = std.os.linux;
const log = std.log.scoped(.networks);
const math = std.math;
const mem = std.mem;
const meta = std.meta;
const posix = std.posix;
const time = std.time;

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


/// Network Info
pub const Network = struct {
    // Meta
    if_index: i32,
    last_seen: zeit.Instant,
    // Details
    bssid: [6]u8,
    ssid: []const u8,
    security: nl._80211.SecurityType,
    auth: nl._80211.AuthType,
    channel: u32,
    freq: u32,
    rssi: i32,
    beacon_interval: ?u16 = null,
    bss_tsf: ?u64 = null,
    rx_qual: ?usize = null,

    pub fn format(
        self: @This(),
        _: []const u8,
        _: fmt.FormatOptions,
        writer: anytype,
    ) !void {
        var last_ts_buf: [50]u8 = .{ 0 } ** 50;
        const last_ts = try self.last_seen.time().bufPrint(last_ts_buf[0..], .rfc3339);
        try writer.print(
            \\{s}
            \\- BSSID:     {s} ({s})
            \\- Security:  {s}
            \\- Auth:      {s}
            \\- Channel:   {d} ({d} MHz)
            \\- RSSI:      {d} dBm
            \\- Rx Qual:   {d}
            \\- Last Seen: {s}
            \\- Seen By:   {d}
            \\
            , .{
                self.ssid,
                MACF{ .bytes = self.bssid[0..] }, try netdata.oui.findOUI(.short, self.bssid),
                @tagName(self.security),
                @tagName(self.auth),
                self.channel, self.freq,
                self.rssi,
                self.rx_qual orelse 0,
                last_ts,
                self.if_index
            },
        );
    }

    pub fn deinit(self: *const @This(), alloc: mem.Allocator) void {
        alloc.free(self.ssid);
    }
};

/// Network Context 
pub const Context = struct {
    scan_configs: *core.ThreadHashMap(i32, nl._80211.TriggerScanConfig),
    networks: *core.ThreadHashMap([6]u8, Network),
    scan_results: *core.ThreadHashMap([6]u8, nl._80211.ScanResults),
    scan_pool: *std.Thread.Pool,
    scan_group: *std.Thread.WaitGroup,


    /// Initialize all Maps.
    pub fn init(alloc: mem.Allocator) !@This() {
        var self: @This() = undefined;
        inline for (meta.fields(@This())) |field| {
            switch (field.type) {
                inline else => |f_ptr_type| {
                    const f_type = @typeInfo(f_ptr_type).Pointer.child;
                    const ctx_field = try alloc.create(f_type);
                    ctx_field.* = switch (f_type) {
                        std.Thread.Pool => .{ .threads = &[_]std.Thread{}, .allocator = alloc },
                        inline else => .{},
                    };
                    @field(self, field.name) = ctx_field;
                }
            }
        }
        return self;
    }

    /// Deinitialize all Maps.
    pub fn deinit(self: *@This(), alloc: mem.Allocator) void {
        self.scan_configs.deinit(alloc);
        var nw_iter = self.networks.iterator();
        while (nw_iter.next()) |nw_entry| nw_entry.value_ptr.deinit(alloc);
        nw_iter.unlock();
        self.networks.deinit(alloc);
        core.resetNLMap(
            alloc,
            [6]u8,
            nl._80211.ScanResults,
            self.scan_results,
        );
        self.scan_results.deinit(alloc);
    }
};

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
        //.available,
        //.scanning => triggerScan: {
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
                error.BUSY,
                error.NODEV => {},
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
    interfaces: *core.ThreadHashMap(i32, core.interfaces.Interface),
    network_ctx: *Context,
    config: *core.Core.Config,
) void {
    log.debug("Tracking WiFi Scans!", .{});
    var err_count: usize = 0;
    while (active.load(.acquire)) {
        defer {
            if (err_count > 10) @panic("WiFi Scan Tracking encountered too many errors to continue.");
            time.sleep(interval.*);
        }
        if (config.scan_configs) |scan_conf_entries| {
            for (scan_conf_entries) |scan_conf_entry| {
                const if_index = nl.route.getIfIdx(scan_conf_entry.if_name) catch continue;
                if (network_ctx.scan_configs.get(if_index)) |_| continue;
                network_ctx.scan_configs.put(
                    alloc,
                    if_index,
                    scan_conf_entry.conf,
                ) catch |err| {
                    log.err("Could not add Scan Config for '{s}': {s}", .{ scan_conf_entry.if_name, @errorName(err) });
                    err_count += 1;
                    continue;
                };
                log.debug("Updated Interface Index f/ Scan Config: {s} ({d})", .{ scan_conf_entry.if_name, if_index });
            }
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
    interfaces: *core.ThreadHashMap(i32, core.interfaces.Interface),
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
    interfaces: *core.ThreadHashMap(i32, core.interfaces.Interface),
    network_ctx: *Context,
) void {
    log.debug("Tracking WiFi Networks!", .{});
    var err_count: usize = 0;
    while (active.load(.acquire)) {
        defer {
            if (err_count >= 10) @panic("WiFi Network Tracking encountered too many errors to continue");
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
        network_ctx.scan_pool.init(.{ .allocator = alloc, .n_jobs = job_count }) catch |err| {
            log.err("WiFi Network Tracking Error: {s}", .{ @errorName(err) });
            err_count += 1;
            continue;
        };
        defer {
            network_ctx.scan_pool.waitAndWork(network_ctx.scan_group);
            network_ctx.scan_pool.deinit();
            network_ctx.scan_group.reset();
        }
        if_iter = interfaces.iterator();
        defer if_iter.unlock();
        while (if_iter.next()) |if_entry| {
            const scan_if = if_entry.value_ptr;
            if (scan_if.usage != .scanning) continue;
            network_ctx.scan_pool.spawnWg(
                network_ctx.scan_group,
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
    interfaces: *core.ThreadHashMap(i32, core.interfaces.Interface),
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
    interfaces: *core.ThreadHashMap(i32, core.interfaces.Interface),
    if_index: i32,
    interval: *const usize,
    network_ctx: *Context,
) !void {
    const scan_if = interfaces.get(if_index) orelse return error.InterfaceNotFound;
    if (scan_if.usage != .scanning) return;
    var set_if = (interfaces.getEntry(if_index) orelse return error.InterfaceNotFound).value_ptr;
    defer set_if.usage = .available;
    interfaces.mutex.unlock();
    try nl._80211.getScan(alloc, scan_if.index, scan_if.nl_sock);
    const scan_results = nl._80211.handleScanResults(alloc, scan_if.nl_sock) catch |err| {
        log.warn("Could not parse Scan Results: {s}", .{ @errorName(err) });
        return err;
    };
    defer alloc.free(scan_results);
    var result_idx: usize = 0;
    errdefer {
        for (scan_results, 0..) |result, idx| {
            if (idx < result_idx) continue;
            nl.parse.freeBytes(alloc, nl._80211.ScanResults, result);
        }
    }
    if (scan_results.len == 0) return;
    //log.debug("Parsing {d} Scan Results...", .{ scan_results.len });
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
        log.debug("-------------\n{s}", .{ new_network });
    }
}
