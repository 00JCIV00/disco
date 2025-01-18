//! Core Functionality of DisCo

const std = @import("std");
const atomic = std.atomic;
const heap = std.heap;
const io = std.io;
const log = std.log.scoped(.core);
const mem = std.mem;
const meta = std.meta;
const posix = std.posix;
const time = std.time;

const netdata = @import("netdata.zig");
const nl = @import("netlink.zig");
const sys = @import("sys.zig");
const utils = @import("utils.zig");
const c = utils.toStruct;

pub const interfaces = @import("core/interfaces.zig");
pub const networks = @import("core/networks.zig");
pub const connections = @import("core/connections.zig");
pub const profiles = @import("core/profiles.zig");


/// Core Context of DisCo.
/// This should be used as a Singleton that is passed around for context.
pub const Core = struct {
    /// Config
    /// This is made to be configurable by users via JSON.
    pub const Config = struct {
        pub const ScanConfEntry = struct { 
            if_name: []const u8,
            conf: nl._80211.TriggerScanConfig,
        };

        pub const ConnectionEntry = struct { 
            ssid: []const u8,
            conf: connections.Config,
        };

        /// Conflicting Process Names
        conflict_proc_names: []const []const u8 = &.{
            "wpa_supplicant",
            "dhcpcd",
            "dhclient",
            "angryoxide",
            "kismet",
            "nmcli",
            "nmtui",
        },
        /// Use Profile Mask
        use_mask: bool = true,
        /// Available Interfaces
        available_ifs: ?[]const i32 = null,
        /// Available Interface Names
        avail_if_names: ?[]const []const u8 = null,
        /// Scan Configs
        scan_configs: ?[]const ScanConfEntry = null,
        /// Connection Configs
        connect_configs: ?[]const ConnectionEntry = null,
        /// Profile Mask
        profile_mask: profiles.Mask = profiles.Mask.google_pixel_6_pro,
    };

    /// Allocator
    _alloc: mem.Allocator,
    /// Arena Wrapper f/ Allocator
    _arena: heap.ArenaAllocator,
    /// Mutex Lock
    _mutex: std.Thread.Mutex = .{},
    /// Timer
    _timer: time.Timer,
    /// Thread Pool
    _thread_pool: std.Thread.Pool,
    /// Wait Group
    _wait_group: std.Thread.WaitGroup = .{},
    /// Config
    config: Config,
    /// Interval for Thread Checks in milliseconds.
    interval: usize = 100 * time.ns_per_ms,
    /// Active Status of the overall program.
    active: atomic.Value(bool) = atomic.Value(bool).init(false),
    /// Interface Context
    if_ctx: interfaces.Context,
    /// Network Context
    network_ctx: networks.Context,
    /// Connection Context
    conn_ctx: connections.Context,
    /// Original Hostname
    og_hostname: []const u8,
    /// Forced Close
    forced_close: bool = false,


    /// Initialize the Core Context.
    pub fn init(alloc: mem.Allocator, config: Config) !@This() {
        log.info("Initializing DisCo Core...", .{});
        try findConflictPIDs(
            alloc, 
            config.conflict_proc_names,
            null,
            "Found the '{s}' process running {d} time(s) (PID(s): {d}). This could cause issues w/ DisCo.",
        );
        var og_hn_buf: [posix.HOST_NAME_MAX]u8 = undefined;
        const og_hostname = try alloc.dupe(u8, try posix.gethostname(og_hn_buf[0..posix.HOST_NAME_MAX]));
        errdefer alloc.free(og_hostname);
        var arena = heap.ArenaAllocator.init(alloc);
        errdefer arena.deinit();
        const arena_alloc = arena.allocator();
        var if_ctx = try interfaces.Context.init(arena_alloc);
        errdefer if_ctx.deinit(alloc);
        var network_ctx = try networks.Context.init(arena_alloc);
        errdefer network_ctx.deinit(alloc);
        var conn_ctx = try connections.Context.init(arena_alloc);
        errdefer conn_ctx.deinit(alloc);
        var self: @This() = .{
            ._alloc = alloc,
            ._arena = arena,
            ._timer = try std.time.Timer.start(),
            ._thread_pool = .{ .threads = &[_]std.Thread{}, .allocator = alloc },
            .config = config,
            .if_ctx = if_ctx,
            .network_ctx = network_ctx,
            .conn_ctx = conn_ctx,
            .og_hostname = og_hostname,
        };
        if (config.use_mask) {
            try sys.setHostName(config.profile_mask.hostname);
            log.info("- Set Hostname to '{s}'.", .{ config.profile_mask.hostname });
        }
        try interfaces.updInterfaces(
            alloc,
            &self.if_ctx,
            &self.config,
            &self.interval,
        );
        if (config.available_ifs) |available_ifs| {
            for (available_ifs) |if_index| {
                const if_entry = self.if_ctx.interfaces.getEntry(if_index) orelse {
                    log.warn("- No Interface Entry for Index: {d}", .{ if_index });
                    continue;
                };
                defer self.if_ctx.interfaces.mutex.unlock();
                if (if_entry.value_ptr.state & c(nl.route.IFF).UP == c(nl.route.IFF).DOWN)
                    try nl.route.setState(if_index, c(nl.route.IFF).UP);
                if_entry.value_ptr.usage = .available;
            }
            alloc.free(available_ifs);
        }
        log.info("- Initialized Interface Tracking Data.", .{});
        if (config.scan_configs) |scan_conf_entries| {
            for (scan_conf_entries) |scan_conf_entry| {
                try self.network_ctx.scan_configs.put(
                    alloc,
                    try nl.route.getIfIdx(scan_conf_entry.if_name),
                    scan_conf_entry.conf,
                );
            }
        }
        log.info("- Initialized Network Tracking Data.", .{});
        if (config.connect_configs) |conn_conf_entries| {
            for (conn_conf_entries) |conn_conf_entry| {
                try self.conn_ctx.configs.put(
                    alloc,
                    conn_conf_entry.ssid,
                    conn_conf_entry.conf,
                );
            }
        }
        log.info("- Initialized Connection Tracking Data.", .{});
        log.info("Initialized DisCo Core.", .{});
        //time.sleep(3000 * time.ns_per_ms);
        return self;
    }

    /// Start the Core Context.
    pub fn start(self: *@This()) !void {
        log.info("Starting DisCo Core...", .{});
        self.active.store(true, .release);
        if (!self._mutex.tryLock()) return error.CoreAlreadyRunning;
        log.info("Core Locked!", .{});
        defer {
            log.info("Core Unlocked!", .{});
            self._mutex.unlock();
        }
        try self._thread_pool.init(.{ .allocator = self._alloc, .n_jobs = 3 });
        // Interface Tracking
        self._thread_pool.spawnWg(
            &self._wait_group,
            interfaces.trackInterfaces,
            .{
                self._alloc,
                &self.active,
                &self.interval,
                &self.if_ctx,
                &self.config,
            },
        );
        log.info("- Started Interface Tracking.", .{});
        // WiFi Network Scanning
        self._thread_pool.spawnWg(
            &self._wait_group,
            networks.trackScans,
            .{
                self._alloc,
                &self.active,
                &self.interval,
                self.if_ctx.interfaces,
                &self.network_ctx,
                &self.config,
            },
        );
        log.info("- Started WiFi Scan Tracking.", .{});
        self._thread_pool.spawnWg(
            &self._wait_group,
            networks.trackNetworks,
            .{
                self._alloc,
                &self.active,
                &self.interval,
                self.if_ctx.interfaces,
                &self.network_ctx,
            },
        );
        log.info("- Started WiFi Network Tracking.", .{});
        self._thread_pool.spawnWg(
            &self._wait_group,
            connections.trackConnections,
            .{
                self._alloc,
                &self.active,
                &self.interval,
                &self.conn_ctx,
                &self.if_ctx,
                &self.network_ctx,
            },
        );
        log.info("- Started Connection Tracking.", .{});
        log.info("Started DisCo Core.", .{});
        self._thread_pool.waitAndWork(&self._wait_group);
        self._thread_pool.deinit();
    }

    /// Stop the Core Context, (TODO) archive session data, and Clean Up as needed.
    pub fn stop(self: *@This()) void {
        log.info("Stopping DisCo Core...", .{});
        self.active.store(false, .seq_cst);
        self._mutex.lock();
        defer self._mutex.unlock();
        //self._thread_pool.waitAndWork(&self._wait_group);
        //self._thread_pool.deinit();
        log.info("- Stopped all Core Threads.", .{});
        // TODO Archive Session Data
        self.cleanUp();
        log.info("Stopped DisCo Core.", .{});
    }

    /// Clean Up.
    /// Note, we just let the OS clean up the Memory.
    /// (TODO) Improve this if it will be needed outise of closing DisCo.
    pub fn cleanUp(self: *@This()) void {
        log.info("Cleaning up DisCo Core...", .{});
        if (self.config.use_mask) {
            if (sys.setHostName(self.og_hostname)) 
                log.info("- Restored the Hostname to '{s}'.", .{ self.og_hostname })
            else |err|
                log.warn("- Couldn't reset the Hostname: {s}", .{ @errorName(err) });
            self.if_ctx.restore(self._alloc);
        }
        self._alloc.free(self.og_hostname);
        if (self.forced_close) {
            log.warn("- Forced close. Leaving memory clean up to the OS.", .{});
            return;
        }
        self.if_ctx.deinit(self._alloc);
        log.info("- Deinitialized Interface Tracking.", .{});
        self.network_ctx.deinit(self._alloc);
        if (self.config.scan_configs) |scan_conf| self._alloc.free(scan_conf);
        log.info("- Deinitialized Network Tracking.", .{});
        self.conn_ctx.deinit(self._alloc);
        log.info("- Deinitialized Connection Tracking.", .{});
        self._arena.deinit();
        log.info("- Deinitialized All Contexts.", .{});
        log.info("Cleaned up DisCo Core.", .{});
    }

    /// Print System & Interface Info
    pub fn printInfo(self: *@This(), writer: anytype) !void {
        var hn_buf: [posix.HOST_NAME_MAX]u8 = undefined;
        try writer.print(
            \\DisCo Info:
            \\-----------
            \\Hostname: {s}
            \\-----------
            \\
            , .{ try posix.gethostname(hn_buf[0..]) }
        );
        var if_iter = self.if_ctx.interfaces.iterator();
        defer if_iter.unlock();
        while (if_iter.next()) |print_if| {
            try writer.print(
                \\Interface Details:
                \\{s}
                \\
                , .{ print_if.value_ptr }
            );
        }
    }
};

/// Find Conflicting PIDs
pub fn findConflictPIDs(
    alloc: mem.Allocator, 
    proc_names: []const []const u8,
    writer: ?io.AnyWriter,
    comptime fmt: []const u8,
) !void {
    for (proc_names) |p_name| {
        const pids = try sys.getPIDs(alloc, &.{ p_name });
        defer alloc.free(pids);
        if (pids.len > 0) {
            if (writer) |w| {
                try w.print(fmt, .{ p_name, pids.len, pids });
                continue;
            }
            log.warn(fmt, .{ p_name, pids.len, pids });
        }
    }
}

/// Thread Safe ArrayList
pub fn ThreadArrayList(T: type) type {
    return struct {
        /// List Type
        pub const ListT: type = std.ArrayListUnmanaged(T);

        /// Mutex Lock
        _mutex: std.Thread.Mutex = .{},
        /// ArrayList
        _list: ListT,

        /// List Items
        pub fn items(self: *@This()) []T {
            return self._list.items;
        }

        /// Initialize
        pub fn initCapacity(self: *@This(), alloc: mem.Allocator, num: usize) mem.Allocator.Error!ListT {
            self._mutex.lock();
            defer self._mutex.unlock();
            self._list = try ListT.initCapacity(alloc, num);
        }

        /// Deinitialize
        pub fn deinit(self: *@This(), alloc: mem.Allocator) void {
            self._mutex.lock();
            defer self._mutex.unlock();
            self._list.deinit(alloc);
        }

        /// Append
        pub fn append(self: *@This(), alloc: mem.Allocator, item: T) mem.Allocator.Error!void {
            self._mutex.lock();
            defer self._mutex.unlock();
            try self._list.append(alloc, item);
        }

        /// Append Slice
        pub fn appendSlice(self: *@This(), alloc: mem.Allocator, slice: []const T) mem.Allocator.Error!void {
            self._mutex.lock();
            defer self._mutex.unlock();
            try self._list.appendSlice(alloc, slice);
        }
    };
}

/// Thread Safe HashMap
pub fn ThreadHashMap(K: type, V: type) type {
    return struct {
        /// Map Type
        pub const MapT: type =
            if (K == []const u8) std.StringHashMapUnmanaged(V)
            else std.AutoHashMapUnmanaged(K, V);
        /// Iterator
        pub const Iterator: type = struct {
            _mutex: *std.Thread.Mutex,
            _iter: MapT.Iterator,

            pub fn next(self: *@This()) ?MapT.Entry {
                return self._iter.next();
            }
            pub fn index(self: *@This()) u32 {
                return self._iter.index;
            }
            pub fn unlock(self: *@This()) void {
                self._mutex.unlock();
            }
        };

        /// Mutex Lock
        mutex: std.Thread.Mutex = .{},
        /// Hash Map
        map: MapT = .{},

        /// Deinitialize this ThreadHashMap
        pub fn deinit(self: *@This(), alloc: mem.Allocator) void {
            self.mutex.lock();
            defer self.mutex.unlock();
            self.map.deinit(alloc);
        }

        ///// Keys (This is an allocated copy)
        //pub fn keys(self: *@This(), alloc: mem.Allocator) ![]K {
        //    self.mutex.lock();
        //    defer self.mutex.unlock();
        //    try alloc.dupe(K, self._map.keys());
        //}

        ///// Values (This is an allocated copy)
        //pub fn values(self: *@This(), alloc: mem.Allocator) ![]K {
        //    self.mutex.lock();
        //    defer self.mutex.unlock();
        //    try alloc.dupe(V, self._map.values());
        //}

        /// Count
        pub fn count(self: *@This()) usize {
            self.mutex.lock();
            defer self.mutex.unlock();
            return self.map.count();
        }

        /// Iterator
        /// Must unlock with `iterator.unlock()` to edit the Map again.
        pub fn iterator(self: *@This()) Iterator {
            self.mutex.lock();
            return .{
                ._mutex = &self.mutex,
                ._iter = self.map.iterator(),
            };
        }

        /// Get
        pub fn get(self: *@This(), key: K) ?V {
            self.mutex.lock();
            defer self.mutex.unlock();
            return self.map.get(key);
        }

        /// Get Entry
        /// Must unlock map with `map.mutex.unlock()` when done with the Entry.
        pub fn getEntry(self: *@This(), key: K) ?MapT.Entry {
            self.mutex.lock();
            return self.map.getEntry(key);
        }

        /// Put
        pub fn put(
            self: *@This(), 
            alloc: mem.Allocator, 
            key: K, 
            val: V,
        ) !void {
            self.mutex.lock();
            defer self.mutex.unlock();
            try self.map.put(alloc, key, val);
        }

        /// Fetch Put
        pub fn fetchPut(
            self: *@This(),
            alloc: mem.Allocator,
            key: K,
            val: V,
        ) !?MapT.KV {
            self.mutex.lock();
            defer self.mutex.unlock();
            return try self.map.fetchPut(alloc, key, val);
        }

        /// Remove
        pub fn remove(self: *@This(), key: K) bool {
            self.mutex.lock();
            defer self.mutex.unlock();
            return self.map.remove(key);
        }

        /// Sort
        pub fn sort(self: *@This(), sort_ctx: anytype) void {
            self.mutex.lock();
            defer self.mutex.unlock();
            try self.map.sort(sort_ctx);
        }
    };
}

/// Reset a Map containing Netlink Data
pub fn resetNLMap(
    alloc: mem.Allocator,
    K: type,
    V: type,
    map: *ThreadHashMap(K, V),
) void {
    // Clean
    var map_iter = map.iterator();
    var rm_idxs: [16_000]?K = .{ null } ** 16_000;
    var rm_count: u16 = 0;
    while (map_iter.next()) |val| {
        nl.parse.freeBytes(alloc, V, val.value_ptr.*);
        rm_idxs[rm_count] = val.key_ptr.*;
        rm_count +|= 1;
    }
    map_iter.unlock();
    for (rm_idxs[0..rm_count]) |_idx| {
        const idx = _idx orelse break;
        _ = map.remove(idx);
    }
}
