//! Core Functionality of DisCo

const std = @import("std");
const log = std.log;
const mem = std.mem;
const meta = std.meta;
const time = std.time;

const netdata = @import("netdata.zig");
const nl = @import("netlink.zig");

pub const interfaces = @import("core/interfaces.zig");
pub const networks = @import("core/networks.zig");
const utils = @import("utils.zig");
const c = utils.toStruct;


/// Core Initialization Config
pub const InitConfig = struct {
    pub const ScanConfEntry = struct { 
        if_index: i32,
        conf: nl._80211.TriggerScanConfig,
    };

    /// Available Interfaces
    available_ifs: ?[]const i32 = null,
    /// Scan Configs
    scan_configs: ?[]const ScanConfEntry = null,
};

/// Core Context of DisCo.
/// This should be used as a Singleton that is passed around for context.
pub const Core = struct {
    /// Allocator
    _alloc: mem.Allocator,
    /// Mutex Lock
    _mutex: std.Thread.Mutex = .{},
    /// Timer
    _timer: time.Timer,
    /// Interval for Thread Checks in milliseconds.
    interval: usize = 500 * time.ns_per_ms,
    /// Active Status of the overall program.
    active: bool = false,
    /// Interface Maps
    if_maps: interfaces.InterfaceMaps,
    /// Interface Thread
    if_thread: ?std.Thread = null,
    /// Network Maps
    network_maps: networks.NetworkMaps,
    /// Scan Config Thread
    scan_conf_thread: ?std.Thread = null,
    /// Network Thread
    network_thread: ?std.Thread = null,


    /// Initialize the Core Context.
    pub fn init(alloc: mem.Allocator, config: InitConfig) !@This() {
        log.info("Initializing DisCo Core...", .{});
        const if_maps = ifMaps: {
            var if_maps: interfaces.InterfaceMaps = undefined;
            inline for (meta.fields(interfaces.InterfaceMaps)) |field| {
                switch (field.type) {
                    inline else => |f_ptr_type| {
                        const f_type = @typeInfo(f_ptr_type).Pointer.child;
                        const list = try alloc.create(f_type);
                        list.* = f_type{};
                        @field(if_maps, field.name) = list;
                    }
                }
            }
            break :ifMaps if_maps;
        };
        const network_maps = nwMaps: {
            var network_maps: networks.NetworkMaps = undefined;
            inline for (meta.fields(networks.NetworkMaps)) |field| {
                switch (field.type) {
                    inline else => |f_ptr_type| {
                        const f_type = @typeInfo(f_ptr_type).Pointer.child;
                        const list = try alloc.create(f_type);
                        list.* = f_type{};
                        @field(network_maps, field.name) = list;
                    }
                }
            }
            break :nwMaps network_maps;
        };
        var self: @This() = .{
            ._alloc = alloc,
            ._timer = try std.time.Timer.start(),
            .if_maps = if_maps,
            .network_maps = network_maps,
        };
        try interfaces.updInterfaces(
            alloc,
            &self.if_maps,
        );
        if (config.available_ifs) |available_ifs| {
            for (available_ifs) |if_index| {
                const if_entry = self.if_maps.interfaces.getEntry(if_index) orelse {
                    log.warn("No Interface Entry for Index: {d}", .{ if_index });
                    continue;
                };
                if (if_entry.value_ptr.state & c(nl.route.IFF).UP == c(nl.route.IFF).DOWN)
                    try nl.route.setState(if_index, c(nl.route.IFF).UP);
                defer self.if_maps.interfaces.mutex.unlock();
                if_entry.value_ptr.usage = .available;
                log.info("- Interface '{s}' available.", .{ if_entry.value_ptr.name });
            }
            alloc.free(available_ifs);
        }
        log.info("- Initialized Interface Tracking Data.", .{});
        if (config.scan_configs) |scan_conf_entries| {
            for (scan_conf_entries) |scan_conf_entry| {
                try self.network_maps.scan_configs.put(
                    alloc,
                    scan_conf_entry.if_index,
                    scan_conf_entry.conf,
                );
            }
            alloc.free(scan_conf_entries);
        }
        log.info("- Initialized Network Tracking Data.", .{});
        log.info("Initialized DisCo Core.", .{});
        return self;
    }

    /// Start the Core Context.
    pub fn start(self: *@This()) !void {
        log.info("Starting DisCo Core...", .{});
        self.active = true;
        if (!self._mutex.tryLock()) return error.CoreAlreadyRunning;
        // Interface Tracking
        self.if_thread = try std.Thread.spawn(
            .{},
            interfaces.trackInterfaces,
            .{
                self._alloc,
                &self.active,
                &self.interval,
                &self.if_maps,
            }
        );
        self.if_thread.?.detach();
        // WiFi Network Scanning
        self.scan_conf_thread = try std.Thread.spawn(
            .{},
            networks.trackScans,
            .{
                self._alloc,
                &self.active,
                &self.interval,
                self.if_maps.interfaces,
                &self.network_maps,
            }
        );
        self.network_thread = try std.Thread.spawn(
            .{},
            networks.trackNetworks,
            .{
                self._alloc,
                &self.active,
                &self.interval,
                self.if_maps.interfaces,
                &self.network_maps,
            }
        );
        log.info("Started DisCo Core.", .{});
    }

    /// Stop the Core Context, Clean Up as needed, and (TODO) archive session data.
    pub fn stop(self: *@This()) void {
        log.info("Stopping DisCo Core...", .{});
        self.active = false;
        self.cleanUp();
        // TODO Archive Session Data
        log.info("Stopped DisCo Core.", .{});
    }

    /// Clean Up
    pub fn cleanUp(self: *@This()) void {
        log.info("Cleaning up DisCo Core...", .{});
        self.if_maps.deinit(self._alloc);
        if (self.if_thread) |ift| ift.join();
        log.info("- Deinitialized & Stopped Interface Tracking.", .{});
        self.network_maps.deinit(self._alloc);
        if (self.scan_conf_thread) |sct| sct.join();
        if (self.network_thread) |nwt| nwt.join();
        log.info("- Deinitialized & Stopped Network Tracking.", .{});
        log.info("Cleaned up DisCo Core.", .{});
    }
};

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
        pub const MapT: type = std.AutoHashMapUnmanaged(K, V);
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
        _map: MapT = .{},

        /// Deinitialize this ThreadHashMap
        pub fn deinit(self: *@This(), alloc: mem.Allocator) void {
            self.mutex.lock();
            defer self.mutex.unlock();
            self._map.deinit(alloc);
        }

        /// Keys (This is an allocated copy)
        pub fn keys(self: *@This(), alloc: mem.Allocator) ![]K {
            self.mutex.lock();
            defer self.mutex.unlock();
            try alloc.dupe(K, self._map.keys());
        }

        /// Values (This is an allocated copy)
        pub fn values(self: *@This(), alloc: mem.Allocator) ![]K {
            self.mutex.lock();
            defer self.mutex.unlock();
            try alloc.dupe(V, self._map.values());
        }

        /// Count
        pub fn count(self: *@This()) usize {
            self.mutex.lock();
            defer self.mutex.unlock();
            return self._map.count();
        }

        /// Iterator
        /// Must unlock with `iterator.unlock()` to edit the Map again.
        pub fn iterator(self: *@This()) Iterator {
            self.mutex.lock();
            return .{
                ._mutex = &self.mutex,
                ._iter = self._map.iterator(),
            };
        }

        /// Get
        pub fn get(self: *@This(), key: K) ?V {
            self.mutex.lock();
            defer self.mutex.unlock();
            return self._map.get(key);
        }

        /// Get Entry
        /// Must unlock map with `map.mutex.unlock()` when done with the Entry.
        pub fn getEntry(self: *@This(), key: K) ?MapT.Entry {
            self.mutex.lock();
            return self._map.getEntry(key);
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
            try self._map.put(alloc, key, val);
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
            return try self._map.fetchPut(alloc, key, val);
        }

        /// Remove
        pub fn remove(
            self: *@This(),
            key: K,
        ) bool {
            self.mutex.lock();
            defer self.mutex.unlock();
            return self._map.remove(key);
        }

        /// Sort
        pub fn sort(self: *@This(), sort_ctx: anytype) void {
            self.mutex.lock();
            defer self.mutex.unlock();
            try self._map.sort(sort_ctx);
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
