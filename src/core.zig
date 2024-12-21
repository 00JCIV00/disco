//! Core Functionality of DisCo

const std = @import("std");
const log = std.log;
const mem = std.mem;
const meta = std.meta;
const time = std.time;

const netdata = @import("netdata.zig");
const nl = @import("nl.zig");

pub const interface = @import("core/interface.zig");


/// Core Context of DisCo.
/// This should be used as a Singleton that is passed around for context.
pub const Core = struct {
    /// Allocator
    _alloc: mem.Allocator,
    /// Mutex Lock
    _mutex: std.Thread.Mutex = .{},
    /// Timer
    _timer: time.Timer,
    /// Interval
    interval: usize = 2500 * time.ns_per_ms,
    /// Active Status of the overall program.
    active: bool = false,
    /// Interface Maps
    if_maps: interface.InterfaceMaps,
    /// Interface Thread
    if_thread: ?std.Thread = null,


    /// Initialize the Core Context.
    pub fn init(alloc: mem.Allocator) !@This() {
        log.info("Initializing DisCo Core...", .{});
        const if_maps = ifMaps: {
            var if_maps: interface.InterfaceMaps = undefined;
            inline for (meta.fields(interface.InterfaceMaps)) |field| {
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
        var self: @This() = .{
            ._alloc = alloc,
            ._timer = try std.time.Timer.start(),
            .if_maps = if_maps,
        };
        try interface.updInterfaces(
            alloc,
            &self.if_maps,
        );
        log.info("Initialized DisCo Core.", .{});
        return self;
    }

    /// Start the Core Context.
    pub fn start(self: *@This()) !void {
        log.info("Starting DisCo Core...", .{});
        self.active = true;
        if (!self._mutex.tryLock()) return error.CoreAlreadyRunning;
        self.if_thread = try std.Thread.spawn(
            .{},
            interface.trackInterfaces,
            .{
                self._alloc,
                &self.active,
                &self.interval,
                &self.if_maps,
            }
        );
        self.if_thread.?.detach();
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
        self.if_maps.interfaces.deinit(self._alloc);
        self.if_maps.links.deinit(self._alloc);
        self.if_maps.addresses.deinit(self._alloc);
        if (self.if_thread) |ift| ift.join();
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
        _mutex: std.Thread.Mutex = .{},
        /// Hash Map
        _map: MapT = .{},

        /// Deinitialize this ThreadHashMap
        pub fn deinit(self: *@This(), alloc: mem.Allocator) void {
            self._mutex.lock();
            defer self._mutex.unlock();
            self._map.deinit(alloc);
        }

        /// Keys (This is an allocated copy)
        pub fn keys(self: *@This(), alloc: mem.Allocator) ![]K {
            self._mutex.lock();
            defer self._mutex.unlock();
            try alloc.dupe(K, self._map.keys());
        }

        /// Values (This is an allocated copy)
        pub fn values(self: *@This(), alloc: mem.Allocator) ![]K {
            self._mutex.lock();
            defer self._mutex.unlock();
            try alloc.dupe(V, self._map.values());
        }

        /// Count
        pub fn count(self: *@This()) usize {
            self._mutex.lock();
            defer self._mutex.unlock();
            return self._map.count();
        }

        /// Iterator
        /// Must unlock with `iterator.unlock()` to edit the Map again.
        pub fn iterator(self: *@This()) Iterator {
            self._mutex.lock();
            return .{
                ._mutex = &self._mutex,
                ._iter = self._map.iterator(),
            };
        }

        /// Get
        pub fn get(self: *@This(), key: K) ?V {
            self._mutex.lock();
            defer self._mutex.unlock();
            return self._map.get(key);
        }

        /// Put
        pub fn put(
            self: *@This(), 
            alloc: mem.Allocator, 
            key: K, 
            val: V,
        ) !void {
            self._mutex.lock();
            defer self._mutex.unlock();
            try self._map.put(alloc, key, val);
        }

        /// Fetch Put
        pub fn fetchPut(
            self: *@This(),
            alloc: mem.Allocator,
            key: K,
            val: V,
        ) !?MapT.KV {
            self._mutex.lock();
            defer self._mutex.unlock();
            return try self._map.fetchPut(alloc, key, val);
        }

        /// Remove
        pub fn remove(
            self: *@This(),
            key: K,
        ) bool {
            self._mutex.lock();
            defer self._mutex.unlock();
            return self._map.remove(key);
        }

        /// Sort
        pub fn sort(self: *@This(), sort_ctx: anytype) void {
            self._mutex.lock();
            defer self._mutex.unlock();
            try self._map.sort(sort_ctx);
        }
    };
}
