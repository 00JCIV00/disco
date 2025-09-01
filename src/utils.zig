//! Utility functions for DisCo

const std = @import("std");
const atomic = std.atomic;
const enums = std.enums;
const fifo = std.fifo;
const fmt = std.fmt;
const io = std.io;
const math = std.math;
const mem = std.mem;
const meta = std.meta;

const ArrayList = std.ArrayListUnmanaged;


/// Create an instance of a Struct Type with Integer Fields from the given Enum (`E`).
pub fn toStruct(E: type) T: {
    @setEvalBranchQuota(100_000);
    break :T enums.EnumFieldStruct(E, @typeInfo(E).@"enum".tag_type, null);
} {
    @setEvalBranchQuota(100_000);
    var _struct: enums.EnumFieldStruct(E, @typeInfo(E).@"enum".tag_type, null) = undefined;
    inline for (meta.fields(@TypeOf(_struct))) |field|
        @field(_struct, field.name) = @intFromEnum(@field(E, field.name));
    return _struct;
}

/// Format the provided `bytes` as readable Hexadecimal.
pub const HexFormatter = struct {
    bytes: []const u8,

    pub fn format(
        self: @This(),
        _: []const u8,
        _: fmt.FormatOptions,
        writer: anytype,
    ) !void {
        var fmt_idx: u16 = 0;
        for (self.bytes[0..], 0..) |byte, idx| {
            if (idx % 16 == 0) {
                _ = try writer.print("\n", .{});
                fmt_idx += 1;
            }
            if (idx % 8 == 0) {
                _ = try writer.print("| ", .{});
                fmt_idx += 2;
            }
            _ = try writer.print("{X:0>2} ", .{ byte });
            fmt_idx += 3;
        }
    }
};

/// Thread Safe First In, First Out (FIFO) Buffer
/// Useful for Single-Producer, Single-Consumer (SPSC) data passing.
pub fn ThreadFifo(T: type, inner_buffer_kind: fifo.LinearFifoBufferType) type {
    return struct {
        /// Type of Items stored in this FIFO Buffer.
        /// Note, this is provided for external reference. The Buffer itself uses `T`.
        pub const ItemT: type = T;
        /// Underlying FIFO Buffer Type
        const BufferT: type = fifo.LinearFifo(T, inner_buffer_kind);
        /// Buffer Kind for inner FIFO Buffer
        pub const ThreadFifoBufferKind = union(enum) {
            static,
            slice: []const u8,
            dynamic: mem.Allocator,
        };

        /// Write Index
        _write_idx: atomic.Value(usize) = .init(0),
        /// Read Index
        _read_idx: atomic.Value(usize) = .init(0),
        /// The FIFO Buffer
        _buf: BufferT,

        /// Increment the Write or Read Index
        fn increment(idx: *atomic.Value(usize)) void {
            if (idx.load(.acquire) == math.maxInt(usize) - 1) idx.store(0, .release)
            else _ = idx.fetchAdd(1, .release);
        }

        /// Check if the FIFO Buffer is Empty.
        pub fn isEmpty(self: *const @This()) bool {
            return self._read_idx.load(.acquire) == self._write_idx.load(.acquire);
        }

        /// Initialize the FIFO Buffer
        pub fn init(buffer_kind: ThreadFifoBufferKind) @This() {
            return .{
                ._buf = switch (buffer_kind) {
                    .static => .init(),
                    .slice => |slice| .init(slice),
                    .dynamic => |alloc| .init(alloc),
                },
            };
        }

        /// Deinitialize the FIFO Buffer
        pub fn deinit(self: *@This(), alloc: mem.Allocator) void {
            self._buf.deinit(alloc);
        }

        /// Write to the FIFO Buffer.
        pub fn write(self: *@This(), item: T) mem.Allocator.Error!void {
            try self._buf.writeItem(item);
            increment(&self._write_idx);
        }

        /// Read & Consume from the FIFO Buffer.
        pub fn read(self: *@This()) ?T {
            if (self.isEmpty()) return null;
            const item: T = self._buf.readItem() orelse return null;
            defer increment(&self._read_idx);
            return item;
        }
    };
}

/// Thread Safe ArrayList
pub fn ThreadArrayList(T: type) type {
    return struct {
        /// List Type
        pub const ListT: type = ArrayList(T);
        /// Empty Thread Safe ArrayList
        pub const empty: @This() = .{};

        /// Mutex Lock
        mutex: std.Thread.Mutex = .{},
        /// ArrayList
        list: ListT = .empty,

        /// List Items
        /// Caller must unlock when finished with `list.mutex.unlock()`.
        pub fn items(self: *@This()) []T {
            self.mutex.lock();
            return self.list.items;
        }

        /// Initialize
        pub fn initCapacity(self: *@This(), alloc: mem.Allocator, num: usize) mem.Allocator.Error!ListT {
            self.mutex.lock();
            defer self.mutex.unlock();
            self.list = try ListT.initCapacity(alloc, num);
        }

        /// Deinitialize
        pub fn deinit(self: *@This(), alloc: mem.Allocator) void {
            self.mutex.lock();
            defer self.mutex.unlock();
            self.list.deinit(alloc);
        }

        /// Append
        pub fn append(self: *@This(), alloc: mem.Allocator, item: T) mem.Allocator.Error!void {
            self.mutex.lock();
            defer self.mutex.unlock();
            try self.list.append(alloc, item);
        }

        /// Append Slice
        pub fn appendSlice(self: *@This(), alloc: mem.Allocator, slice: []const T) mem.Allocator.Error!void {
            self.mutex.lock();
            defer self.mutex.unlock();
            try self.list.appendSlice(alloc, slice);
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

        /// Empty Thread Safe HashMap
        pub const empty: @This() = .{};

        /// Mutex Lock
        mutex: std.Thread.Mutex = .{},
        /// Hash Map
        map: MapT = .empty,

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
    };
}

