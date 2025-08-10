//! Parsing Functions for Netlink Data
const std = @import("std");
const enums = std.enums;
const fmt = std.fmt;
const heap = std.heap;
const io = std.io;
const log = std.log.scoped(.netlink);
const math = std.math;
const mem = std.mem;
const meta = std.meta;
const ArrayList = std.ArrayListUnmanaged;

const nl = @import("../netlink.zig");
const utils = @import("../utils.zig");
const HexF = utils.HexFormatter;

/// Get an Instance of a Primitive Type (`T`) from the given `bytes`.
pub fn primFromBytes(T: type, bytes: []const u8) !T {
    if (T == []const u8) return bytes;
    return switch (@typeInfo(T)) {
        .array => |ary| bytes[0..ary.len].*,
        .optional => |optl| try primFromBytes(bytes, optl.child),
        .int, .float => @as(*const align(1) T, @alignCast(@ptrCast(bytes))).*,
        .bool => if (bytes.len == 0) true else @as(*const align(1) T, @alignCast(@ptrCast(bytes))).*,
        else => error.NonPrimitiveType,
    };
}

/// Get an Instance of a Pointer Type (`T`) from the given `bytes`.
/// Note, Slices also return a single instance of the underlying Child Type. This is meant to be used w/ `setPtrFromBytes()`.
pub fn ptrFromBytes(alloc: mem.Allocator, T: type, bytes: []const u8) !T {
    if (T == []const u8) return try alloc.dupe(u8, bytes);
    const raw_info = @typeInfo(T);
    if (raw_info != .pointer) return error.NotAPointer;
    const info = raw_info.pointer;
    switch (info.size) {
        .one => {
            const new = try alloc.create(info.child);
            errdefer alloc.destroy(new);
            new.* = switch (@typeInfo(info.child)) {
                .pointer => try ptrFromBytes(alloc, info.child, bytes),
                .optional => try optFromBytes(alloc, info.child, bytes),
                .@"struct" => try fromBytes(alloc, info.child, bytes),
                else => try primFromBytes(info.child, bytes),
            };
            return new;
        },
        .slice => {
            const child_info = @typeInfo(info.child);
            if (grouped: {
                if (child_info != .@"struct") break :grouped false;
                for (child_info.@"struct".decls) |decl| {
                    if (mem.eql(u8, decl.name, "_grouped_attr")) break :grouped true;
                }
                break :grouped false;
            }) {
                //log.debug("*****Handling grouped slice!", .{});
                const HdrT: type = inline for (child_info.@"struct".decls) |decl| {
                    comptime if (mem.eql(u8, decl.name, "AttrHdrT")) break @field(info.child, "AttrHdrT");
                } else nl.AttributeHeader;
                const hdr_len = @sizeOf(HdrT);
                var group_buf: ArrayList(info.child) = .empty;
                errdefer group_buf.deinit(alloc);
                var start: usize = 0;
                var end: usize = 0;
                //log.debug("*******Total Len: {d}B", .{ bytes.len });
                while (end < bytes.len) {
                    start = end;
                    end += hdr_len;
                    const hdr: *const HdrT = @alignCast(@ptrCast(bytes[start..end]));
                    //log.debug("**********Attr: {d}B, Idx: {d}, Start: {d}B", .{ hdr.len, hdr.type, start });
                    start = end;
                    end += hdr.len -| hdr_len;
                    const item = try ptrFromBytes(alloc, *info.child, bytes[start..end]);
                    defer alloc.destroy(item);
                    try group_buf.append(alloc, item.*);
                    end = mem.alignForward(usize, end, 4);
                }
                return try group_buf.toOwnedSlice(alloc);
            }
            const new = try alloc.alloc(info.child, 1);
            errdefer alloc.free(new);
            new[0] = switch (@typeInfo(info.child)) {
                .pointer => try ptrFromBytes(alloc, info.child, bytes),
                .optional => try optFromBytes(alloc, info.child, bytes),
                .@"struct" => try fromBytes(alloc, info.child, bytes),
                else => try primFromBytes(info.child, bytes),
            };
            return new;
        },
        else => {
            log.err("Unsupported Type: {s}", .{ @typeName(T) });
            return error.UnsupportedType;
        },
    }
}

/// Set an `instance` of a Pointer Type (`T`) from the given `bytes`.
pub fn setPtrFromBytes(
    alloc: mem.Allocator,
    T: type,
    instance: *T,
    bytes: []const u8
) !void {
    const raw_info = @typeInfo(T);
    if (raw_info != .pointer) return error.NotAPointer;
    const info = raw_info.pointer;
    switch (info.size) {
        .one => instance.* = try ptrFromBytes(alloc, T, bytes),
        .slice => {
            if (T == []const u8) {
                instance.* = try alloc.dupe(u8, bytes);
                return;
            }
            const add = try ptrFromBytes(alloc, T, bytes);
            errdefer freePtrBytes(alloc, T, add);
            const new = 
                if (instance.*.len == 0) add
                else new: {
                    defer alloc.free(instance.*);
                    break :new try mem.concat(alloc, info.child, &.{ instance.*, add });
                };
            defer alloc.free(add);
            instance.* = new;
        },
        else => return error.UnsupportedType,
    }
}

/// Get an Instance of an Optional Type (`T`) from the given `bytes`.
pub fn optFromBytes(alloc: mem.Allocator, T: type, bytes: []const u8) !T {
    const raw_info = @typeInfo(T);
    if (raw_info != .optional) return error.NotAnOptional;
    const info = raw_info.optional;
    return switch (@typeInfo(info.child)) {
        .optional => try optFromBytes(alloc, T, bytes),
        .pointer => try ptrFromBytes(alloc, T, bytes),
        .@"struct" => try fromBytes(alloc, T, bytes),
        else => try primFromBytes(T, bytes),
    };
}

/// Set an `instance` of an Optional Type (`T`) from the given `bytes`.
pub fn setOptFromBytes(
    alloc: mem.Allocator,
    T: type,
    instance: *T,
    bytes: []const u8,
) !void {
    const raw_info = @typeInfo(T);
    if (raw_info != .optional) return error.NotAnOptional;
    const info = raw_info.optional;
    const child_info = @typeInfo(info.child);
    errdefer freeOptBytes(alloc, T, instance.*);
    if (instance.*) |*_instance| {
        if (child_info == .pointer and child_info.pointer.size == .slice)
            return try setPtrFromBytes(alloc, info.child, _instance, bytes)
        else return;
    }
    switch (child_info) {
        .optional => try setOptFromBytes(alloc, info.child, instance, bytes),
        .pointer => {
            if (instance.*) |*_instance|
                try setPtrFromBytes(alloc, info.child, _instance, bytes)
            else instance.* = try ptrFromBytes(alloc, info.child, bytes);
        },
        .@"struct" => instance.* = try fromBytes(alloc, info.child, bytes),
        else => instance.* = try primFromBytes(info.child, bytes),
    }
}

/// Get an Instance of a Raw (packed or extern) Type (`T`) from the given `bytes`.
pub fn rawFromBytes(T: type, bytes: []const u8) !T {
    const type_len = @bitSizeOf(T) / 8;
    if (bytes.len != type_len) {
        log.err("Error converting to Type `{s}`. Expected {d}B, received {d}B.", .{ @typeName(T), type_len, bytes.len });
        return error.IncorrectBytesLength;
    }
    return @bitCast(bytes[0..type_len].*);
}

/// Get an Instance of a Type (`T`) from the given `bytes`.
/// Note, the resulting instance should be freed using `freeBytes()`.
pub fn fromBytes(
    alloc: mem.Allocator, 
    T: type, 
    bytes: []const u8,
) !T {
    var instance: T = undefined;
    errdefer freeBytes(alloc, T, instance);
    inline for (meta.fields(T)) |field| {
        const field_info = @typeInfo(field.type);
        if (field_info == .optional) @field(instance, field.name) = null;
        if (field.default_value_ptr) |val| @field(instance, field.name) = @as(*const field.type, @alignCast(@ptrCast(val))).*;
        if (field_info == .pointer and field_info.pointer.size == .slice)
            @field(instance, field.name) = &.{};
    }
    return try baseFromBytes(alloc, T, bytes, instance);
}

/// Update an `instance` of a Type (`T`) from the given `bytes`.
/// Note, the resulting instance should be freed using `freeBytes()`.
pub fn updFromBytes(
    alloc: mem.Allocator,
    T: type, 
    bytes: []const u8,
    instance: *T,
) !void {
    instance.* = try baseFromBytes(alloc, T, bytes, instance.*);
}

/// Fill the `base_instance` of a Type (`T`) from the given `bytes`.
/// Note, the resulting instance should be freed using `freeBytes()`.
pub fn baseFromBytes(
    alloc: mem.Allocator,
    T: type,
    bytes: []const u8,
    base_instance: T,
) !T {
    if (meta.hasFn(T, "fromBytes")) return try T.fromBytes(alloc, bytes);
    const info = @typeInfo(T);
    if (info == .@"struct" and (info.@"struct".layout == .@"extern" or info.@"struct".layout == .@"packed"))
        return try rawFromBytes(T, bytes);
    var instance = base_instance;
    errdefer freeBytes(alloc, T, instance);
    comptime var req_fields = 0;
    inline for (meta.fields(T)) |field| {
        const field_info = @typeInfo(field.type);
        if (field_info != .optional and field.default_value_ptr == null) req_fields += 1;
    }
    const E, 
    const HdrT = comptime consts: {
        var E: ?type = null;
        var HdrT: ?type = null;
        for (@typeInfo(T).@"struct".decls) |decl| {
            if (mem.eql(u8, decl.name, "AttrE")) E = @field(T, "AttrE");
            if (mem.eql(u8, decl.name, "AttrHdrT")) HdrT = @field(T, "AttrHdrT");
        }
        break :consts .{
            E orelse @compileError("Missing Attribute Enum Declaration (`AttrE`)"),
            HdrT orelse nl.AttributeHeader,
        };
    };
    //log.debug("T: {s}, E: {s}", .{ @typeName(T), @typeName(E) });
    const hdr_len = @sizeOf(HdrT);
    //log.debug("---\nConverting to '{s}'. Hdr Len: {d}. Align: '{}'", .{ @typeName(T), hdr_len, HdrT.nl_align });
    var field_count: usize = 0;
    var start: usize = 0;
    var end: usize = hdr_len;
    while (end < bytes.len) {
        const hdr = mem.bytesToValue(HdrT, bytes[start..end]);
        const tag: E = meta.intToEnum(E, hdr.type) catch meta.stringToEnum(E, "__UNKNOWN__") orelse {
            log.err("The Tag # '{d}' does not match a field in the '{s}' Enum.", .{ hdr.type, @typeName(E) });
            return error.UnknownTag;
        };
        const diff = if (HdrT.full_len) hdr.len -| hdr_len else hdr.len;
        //log.debug("Len: {d: <5} Num: {d: <5} Type: {s}", .{ hdr.len, hdr.type, @tagName(tag) });
        //log.debug(" - Start: {d}B, End: {d}B", .{ start, end + diff });
        start = end;
        end += diff;
        var parsed_fields: std.StringHashMapUnmanaged(void) = .{};
        defer parsed_fields.deinit(alloc);
        inline for (meta.fields(T)) |field| cont: {
            if (!mem.eql(u8, field.name, @tagName(tag)) or diff == 0) break :cont;
            if (parsed_fields.get(field.name)) |_| break :cont;
            // TODO: Figure out the potential segfault here
            try parsed_fields.put(alloc, field.name, {});
            const field_info = @typeInfo(field.type);
            defer if (field_info != .optional) {
                field_count += 1;
            };
            const in_field = &@field(instance, field.name);
            switch (field_info) {
                .optional => try setOptFromBytes(alloc, field.type, in_field, bytes[start..end]),
                .pointer => try setPtrFromBytes(alloc, field.type, in_field, bytes[start..end]),
                .@"struct" => in_field.* = try fromBytes(alloc, field.type, bytes[start..end]),
                else => in_field.* = try primFromBytes(field.type, bytes[start..end]),
            }
        }
        if (HdrT.nl_align) end = mem.alignForward(usize, end, 4);
        start = end;
        end += hdr_len;
    }
    //log.debug("---", .{});
    if (field_count < req_fields) {
        log.err(
            "Error converting to Type '{s}'. Required Fields: {d}. Provided Fields: {d}.\n{s}", 
            .{ 
                @typeName(T), 
                req_fields, 
                field_count, 
                HexF{ .bytes = bytes }, 
            },
        );
        return error.IncompleteTypeData;
    }
    return instance;
}

/// Recursively frees allocations from Pointer instances, including the provided `instance` Pointer.
pub fn freePtrBytes(alloc: mem.Allocator, T: type, instance: T) void {
    if (T == []const u8) {
        alloc.free(instance);
        return;
    }
    const raw_info = @typeInfo(T);
    if (raw_info != .pointer) return;
    const info = raw_info.pointer;
    const child_info = @typeInfo(info.child);
    switch (info.size) {
        .one => {
            switch (child_info) {
                .optional => freeOptBytes(alloc, info.child, instance),
                .pointer => freePtrBytes(alloc, info.child, instance),
                .@"struct" => freeBytes(alloc, info.child, instance),
                else => {},
            }
        },
        .slice => {
            for (instance) |in_field| {
                switch (child_info) {
                    .optional => freeOptBytes(alloc, info.child, in_field),
                    .pointer => freePtrBytes(alloc, info.child, in_field),
                    .@"struct" => freeBytes(alloc, info.child, in_field),
                    else => {},
                }
            }
        },
        else => {},
    }
    alloc.free(instance);
}

/// Recursively frees allocations from Optional instances.
pub fn freeOptBytes(alloc: mem.Allocator, T: type, instance: T) void {
    const _instance = instance orelse return;
    const raw_info = @typeInfo(T);
    if (raw_info != .optional) return;
    const info = raw_info.optional;
    const child_info = @typeInfo(info.child);
    switch (child_info) {
        .optional => freeOptBytes(alloc, info.child, _instance),
        .pointer => freePtrBytes(alloc, info.child, _instance),
        .@"struct" => freeBytes(alloc, info.child, _instance),
        else => {},
    }
}

/// Recursively frees allocations made by `fromBytes()`.
pub fn freeBytes(alloc: mem.Allocator, T: type, instance: T) void {
    //log.debug("-------\n       CHECK f/ Free: {s}", .{ @typeName(T) });
    inline for (meta.fields(T)) |field| {
        const in_field = @field(instance, field.name);
        switch (@typeInfo(field.type)) {
            .optional => freeOptBytes(alloc, field.type, in_field),
            .pointer => freePtrBytes(alloc, field.type, in_field),
            .@"struct" => freeBytes(alloc, field.type, in_field),
            else => {},
            //else => log.debug("__NOT FREED: {s} ({s})", .{ field.name, @typeName(field.type) }),
        }
    }
    //log.debug("FINISH: {s}\n       -------", .{ @typeName(T) });
}

/// Write an `instance` of the provided Raw (packed or union) Type (`T`) to Netlink Bytes using the provided Allocator `alloc`.
pub fn rawToBytes(alloc: mem.Allocator, T: type, instance: T) ![]u8 {
    return alloc.dupe(u8, mem.toBytes(instance)[0..(@bitSizeOf(T) / 8)]);
}

/// Write the provided `instance` to Netlink Bytes using the provided Allocator `alloc`.
pub fn toBytes(alloc: mem.Allocator, T: type, instance: T) ![]u8 {
    if (meta.hasMethod(T, "toBytes")) return try instance.toBytes(alloc);
    const info = @typeInfo(T);
    if (info == .@"struct" and (info.@"struct".layout == .@"extern" or info.@"struct".layout == .@"packed"))
        return try rawToBytes(alloc, T, instance);
    var buf: ArrayList(u8) = .empty;
    errdefer buf.deinit(alloc);
    const E,
    const HdrT = comptime consts: {
        var E: ?type = null;
        var HdrT: ?type = null;
        for (@typeInfo(T).@"struct".decls) |decl| {
            if (mem.eql(u8, decl.name, "AttrE")) E = @field(T, "AttrE");
            if (mem.eql(u8, decl.name, "AttrHdrT")) HdrT = @field(T, "AttrHdrT");
        }
        break :consts .{
            E orelse @compileError(fmt.comptimePrint("Type `{s}` is missing Attribute Enum Declaration (`AttrE`)", .{ @typeName(T) })),
            HdrT orelse nl.AttributeHeader,
        };
    };

    inline for (meta.fields(T)) |field| cont: {
        var hdr: HdrT = .{
            .len = if (HdrT.full_len) @sizeOf(HdrT) else 0,
            .type = @intFromEnum(meta.stringToEnum(E, field.name) orelse {
                log.debug("Unknown Tag '{s}' for Enum '{s}'", .{ field.name, @typeName(E) });
                return error.UnknownEnum;
            }),
        };
        const in_field = @field(instance, field.name);
        const field_info = @typeInfo(field.type);
        const bytes = switch (field_info) {
            .pointer => try ptrToBytes(alloc, field.type, in_field, HdrT, E, field.name),
            .optional => try optToBytes(alloc, field.type, in_field orelse break :cont, HdrT, E, field.name),
            .@"struct" => try toBytes(alloc, field.type, in_field),
            else => try primToBytes(alloc, field.type, in_field),
        };
        defer alloc.free(bytes);
        hdr.len +|= @intCast(bytes.len);
        const add_hdr = addHdr: {
            const hdr_child,
            const hdr_info =
                if (field_info == .optional) .{ field_info.optional.child, @typeInfo(field_info.optional.child) } 
                else .{ field.type, field_info };
            if (hdr_child == []const u8 or hdr_info != .pointer) break :addHdr true;
            if (hdr_info.pointer.size != .slice) break :addHdr true;
            break :addHdr false;
        };
        if (add_hdr)
            try buf.appendSlice(alloc, mem.toBytes(hdr)[0..]);
        try buf.appendSlice(alloc, bytes);
        if (HdrT.nl_align) try buf.appendNTimes(alloc, 0, (mem.alignForward(usize, buf.items.len, 4) - buf.items.len));
    }
    return try buf.toOwnedSlice(alloc);
}

/// Write an `instance` of Pointer Type (`T`) to Bytes.
fn ptrToBytes(
    alloc: mem.Allocator, 
    T: type,
    instance: T,
    HdrT: type,
    E: type,
    field_name: []const u8,
) ![]const u8 {
    const raw_info = @typeInfo(T);
    if (raw_info != .pointer) return error.NotAPointer;
    const info = raw_info.pointer;
    const child_info = @typeInfo(info.child);
    switch (info.size) {
        .one => return try primToBytes(alloc, info.child, instance.*),
        .slice => {
            if (T == []const u8) return try alloc.dupe(u8, instance);
            var buf: ArrayList(u8) = .empty;
            //if (T == []const []const u8) log.debug("Slice of Strings: {s}", .{ field_name });
            for (instance[0..]) |in_item| {
                var hdr: HdrT = .{
                    .len = if (HdrT.full_len) @sizeOf(HdrT) else 0,
                    .type = @intFromEnum(meta.stringToEnum(E, field_name) orelse return error.UnknownEnum),
                };
                const bytes = switch (child_info) {
                    .pointer => try ptrToBytes(alloc, info.child, in_item, HdrT, E, field_name),
                    .optional => try optToBytes(alloc, info.child, in_item, HdrT, E, field_name),
                    .@"struct" => try toBytes(alloc, info.child, in_item),
                    else => try primToBytes(alloc, info.child, in_item),
                };
                defer alloc.free(bytes);
                hdr.len +|= @intCast(bytes.len);
                //if (T == []const []const u8)
                //    log.debug("\nHdr: {}\nBytes: {X}", .{ hdr, bytes });
                try buf.appendSlice(alloc, mem.toBytes(hdr)[0..]);
                try buf.appendSlice(alloc, bytes);
                if (HdrT.nl_align) try buf.appendNTimes(alloc, 0, (mem.alignForward(usize, buf.items.len, 4) - buf.items.len));
            }
            return try buf.toOwnedSlice(alloc);
        },
        else => return error.UnsupportedType,
    }
}

/// Write an `instance` of Optional Type (`T`) to Bytes.
fn optToBytes(
    alloc: mem.Allocator, 
    T: type,
    instance: T,
    HdrT: type,
    E: type,
    field_name: []const u8,
) ![]const u8 {
    const raw_info = @typeInfo(T);
    if (raw_info != .optional) return;
    const info = raw_info.optional;
    const child_info = @typeInfo(info.child);
    const _instance = instance orelse return try alloc.alloc(u8, 0);
    return switch (child_info) {
        .optional => try optToBytes(alloc, info.child, _instance, HdrT, E, field_name),
        .pointer => try ptrToBytes(alloc, info.child, _instance, HdrT, E, field_name),
        .@"struct" => try toBytes(alloc, info.child, _instance),
        else => try primToBytes(alloc, info.child, _instance),
    };
}

/// Write an `instance` of a Primitive Type (`T`) to Bytes.
fn primToBytes(alloc: mem.Allocator, T: type, instance: T) ![]const u8 {
    switch (@typeInfo(T)) {
        .pointer => {
            if (T != []const u8) {
                log.err("Unsupported Pointer Type: '{s}'", .{ @typeName(T) });
                return error.UnsupportedType;
            }
            return try alloc.dupe(u8, instance);
        },
        .int, .float, .bool, .array => {
            const bytes = mem.toBytes(instance)[0..];
            return try alloc.dupe(u8, bytes);
        },
        else => {
            log.err("Unsupported Type: {s}", .{ @typeName(T) });
            return error.UnsupportedType;
        }
    }
}

/// Create a "Type, Length, Value" (TLV) Type (`OutT`) instance from an `instance` of the provided Type (`InT`).
/// Note, the OutT must possess `.type`, `.len`, and `.data` fields.
/// User must free the `.data` bytes of the resulting `OutT` instance.
pub fn toTLV(alloc: mem.Allocator, InT: type, instance: InT, OutT: type) !OutT {
    const HdrT = @FieldType(OutT, "hdr");
    const hdr_len = @sizeOf(HdrT);
    const tlv_bytes = try toBytes(alloc, InT, instance);
    defer alloc.free(tlv_bytes);
    return .{
        .hdr = mem.bytesToValue(HdrT, tlv_bytes[0..hdr_len]),
        .data = try alloc.dupe(u8, tlv_bytes[hdr_len..]),
    };
}

///// Write the provided Instance to Netlink Bytes using the provided `writer`.
//pub fn writeToBytes(writer: io.AnyWriter, T: type, instance: T) !usize {
//    if (meta.hasMethod(T, "writeToBytes")) return try instance.toBytes(writer);
//}

/// Config for creating an Iterator.
pub const IteratorConfig = struct {
    /// The Length Field Name
    len_field: []const u8 = "len",
    /// The Type Field Name (currently unused)
    type_field: []const u8 = "type",
};
/// Iterator
pub fn Iterator(
    HdrT: type,
    comptime iter_config: IteratorConfig,
) type {
    return struct {
        const config = iter_config;
        const hdr_len = @sizeOf(HdrT);
        const IterT = struct {
            hdr: HdrT,
            data: []const u8,
        };
        bytes: []const u8,
        index: usize = 0,
        fn rawNext(self: *@This(), is_peek: bool) ?IterT {
            var start: usize = self.index;
            var end: usize = self.index + hdr_len;
            if (self.bytes.len -| end == 0) return null;
            const hdr = mem.bytesToValue(HdrT, self.bytes[start..end]);
            const iter_len = @field(hdr, config.len_field);
            start = end;
            end = self.index + iter_len;
            //if (self.bytes.len -| end == 0) return null;
            if (!is_peek) self.index = end;
            return .{ .hdr = hdr, .data = self.bytes[start..end] };
        }
        pub fn next(self: *@This()) ?IterT {
            return self.rawNext(false);
        }
        pub fn peek(self: *@This()) ?IterT {
            return self.rawNext(true);
        }
    };
}
