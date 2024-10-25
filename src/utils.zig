//! Utility functions for DisCo

const std = @import("std");
const enums = std.enums;
const fmt = std.fmt;
const io = std.io;
const mem = std.mem;
const meta = std.meta;

/// Print a Network Address (IPv4, IPv6, MAC)
pub fn printAddr(
    bytes: []const u8, 
    comptime sep: []const u8, 
    comptime byte_fmt: []const u8, 
    writer: io.AnyWriter,
) !void {
    if (bytes.len == 0) return;
    try writer.print(byte_fmt, .{ bytes[0] });
    if (bytes.len == 1) return;
    for (bytes[1..]) |byte| try writer.print(sep ++ byte_fmt, .{ byte });
}

/// Create an instance of a Struct Type with Integer Fields from the given Enum (`E`).
pub fn toStruct(E: type) enums.EnumFieldStruct(E, @typeInfo(E).Enum.tag_type, null) {
    var _struct: enums.EnumFieldStruct(E, @typeInfo(E).Enum.tag_type, null) = undefined;
    inline for (meta.fields(@TypeOf(_struct))) |field|
        @field(_struct, field.name) = @intFromEnum(@field(E, field.name));
    return _struct;
}
