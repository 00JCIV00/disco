//! Utility functions for DisCo

const std = @import("std");
const enums = std.enums;
const fmt = std.fmt;
const io = std.io;
const mem = std.mem;
const meta = std.meta;


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
