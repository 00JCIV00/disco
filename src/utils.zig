//! Utility functions for DisCo

const std = @import("std");
const enums = std.enums;
const fmt = std.fmt;
const io = std.io;
const mem = std.mem;
const meta = std.meta;


/// Create an instance of a Struct Type with Integer Fields from the given Enum (`E`).
pub fn toStruct(E: type) enums.EnumFieldStruct(E, @typeInfo(E).Enum.tag_type, null) {
    var _struct: enums.EnumFieldStruct(E, @typeInfo(E).Enum.tag_type, null) = undefined;
    inline for (meta.fields(@TypeOf(_struct))) |field|
        @field(_struct, field.name) = @intFromEnum(@field(E, field.name));
    return _struct;
}
