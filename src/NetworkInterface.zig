//! Network Interface details for DisCo.

const std = @import("std");
const fmt = std.fmt;
const log = std.log;
const mem = std.mem;
const os = std.os;
const posix = std.posix;

const nl = @import("netlink.zig");

const AF = os.linux.AF;

name: []const u8,
index: i32,
route_info: nl.route.DeviceInfo,

/// Get an Interface using Netlink.
pub fn get(name: []const u8) !@This() {
    var net_if: @This() = undefined;
    const idx = try nl.route.getIfIdx(name);
    net_if.name = name;
    net_if.index = idx;
    net_if.route_info = try nl.route.DeviceInfo.get(idx);

    return net_if;
}

/// Update this Interface
pub fn update(self: *@This()) !void {
    self.* = try get(self.name);
}

/// Print this Network Interface's Details
pub fn format(
    self: @This(), 
    _: []const u8, 
    _: fmt.FormatOptions, 
    writer: anytype,
) !void {
    try writer.print(
        \\- Name:  {s}
        \\{s}
        \\
        , .{
            self.name,
            self.route_info,
        }
    );
}

