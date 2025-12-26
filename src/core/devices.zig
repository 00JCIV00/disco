//! Device Tracking


const std = @import("std");
const atomic = std.atomic;
const fmt = std.fmt;
const heap = std.heap;
const linux = std.os.linux;
const log = std.log.scoped(.networks);
const math = std.math;
const mem = std.mem;
const meta = std.meta;
const posix = std.posix;
const time = std.time;
const ArrayList = std.ArrayList;
const Io = std.Io;
const Thread = std.Thread;

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
const ansi = utils.ansi;
const c = utils.toStruct;
const ThreadHashMap = utils.ThreadHashMap;


/// Received Signal Stength Index (RSSI)
pub const RSSI = struct {
    /// Signal Strength in dBm
    strength: i32,

    pub fn format(self: @This(), writer: *Io.Writer) Io.Writer.Error!void {
        const rssi_color: []const u8 = switch (self.strength) {
            -40...100 => ansi.fg.green,
            -70...-41 => ansi.fg.yellow,
            else => ansi.fg.red,
        };
        try writer.print("{s}{d}{s}", .{ rssi_color, self.strength, ansi.fg.reset });
    }
};
