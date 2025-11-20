//! ABI Compliant Requests to DisCo Core

const std = @import("std");
const atomic = std.atomic;
const mem = std.mem;
const posix = std.posix;
const HashMap = std.HashMapUnmanaged;
const Io = std.Io;
const Thread = std.Thread;

const core = @import("../core.zig");
const nl = @import("../netlink.zig");
const utils = @import("../utils.zig");
const CSlice = utils.CSlice;
const ThreadArrayList = utils.ThreadArrayList;

/// External Get Request
pub const ExGet = extern union {
    interface: extern struct {
        tag: enum(u8) { name, mac },
        id: extern union { name: CSlice(u8), mac: [6]u8 },
    },
};

/// External Set Request
pub const ExSet = extern union {
    interface: extern struct {
        tag: enum(u8) {
            mac,
            state,
            add_ip,
            del_ip,
            mode,
            channel,
        },
        field: extern union {
            mac: [6]u8,
            state: u32,
            add_ip: extern struct { addr: [4]u8, cidr: u8 },
            del_ip: extern struct { addr: [4]u8, cidr: u8 },
            mode: u32,
            channel: extern struct { ch: usize, width: @typeInfo(nl._80211.CHANNEL_WIDTH).@"enum".tag_type },
        }
    },
};

/// External Request
pub const ExRequest = extern struct {
    module: Module,
    kind: enum (u8) { get, set },
    body: extern union { get: ExGet, set: ExSet },
};
