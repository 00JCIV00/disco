//! Requests to DisCo Core

const std = @import("std");

const nl = @import("../netlink.zig");

pub const CSlice = extern struct {
    ptr: [*]const u8,
    len: usize,

    pub fn fromSlice(slice: []const u8) @This() {
        return .{
            .ptr = slice.ptr,
            .len = slice.len,
        };
    }

    pub fn toSlice(self: *@This()) []const u8 {
        self.ptr[0..self.len];
    }
};


/// Core Modules to request from
pub const Module = enum(u8) {
    core,
    interfaces,
    networks,
    connections,
    sockets,
    captures,
    serve,
};

/// Get Request
pub const Get = extern union {
    interface: extern struct {
        tag: enum(u8) { name, mac },
        id: extern union { name: CSlice, mac: [6]u8 },
    },
};

/// Set Request
pub const Set = extern union {
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

/// Request
pub const Request = extern struct {
    module: Module,
    kind: enum (u8) { get, set },
    body: extern union { get: Get, set: Set },
};
