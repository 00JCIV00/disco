//! Basic Netlink Route Functions

const std = @import("std");
const json = std.json;
const log = std.log;
const math = std.math;
const mem = std.mem;
const os = std.os;
const posix = std.posix;

const nl = @import("../nl.zig");

/// Netlink Route Request
pub const Request = extern struct {
    /// Netlink Header
    nlh: os.linux.nlmsghdr,
    /// Interface Info Message
    ifi: os.linux.ifinfomsg,
};
/// Netlink Route Request Length
pub const req_len = mem.alignForward(u32, @sizeOf(Request), 4);
/// Route Attribute Type
pub const Attribute = os.linux.rtattr;
/// Route Attribute Length (aligned to 4B for Netlink Messaging)
pub const attr_len = mem.alignForward(usize, @sizeOf(os.linux.rtattr), 4);
/// Interface Flags (IFF)
pub const IFF = enum(u32) {
    DOWN = 0,
    UP = 1,
    BROADCAST = 1 << 1,
    DEBUG = 1 << 2,
    LOOPBACK = 1 << 3,
    POINTOPOINT = 1 << 4,
    RUNNING = 1 << 6,
    NOARP = 1 << 7,
    PROMISC = 1 << 8,
    ALLMULTI = 1 << 9,
    MULTICAST = 1 << 12,
};
const IFNAMESIZE = posix.IFNAMESIZE;


/// Get the Index of an Interface from the provided Interface Name (`if_name`).
pub fn getIfIdx(if_name: []const u8) !i32 {
    const nl_sock = try nl.netlinkRequest(
        os.linux.NETLINK.ROUTE,
        Request,
        .{
            .nlh = .{
                .len = 0,
                .type = .RTM_GETLINK,
                .flags = os.linux.NLM_F_REQUEST | os.linux.NLM_F_DUMP,
                .seq = 0,
                .pid = 50505,
            },
            .ifi = .{
                .family = nl.AF.PACKET,
                .index = 0,
                .flags = 0,
                .change = 0,
                .type = 0,
            },
        },
        Attribute,
        1,
        .{ .{ .len = 0, .type = .IFNAME } },
        .{ if_name },
        .{ IFNAMESIZE },
    );
    defer posix.close(nl_sock);

    var resp_idx: usize = 0;
    while (resp_idx <= 10) : (resp_idx += 1) {
        var resp_buf: [4096]u8 = .{ 0 } ** 4096;
        const resp_len = posix.recv(
            nl_sock,
            resp_buf[0..],
            0,
        ) catch |err| switch (err) {
            error.WouldBlock => return error.NoInterfaceFound,
            else => return err,
        };

        var offset: usize = 0;
        while (offset < resp_len) {
            var start: usize = offset;
            var end: usize = (offset + @sizeOf(os.linux.nlmsghdr));
            const nl_resp_hdr: *os.linux.nlmsghdr = @alignCast(@ptrCast(resp_buf[start..end]));
            if (nl_resp_hdr.len < @sizeOf(os.linux.nlmsghdr))
                return error.InvalidMessage;
            if (nl_resp_hdr.type == .ERROR) {
                start = end;
                end += @sizeOf(nl.NetlinkError);
                const nl_err: *nl.NetlinkError = @alignCast(@ptrCast(resp_buf[start..end]));
                switch (posix.errno(@as(isize, @intCast(nl_err.err)))) {
                    .SUCCESS => {},
                    .BUSY => return error.BUSY,
                    else => |err| {
                        log.err("OS Error: ({d}) {s}", .{ nl_err.err, @tagName(err) });
                        return error.OSError;
                    },
                }
            }
            if (nl_resp_hdr.type == .RTM_NEWLINK) ifi: {
                start = end;
                end += @sizeOf(os.linux.ifinfomsg);
                const ifi: *const os.linux.ifinfomsg = @alignCast(@ptrCast(resp_buf[start..end]));
                start = end;
                end += @sizeOf(Attribute);
                const _attr: *const Attribute = @alignCast(@ptrCast(resp_buf[start..end]));
                if (_attr.type != .IFNAME) break :ifi;
                start = end;
                end += _attr.len;
                const name = resp_buf[start..end];
                if (!mem.eql(u8, if_name, name[0..@min(_attr.len, if_name.len)])) break :ifi;
                return ifi.index;
            }
            offset += mem.alignForward(usize, nl_resp_hdr.len, 4);
        }
    }
    return error.NoInterfaceIndexFound;
}

/// Set the provided Interface (`if_index`) to the Up or Down State (`state`).
pub fn setState(if_index: i32, state: IFF) !void {
    const nl_sock = try nl.netlinkRequest(
        os.linux.NETLINK.ROUTE,
        Request,
        .{
            .nlh = .{
                .len = 0,
                .type = .RTM_SETLINK,
                .flags = os.linux.NLM_F_REQUEST | os.linux.NLM_F_ACK,
                .seq = 0,
                .pid = 40404,
            },
            .ifi = .{
                .family = nl.AF.UNSPEC,
                .index = if_index,
                .change = @intFromEnum(IFF.UP), 
                .flags = @intFromEnum(state),
                .type = 0,
            },
        },
        Attribute,
        0,
        .{},
        .{},
        .{},
    );
    defer posix.close(nl_sock);
    try nl.handleNetlinkAck(nl_sock);
}

/// Set the MAC (`mac`) of the provided Interface (`if_index`).
pub fn setMAC(if_index: i32, mac: [6]u8) !void {
    try setState(if_index, .DOWN);
    const nl_sock = try nl.netlinkRequest(
        os.linux.NETLINK.ROUTE,
        Request,
        .{
            .nlh = .{
                .len = 0,
                .type = .RTM_NEWLINK,
                .flags = os.linux.NLM_F_REQUEST | os.linux.NLM_F_ACK,
                .seq = 0,
                .pid = 60606,
            },
            .ifi = .{
                .family = nl.AF.UNSPEC,
                .index = @intCast(if_index),
                .change = 0,
                .flags = 0,
                .type = 0,
            },
        },
        Attribute,
        1,
        .{ .{ .len = 0, .type = .ADDRESS } },
        .{ mac[0..] },
        .{ 6 },
    );
    defer posix.close(nl_sock);
    try nl.handleNetlinkAck(nl_sock);
    try setState(if_index, .UP);
}

///// Get All Interface Details (WIP)
//pub fn getAllIF(if_name: []const u8) !void {
//    const nl_sock = try netlinkRequest(
//        .{
//            .nlh = .{
//                .len = 0,
//                .type = .RTM_GETLINK,
//                .flags = os.linux.NLM_F_REQUEST | os.linux.NLM_F_DUMP,
//                .seq = 0,
//                .pid = 50505,
//            },
//            .ifi = .{
//                .family = AF.PACKET,
//                .index = 0,
//                .flags = 0,
//                .change = 0,
//                .type = 0,
//            },
//        },
//        attr,
//        .{
//            .len = 0,
//            .type = .IFNAME,
//        },
//        if_name,
//        IFNAMESIZE,
//    );
//    defer posix.close(nl_sock);
//
//    var resp_idx: usize = 0;
//    while (resp_idx <= 10) : (resp_idx += 1) {
//        var resp_buf: [4096]u8 = undefined;
//        const resp_len = posix.recv(
//            nl_sock,
//            resp_buf[0..],
//            0,
//        ) catch |err| switch (err) {
//            error.WouldBlock => return error.NoInterfaceFound,
//            else => return err,
//        };
//
//        var offset: usize = 0;
//        while (offset < resp_len) {
//            var start: usize = offset;
//            var end: usize = (offset + @sizeOf(os.linux.nlmsghdr));
//            const nl_resp_hdr: *os.linux.nlmsghdr = @alignCast(@ptrCast(resp_buf[start..end]));
//            if (nl_resp_hdr.len < @sizeOf(os.linux.nlmsghdr))
//                return error.InvalidMessage;
//            if (nl_resp_hdr.type == .ERROR)
//                return error.NetlinkMessageError;
//            if (nl_resp_hdr.type == .RTM_NEWLINK) ifi: {
//                start = end;
//                end += @sizeOf(os.linux.ifinfomsg);
//                //const ifi: *const os.linux.ifinfomsg = @alignCast(@ptrCast(resp_buf[start..end]));
//                start = end;
//                end += @sizeOf(attr);
//                const attr: *const attr = @alignCast(@ptrCast(resp_buf[start..end]));
//                if (attr.type != .IFNAME) break :ifi;
//                start = end;
//                end += attr.len;
//                const name = resp_buf[start..end];
//                if (!mem.eql(u8, if_name, name[0..@min(attr.len, if_name.len)])) break :ifi;
//                //return ifi.index;
//            }
//
//            offset += mem.alignForward(usize, nl_resp_hdr.len, 4);
//        }
//    }
//    return error.NoInterfaceIndexFound;
//}
