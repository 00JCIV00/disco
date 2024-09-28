//! Basic Netlink Functions

const std = @import("std");
const json = std.json;
const log = std.log;
const math = std.math;
const mem = std.mem;
const os = std.os;
const posix = std.posix;

const AF = os.linux.AF;
const NETLINK = os.linux.NETLINK;
const SOCK = posix.SOCK;
const IFNAMESIZE = posix.IFNAMESIZE;

const timeout = mem.toBytes(posix.timeval{ .tv_sec = 3, .tv_usec = 0 });
const nl_req_len = mem.alignForward(u32, @sizeOf(NetlinkRequest), 4);
const rtattr_len = mem.alignForward(usize, @sizeOf(os.linux.rtattr), 4);


/// Netlink Request
pub const NetlinkRequest = extern struct {
    /// Netlink Header
    nlh: os.linux.nlmsghdr,
    /// Interface Info Message
    ifi: os.linux.ifinfomsg,
};
/// Netlink Error
pub const NetlinkError = extern struct {
    /// Error
    err: i32,
    /// Netlink Header
    nlh: os.linux.nlmsghdr,
};

/// Send a Netlink Request
pub fn netlinkRequest(
    /// Raw Netlink Request (Before Length Calculation)
    nl_req_raw: NetlinkRequest,
    /// Route Attributes (Before Length Calculation)
    comptime rt_attrs_raw: ?os.linux.rtattr,
    /// Data Bytes
    data: ?[]const u8,
    /// Data Length (Used for padding)
    comptime data_len: usize,
) !posix.socket_t {
    const nl_sock = try posix.socket(AF.NETLINK, SOCK.RAW | SOCK.CLOEXEC, NETLINK.ROUTE);
    try posix.setsockopt(nl_sock, posix.SOL.SOCKET, posix.SO.RCVTIMEO, timeout[0..]);
    var rt_attrs = rt_attrs_raw;
    const attrs_len = comptime mem.alignForward(u16, rtattr_len + data_len, 4);
    if (rt_attrs) |*attrs| attrs.len = attrs_len;
    var nl_req = nl_req_raw;
    nl_req.nlh.len = mem.alignForward(u32, nl_req_len + attrs_len, 4);
    var req_buf: [mem.alignForward(usize, nl_req_len + attrs_len, 4)]u8 = undefined;
    @memset(req_buf[0..], 0);
    var start: usize = 0;
    var end: usize = nl_req_len;
    @memcpy(req_buf[start..end], mem.toBytes(nl_req)[0..]);
    if (rt_attrs) |attrs| {
        start = end;
        end += rtattr_len;
        @memcpy(req_buf[start..end], mem.toBytes(attrs)[0..]);
    }
    if (data) |_data| {
        start = end;
        end += _data.len;
        @memcpy(req_buf[start..end], _data);
    }
    _ = try posix.send(
        nl_sock,
        req_buf[0..],
        0,
    );
    return nl_sock;
}

/// Handle a Netlink ACK Response.
pub fn handleNetlinkAck(nl_sock: posix.socket_t) !void {
    var resp_idx: usize = 0;
    while (resp_idx <= 15) : (resp_idx += 1) {
        var resp_buf: [4096]u8 = .{ 0 } ** 4096;
        const resp_len = try posix.recv(
            nl_sock,
            resp_buf[0..],
            0,
        );
        var offset: usize = 0;
        while (offset < resp_len) {
            var start: usize = offset;
            var end: usize = (offset + @sizeOf(os.linux.nlmsghdr));
            const nl_resp_hdr: *os.linux.nlmsghdr = @alignCast(@ptrCast(resp_buf[start..end]));
            if (nl_resp_hdr.len < @sizeOf(os.linux.nlmsghdr))
                return error.InvalidMessage;
            if (nl_resp_hdr.type == .ERROR) {
                start = end;
                end += @sizeOf(NetlinkError);
                const nl_err: *const NetlinkError = @alignCast(@ptrCast(resp_buf[start..end]));
                switch (posix.errno(@as(isize, @intCast(nl_err.err)))) {
                    .SUCCESS => return,
                    .BUSY => return error.BUSY,
                    else => |err| {
                        log.err("OS Error: ({d}) {s}", .{ nl_err.err, @tagName(err) });
                        return error.OSError;
                    },
                }
            }
            offset += mem.alignForward(usize, nl_resp_hdr.len, 4);
        }
    }
    return error.NetlinkAckError;
}

/// Get the Index of an Interface from the provided Interface Name (`if_name`).
pub fn getIfIdx(if_name: []const u8) !i32 {
    const nl_sock = try netlinkRequest(
        .{
            .nlh = .{
                .len = 0,
                .type = .RTM_GETLINK,
                .flags = os.linux.NLM_F_REQUEST | os.linux.NLM_F_DUMP,
                .seq = 0,
                .pid = 50505,
            },
            .ifi = .{
                .family = AF.PACKET,
                .index = 0,
                .flags = 0,
                .change = 0,
                .type = 0,
            },
        },
        .{
            .len = 0,//mem.alignForward(u16, rtattr_len + IFNAMESIZE, 4),
            .type = .IFNAME,
        },
        if_name,
        IFNAMESIZE,
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
                end += @sizeOf(NetlinkError);
                const nl_err: *NetlinkError = @alignCast(@ptrCast(resp_buf[start..end]));
                if (nl_err.err != 0) {
                    log.debug("Netlink Error Status: {d}", .{ nl_err.err });
                    return error.NetlinkMessageError;
                }
            }
            if (nl_resp_hdr.type == .RTM_NEWLINK) ifi: {
                start = end;
                end += @sizeOf(os.linux.ifinfomsg);
                const ifi: *const os.linux.ifinfomsg = @alignCast(@ptrCast(resp_buf[start..end]));
                start = end;
                end += @sizeOf(os.linux.rtattr);
                const attr: *const os.linux.rtattr = @alignCast(@ptrCast(resp_buf[start..end]));
                if (attr.type != .IFNAME) break :ifi;
                start = end;
                end += attr.len;
                const name = resp_buf[start..end];
                if (!mem.eql(u8, if_name, name[0..@min(attr.len, if_name.len)])) break :ifi;
                return ifi.index;
            }
            offset += mem.alignForward(usize, nl_resp_hdr.len, 4);
        }
    }
    return error.NoInterfaceIndexFound;
}

/// Set the provided Interface (`if_index`) to the Up or Down State (`state`).
pub fn setState(if_index: i32, state: enum{ down, up }) !void {
    const nl_sock = try netlinkRequest(
        .{
            .nlh = .{
                .len = 0,
                .type = .RTM_SETLINK,
                .flags = os.linux.NLM_F_REQUEST | os.linux.NLM_F_ACK,
                .seq = 0,
                .pid = 40404,
            },
            .ifi = .{
                .family = AF.UNSPEC,
                .index = if_index,
                .change = 1, // IFF UP
                .flags = @intFromEnum(state),
                .type = 0,
            },
        },
        null,
        null,
        0,
    );
    try handleNetlinkAck(nl_sock);
}

/// Change the MAC (`mac`) of the provided Interface (`if_index`).
pub fn changeMAC(if_index: i32, mac: [6]u8) !void {
    try setState(if_index, .down);
    const nl_mac_sock = try netlinkRequest(
        .{
            .nlh = .{
                .len = 0,
                .type = .RTM_NEWLINK,
                .flags = os.linux.NLM_F_REQUEST | os.linux.NLM_F_ACK,
                .seq = 0,
                .pid = 60606,
            },
            .ifi = .{
                .family = AF.UNSPEC,
                .index = @intCast(if_index),
                .change = 0,
                .flags = 0,
                .type = 0,
            },
        },
        .{
            .len = 0,
            .type = .ADDRESS,
        },
        mac[0..],
        6,
    );
    try handleNetlinkAck(nl_mac_sock);
    try setState(if_index, .up);
}

/// Get All Interface Details (WIP)
pub fn getAllIF(if_name: []const u8) !void {
    const nl_sock = try netlinkRequest(
        .{
            .nlh = .{
                .len = 0,
                .type = .RTM_GETLINK,
                .flags = os.linux.NLM_F_REQUEST | os.linux.NLM_F_DUMP,
                .seq = 0,
                .pid = 50505,
            },
            .ifi = .{
                .family = AF.PACKET,
                .index = 0,
                .flags = 0,
                .change = 0,
                .type = 0,
            },
        },
        .{
            .len = 0,
            .type = .IFNAME,
        },
        if_name,
        IFNAMESIZE,
    );
    defer posix.close(nl_sock);

    var resp_idx: usize = 0;
    while (resp_idx <= 10) : (resp_idx += 1) {
        var resp_buf: [4096]u8 = undefined;
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
            if (nl_resp_hdr.type == .ERROR)
                return error.NetlinkMessageError;
            if (nl_resp_hdr.type == .RTM_NEWLINK) ifi: {
                start = end;
                end += @sizeOf(os.linux.ifinfomsg);
                //const ifi: *const os.linux.ifinfomsg = @alignCast(@ptrCast(resp_buf[start..end]));
                start = end;
                end += @sizeOf(os.linux.rtattr);
                const attr: *const os.linux.rtattr = @alignCast(@ptrCast(resp_buf[start..end]));
                if (attr.type != .IFNAME) break :ifi;
                start = end;
                end += attr.len;
                const name = resp_buf[start..end];
                if (!mem.eql(u8, if_name, name[0..@min(attr.len, if_name.len)])) break :ifi;
                //return ifi.index;
            }

            offset += mem.alignForward(usize, nl_resp_hdr.len, 4);
        }
    }
    return error.NoInterfaceIndexFound;
}
