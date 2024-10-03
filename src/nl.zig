//! Basic Netlink Functions

const std = @import("std");
const fmt = std.fmt;
const json = std.json;
const log = std.log;
const math = std.math;
const mem = std.mem;
const os = std.os;
const posix = std.posix;

pub const AF = os.linux.AF;
const NETLINK = os.linux.NETLINK;
const SOCK = posix.SOCK;

const timeout = mem.toBytes(posix.timeval{ .tv_sec = 3, .tv_usec = 0 });

pub const _80211 = @import("netlink/_80211.zig");
pub const route = @import("netlink/route.zig");


/// Netlink Error
pub const NetlinkError = extern struct {
    /// Error
    err: i32,
    /// Netlink Header
    nlh: os.linux.nlmsghdr,
};

/// Send a Netlink Request
pub fn netlinkRequest(
    nl_sock_kind: comptime_int,
    RequestT: type,
    /// Raw Netlink Request (Before Length Calculation)
    nl_req_raw: RequestT,
    /// Attribute Type
    AttrT: type,
    /// Number of Attributes
    comptime num_attrs: usize,
    /// Attributes (Before Length Calculation) Array
    comptime attrs_raw: [num_attrs]AttrT,
    /// Data Bytes
    data: [num_attrs][]const u8,
    /// Data Lengths (Used for padding)
    comptime data_lens: [num_attrs]usize,
) !posix.socket_t {
    const req_len = comptime switch (RequestT) {
        route.Request => route.req_len,
        _80211.Request => _80211.req_len,
        else => @compileError("Unsupported Netlink Request Type."),
    };
    const attr_len = comptime switch (AttrT) {
        route.Attribute => route.attr_len,
        _80211.Attribute => _80211.attr_len,
        void => 0,
        else => @compileError("Unsupported Netlink Attribute Type."),
    };
    const attrs,
    const attrs_len: usize = comptime attrsLen: {
        if (num_attrs == 0) break :attrsLen .{ .{}, 0 };
        var attrs = attrs_raw;
        var len: usize = 0;
        for (data_lens[0..], attrs[0..]) |data_len, *attr| {
            attr.len = mem.alignForward(u16, attr_len + data_len, 4);
            len += attr.len;
        }
        break :attrsLen .{ attrs, len };
    };
    var nl_req = nl_req_raw;
    const msg_len = comptime mem.alignForward(u32, req_len + attrs_len, 4);
    nl_req.nlh.len = msg_len;
    var req_buf: [msg_len]u8 = undefined;
    @memset(req_buf[0..], 0);
    var start: usize = 0;
    var end: usize = req_len;
    @memcpy(req_buf[start..end], mem.toBytes(nl_req)[0..]);
    if (num_attrs > 0) {
        const _attrs = attrs;
        for (_attrs[0..], data[0..], data_lens[0..]) |attr, item, len| {
            start = end;
            end += attr_len;
            // Kinda iffy way to hanlde Variable Length SSIDs
            if (AttrT == _80211.Attribute and attr.type == _80211.ATTR_SSID) {
                nl_req.nlh.len = @intCast(msg_len - (32 - item.len));
                @memcpy(req_buf[0..req_len], mem.toBytes(nl_req)[0..]);
                var ssid_attr = attr;
                ssid_attr.len = @truncate(attr_len + item.len);
                @memcpy(req_buf[start..end], mem.toBytes(ssid_attr)[0..]);
                start = end;
                end += item.len;
                @memcpy(req_buf[start..end], item);
                continue;
            }
            @memcpy(req_buf[start..end], mem.toBytes(attr)[0..]);
            start = end;
            end += len;
            @memcpy(req_buf[start..@min(end, start + item.len)], item);
        }
    }
    const nl_sock = try posix.socket(AF.NETLINK, SOCK.RAW | SOCK.CLOEXEC, nl_sock_kind);
    errdefer posix.close(nl_sock);
    try posix.setsockopt(nl_sock, posix.SOL.SOCKET, posix.SO.RCVTIMEO, timeout[0..]);
    end = mem.alignForward(usize, end, 4);
    _ = try posix.send(
        nl_sock,
        req_buf[0..end],
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



