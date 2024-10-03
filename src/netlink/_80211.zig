//! Basic Netlink 802.11 Functions

const std = @import("std");
const json = std.json;
const log = std.log;
const math = std.math;
const mem = std.mem;
const os = std.os;
const posix = std.posix;
const time = std.time;

const nl = @import("../nl.zig");

/// Netlink General Request
pub const Request = extern struct {
    /// Netlink Header
    nlh: os.linux.nlmsghdr,
    /// General Netlink Header
    genh: Header,
};
/// Netlink General Request Length
pub const req_len = mem.alignForward(usize, @sizeOf(Request), 4);

/// Netlink 802.11 Attribute
pub const Attribute = extern struct {
    len: u16 = 0,
    type: u16,
};
pub const attr_len: usize = mem.alignForward(usize, @sizeOf(Attribute), 4);

/// General Netlink Message Header
pub const Header = extern struct {
    cmd: u8,
    version: u8,
    __reserved: u16 = 0,
};

// Constants
// - General
pub const GENL_ID_CTRL: u16 = 16;
// - Control
pub const CTRL_CMD_GETFAMILY: u8 = 3;
pub const CTRL_ATTR_FAMILY_ID: u16 = 1;
pub const CTRL_ATTR_FAMILY_NAME: u16 = 2;
pub const CTRL_ATTR_VERSION: u16 = 3;
// - Command
pub const CMD_SET_INTERFACE: u8 = 6;
pub const CMD_CONNECT: u8 = 46;
// - Attributes
pub const ATTR_IFINDEX: u16 = 3;
pub const ATTR_IFNAME: u16 = 4;
pub const ATTR_IFTYPE: u16 = 5;
pub const ATTR_SSID: u16 = 52;
pub const ATTR_AUTH_TYPE: u16 = 53;
pub const ATTR_CIPHER_SUITE: u16 = 57;
pub const ATTR_CIPHER_SUITES_PAIRWISE: u16 = 73;
pub const ATTR_CIPHER_SUITE_GROUP: u16 = 74;
pub const ATTR_WPA_VERSIONS: u16 = 75;
pub const ATTR_PMK: u16 = 254;
// - Authentication
pub const AUTH_TYPE_OPEN: u32 = 0;
pub const WPA_VERSION_1: u32 = 1;
pub const WPA_VERSION_2: u32 = 2;
// - Interface Type
pub const IFTYPE = enum(u32) {
    UNSPECIFIED,
    ADHOC,
    STATION,
    AP,
    AP_VLAN,
    WDS,
    MONITOR,
    MESH_POINT,
    P2P_CLIENT,
    P2P_GO,
    P2P_DEVICE,
    OCB,
    NAN,
};

/// Get Netlink 80211 Family ID
pub fn getFamID() !i32 {
    const nl_sock = try nl.netlinkRequest(
        os.linux.NETLINK.GENERIC,
        Request,
        .{
            .nlh = .{
                .len = 0,
                .type = @enumFromInt(GENL_ID_CTRL),
                .flags = os.linux.NLM_F_REQUEST,
                .seq = 0,
                .pid = 12321,
            },
            .genh = .{
                .cmd = CTRL_CMD_GETFAMILY,
                .version = 1,
            },
        },
        Attribute,
        1,
        .{ .{ .type = CTRL_ATTR_FAMILY_NAME } },
        .{ "nl80211" },
        .{ 7 },
    );
    defer posix.close(nl_sock);

    var resp_buf: [4096]u8 = .{ 0 } ** 4096;
    const resp_len = posix.recv(
        nl_sock,
        resp_buf[0..],
        0,
    ) catch |err| switch (err) {
        error.WouldBlock => return error.CouldNotFindNL80211Family,
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
        start = end;
        end += @sizeOf(Header);
        //const genh: *const Header = @alignCast(@ptrCast(resp_buf[start..end]));
        start = end;
        end += @sizeOf(Attribute);
        while (end < resp_len) {
            const attr: *const Attribute = @alignCast(@ptrCast(resp_buf[start..end]));
            start = end;
            end += attr.len - attr_len;
            if (attr.type == CTRL_ATTR_FAMILY_ID) {
                return @as(*u16, @alignCast(@ptrCast(resp_buf[start..end]))).*;
            }
            //end += mem.alignForward(usize, attr.len, 4) - attr.len;
            start = end;
            end += @sizeOf(Attribute);
        }
        offset += mem.alignForward(usize, nl_resp_hdr.len, 4);
    }
    return error.CouldNotFindNL80211Family;
}

/// Set the Mode for the Interface
pub fn setMode(if_index: i32, mode: IFTYPE) !void {
    const fam_id = try getFamID();
    const nl_sock = try nl.netlinkRequest(
        os.linux.NETLINK.GENERIC,
        Request,
        .{
            .nlh = .{
                .len = 0,
                .type = @enumFromInt(fam_id),
                .flags = os.linux.NLM_F_REQUEST | os.linux.NLM_F_ACK,
                .pid = 23432,
                .seq = 0,
            },
            .genh = .{
                .cmd = CMD_SET_INTERFACE,
                .version = 1,
            },
        },
        Attribute,
        2,
        .{
            .{ .type = ATTR_IFINDEX },
            .{ .type = ATTR_IFTYPE },
        },
        .{
            mem.toBytes(if_index)[0..],
            mem.toBytes(mode)[0..],
        },
        .{ 
            4,
            4,
        },
    );
    defer posix.close(nl_sock);

    try nl.handleNetlinkAck(nl_sock);
}

/// Connect to a WPA2 Network
pub fn connectWPA2(if_index: i32, ssid: []const u8, pmk: []const u8) !void {
    try nl.route.setState(if_index, .DOWN);
    time.sleep(10 * time.ns_per_ms);
    try setMode(if_index, IFTYPE.STATION);
    time.sleep(10 * time.ns_per_ms);
    try nl.route.setState(if_index, .UP);
    time.sleep(10 * time.ns_per_ms);
    const fam_id = try getFamID();
    const nl_sock = try nl.netlinkRequest(
        os.linux.NETLINK.GENERIC,
        Request,
        .{
            .nlh = .{
                .len = 0,
                .type = @enumFromInt(fam_id),
                .flags = os.linux.NLM_F_REQUEST | os.linux.NLM_F_ACK,
                .seq = 0,
                .pid = 12321,
            },
            .genh = .{
                .cmd = CMD_CONNECT,
                .version = 1,
            },
        },
        Attribute,
        7,
        .{
            .{ .type = ATTR_IFINDEX },
            .{ .type = ATTR_WPA_VERSIONS },
            .{ .type = ATTR_AUTH_TYPE },
            .{ .type = ATTR_CIPHER_SUITE_GROUP },
            .{ .type = ATTR_CIPHER_SUITES_PAIRWISE },
            .{ .type = ATTR_SSID },
            .{ .type = ATTR_PMK },
        },
        .{ 
            mem.toBytes(if_index)[0..],
            mem.toBytes(@as(u32, 2))[0..],
            mem.toBytes(@as(u32, 0))[0..],
            mem.toBytes(@as(u32, 4))[0..],
            mem.toBytes(@as(u32, 4))[0..],
            ssid,
            pmk,
        },
        .{ 
            4,
            4,
            4,
            4,
            4,
            32,
            32,
        },
    );
    defer posix.close(nl_sock);

    try nl.handleNetlinkAck(nl_sock);
}
