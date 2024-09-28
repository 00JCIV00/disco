//! Network Interface details for DisCo.

const std = @import("std");
const log = std.log; 
const mem = std.mem;
const os = std.os;
const posix = std.posix;

const nl = @import("nl.zig");

const AF = os.linux.AF;

name: []const u8,
idx: i32,
mac: [6]u8,
mtu: usize,
phy: ?usize = null,
ips: ?[][4]u8 = null,
ch: ?u16 = null,
rssi: ?i16 = null,
rxq: ?u16 = null,

/// Get an Interface using Netlink.
pub fn get(name: []const u8) !@This() {
    var net_if: @This() = undefined;
    net_if.name = name;
    net_if.idx = try nl.getIfIdx(name);
    net_if.phy = null;
    net_if.ips = null;
    net_if.ch = null;
    net_if.rssi = null;
    net_if.rxq = null;

    const nl_sock = try nl.netlinkRequest(
        .{
            .nlh = .{
                .len = 0,
                .type = .RTM_GETLINK,
                .flags = os.linux.NLM_F_REQUEST,
                .pid = 10101,
                .seq = 0,
            },
            .ifi = .{
                .family = AF.UNSPEC,
                .index = net_if.idx,
                .type = 0,
                .change = 0,
                .flags = 0,
            },
        },
        null,
        null,
        0,
    );
    defer posix.close(nl_sock);

    var set_count: u8 = 0;
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
        if (nl_resp_hdr.type == .RTM_NEWLINK) {
            start = end + @sizeOf(os.linux.ifinfomsg);
            end += @sizeOf(os.linux.ifinfomsg) + nl.rtattr_len;
            while (end < offset + nl_resp_hdr.len) {
                const attr: *const os.linux.rtattr = @alignCast(@ptrCast(resp_buf[start..end]));
                start = end;
                end += (attr.len -| nl.rtattr_len);
                switch (attr.type) {
                    .ADDRESS => {
                        @memcpy(net_if.mac[0..], resp_buf[start..start + 6]);
                        set_count += 1;
                    },
                    .MTU => {
                        net_if.mtu = @as(*const u32, @alignCast(@ptrCast(resp_buf[start..start + 4]))).*;
                        set_count += 1;
                    },
                    else => {}
                }
                end = mem.alignForward(usize, end, 4);
                start = end;
                end += nl.rtattr_len;
            }
        }
        offset += mem.alignForward(usize, nl_resp_hdr.len, 4);
    }
    if (set_count < 2) return error.DetailsNotProvided;
    return net_if;
}


