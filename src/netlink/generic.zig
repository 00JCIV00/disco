//! Basic Netlink Generic (genetlink) Functions

const std = @import("std");
const ascii = std.ascii;
const enums = std.enums;
const heap = std.heap;
const json = std.json;
const log = std.log.scoped(.genetlink);
const math = std.math;
const mem = std.mem;
const meta = std.meta;
const os = std.os;
const posix = std.posix;
const time = std.time;

const nl = @import("../netlink.zig");
const utils = @import("../utils.zig");
const c = utils.toStruct;

/// Netlink Generic Request
pub const Request = nl.Request(Header);
/// Generic Netlink Message Header
pub const Header = extern struct {
    /// Generic Netlink Command
    cmd: u8,
    /// Generic Netlink Version
    version: u8 = 1,
    /// Reserved for future use.
    __reserved: u16 = 0,
};

/// General
pub const GENL = enum(u16) {
    ID_CTRL = 16,
};
/// Control
pub const CTRL = struct {
    pub const CMD = enum(u8) {
        NEWFAMILY = 1,
        GETFAMILY = 3,
    };
    pub const ATTR = enum(u16) {
        pub const MCAST_GRP = enum(u16) {
            NAME = 1,
            ID = 2,
        };

        FAMILY_ID = 1,
        FAMILY_NAME = 2,
        VERSION = 3,
        HDR_SIZE = 4,
        MAXATTR = 5,
        OPS = 6,
        MCAST_GROUPS = 7,
    };
};
/// Control Info 
pub const CtrlInfo = struct {
    FAMILY_ID: u16,
    FAMILY_NAME: []const u8,
    VERSION: u16,
    HDR_SIZE: u16,
    MAXATTR: u16,
    OPS: []const u8,
    MCAST_GROUPS: *std.StringHashMapUnmanaged(u32),

    pub fn fromBytes(alloc: mem.Allocator, bytes: []const u8) !@This() {
        var info: @This() = undefined;
        var field_count: usize = 0;
        var start: usize = 0;
        var end: usize = nl.attr_hdr_len;
        while (end < bytes.len) : (field_count += 1) {
            var hdr: *const nl.AttributeHeader = @alignCast(@ptrCast(bytes[start..end]));
            const attr_end = end + (hdr.len - nl.attr_hdr_len);
            const tag: CTRL.ATTR = @enumFromInt(hdr.type);
            log.debug("Len: {d}, Type: {s}", .{ hdr.len, @tagName(tag) });
            switch (tag) {
                .MCAST_GROUPS => {
                    var grp_map = try alloc.create(std.StringHashMapUnmanaged(u32)); 
                    errdefer alloc.destroy(grp_map);
                    grp_map.* = std.StringHashMapUnmanaged(u32){}; 
                    start = end;
                    end += nl.attr_hdr_len;
                    while (end < bytes.len) {
                        hdr = @alignCast(@ptrCast(bytes[start..end]));
                        start = end;
                        end += nl.attr_hdr_len;
                        hdr = @alignCast(@ptrCast(bytes[start..end]));
                        start = end;
                        end += hdr.len - nl.attr_hdr_len;
                        const id: *const u32 = @alignCast(@ptrCast(bytes[start..end]));
                        start = end;
                        end += nl.attr_hdr_len;
                        hdr = @alignCast(@ptrCast(bytes[start..end]));
                        start = end;
                        end += hdr.len - nl.attr_hdr_len;
                        const name = try alloc.dupe(u8, mem.trim(u8, bytes[start..end], (ascii.whitespace ++ .{ 0 })[0..]));
                        try grp_map.put(alloc, name, id.*);
                        end = mem.alignForward(usize, end, 4);
                        start = end;
                        end += nl.attr_hdr_len;
                        log.debug("Name: '{s}' ({d}B), ID: {d}", .{ name, name.len, id.* });
                    }
                    info.MCAST_GROUPS = grp_map;
                },
                .OPS => info.OPS = try alloc.dupe(u8, bytes),
                else => primField: { 
                    start = end;
                    end += hdr.len - nl.attr_hdr_len;
                    inline for (meta.fields(@This())) |field| cont: {
                        if (!mem.eql(u8, field.name, @tagName(tag))) break :cont;
                        @field(info, field.name) = try nl.parse.primFromBytes(field.type, bytes[start..end]);
                        break :primField;
                    }
                    return error.CouldNotConvertToType;
                },
            }
            end = mem.alignForward(usize, attr_end, 4);
            start = end;
            end += nl.attr_hdr_len;
        }
        return
            if (field_count < meta.fields(@This()).len) error.ControlInfoIncomplete
            else info;
    }

    /// Initialize Control Info for the specified `family`.
    pub fn init(alloc: mem.Allocator, family: []const u8) !@This() {
        // Request
        const buf_len = comptime mem.alignForward(usize, (Request.len + nl.attr_hdr_len + 7) * 2, 4);
        var req_buf: [buf_len]u8 = .{ 0 } ** buf_len;
        var fba = heap.FixedBufferAllocator.init(req_buf[0..]);
        const nl_sock = try nl.request(
            fba.allocator(),
            nl.NETLINK.GENERIC,
            Request,
            .{
                .nlh = .{
                    .len = 0,
                    .type = c(GENL).ID_CTRL,
                    .flags = c(nl.NLM_F).REQUEST,
                    .seq = 12321,
                    .pid = 0,
                },
                .msg = .{
                    .cmd = c(CTRL.CMD).GETFAMILY,
                    .version = 1,
                },
            },
            &.{ .{ .hdr = .{ .type = c(CTRL.ATTR).FAMILY_NAME }, .data = family } },
        );
        defer posix.close(nl_sock);

        // Response
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
            // Netlink Header
            var start: usize = offset;
            var end: usize = (offset + @sizeOf(nl.MessageHeader));
            const nl_resp_hdr: *const nl.MessageHeader = @alignCast(@ptrCast(resp_buf[start..end]));
            if (nl_resp_hdr.len < @sizeOf(nl.MessageHeader))
                return error.InvalidMessage;
            if (nl_resp_hdr.type == c(nl.NLMSG).ERROR) {
                start = end;
                end += @sizeOf(nl.ErrorHeader);
                const nl_err: *const nl.ErrorHeader = @alignCast(@ptrCast(resp_buf[start..end]));
                switch (posix.errno(@as(isize, @intCast(nl_err.err)))) {
                    .SUCCESS => {},
                    .BUSY => return error.BUSY,
                    else => |err| {
                        log.err("OS Error: ({d}) {s}", .{ nl_err.err, @tagName(err) });
                        return error.OSError;
                    },
                }
            }
            // General Header
            start = end;
            end += @sizeOf(Header);
            const gen_hdr: *const Header = @alignCast(@ptrCast(resp_buf[start..end]));
            start = end;
            end = offset + nl_resp_hdr.len;
            offset += mem.alignForward(usize, nl_resp_hdr.len, 4);
            if (gen_hdr.cmd != c(CTRL.CMD).NEWFAMILY) continue;
            // Control Info
            return try CtrlInfo.fromBytes(alloc, resp_buf[start..end]);
        }
        return error.NetlinkFamilyNotFound;
    }

    /// Deinitialize Control Info
    pub fn deinit(info: @This(), alloc: mem.Allocator) void {
        alloc.free(info.OPS);
        var key_iter = info.MCAST_GROUPS.keyIterator();
        while (key_iter.next()) |key| alloc.free(key.*);
        info.MCAST_GROUPS.deinit(alloc);
        alloc.destroy(info.MCAST_GROUPS);
    }
};

