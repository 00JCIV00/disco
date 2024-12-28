//! Basic Netlink Functions

const std = @import("std");
const fmt = std.fmt;
const json = std.json;
const log = std.log;
const math = std.math;
const mem = std.mem;
const meta = std.meta;
const os = std.os;
const posix = std.posix;

pub const AF = os.linux.AF;
pub const IFLA = os.linux.IFLA;
pub const NETLINK = os.linux.NETLINK;
const SOCK = posix.SOCK;


pub const parse = @import("netlink/parse.zig");
pub const _80211 = @import("netlink/_80211.zig");
pub const generic = @import("netlink/generic.zig");
pub const route = @import("netlink/route.zig");

const utils = @import("utils.zig");
const c = utils.toStruct;

/// Netlink Socket Options
pub const NETLINK_OPT = struct {
    pub const ADD_MEMBERSHIP: u32 = 1;
    pub const DROP_MEMBERSHIP: u32 = 2;
    pub const PKTINFO: u32 = 3;
    pub const BROADCAST_ERROR: u32 = 4;
    pub const NO_ENOBUFS: u32 = 5;
    pub const RX_RING: u32 = 6;
    pub const TX_RING: u32 = 7;
    pub const LISTEN_ALL_NSID: u32 = 8;
    pub const LIST_MEMBERSHIPS: u32 = 9;
    pub const CAP_ACK: u32 = 10;
    pub const EXT_ACK: u32 = 11;
    pub const GET_STRICT_CHK: u32 = 12;
};

/// Netlink Message Header
pub const MessageHeader = extern struct {
    /// Length of the entire Request or Response.
    len: u32 = 0,
    /// Request or Response "Type." This will vary in meaning depending on the Netlink Family.
    type: u16,
    /// Request/Response Flags
    flags: u16,
    /// Sequence ID. This is useful for tracking this Request/Response and others related to it.
    seq: u32,
    /// Process ID. This is useful for tracking this specific Request/Response.
    pid: u32,
};
/// Generic Netlink Request Header, wrapping the Netlink Message Header w/ the provided Family Message Header Type (MsgT).
pub fn Request(MsgT: type) type {
    return extern struct {
        pub const len = mem.alignForward(u32, @sizeOf(@This()), 4);
        /// Netlink Message Header
        nlh: MessageHeader,
        /// Family Message Header
        msg: MsgT,
    };
}

/// Raw Request w/ no Family Message Header
pub const RequestRaw = Request(u32);

/// Netlink Attribute Header
pub const AttributeHeader = extern struct {
    pub const nl_align: bool = true;
    pub const full_len: bool = true;

    len: u16 = 0,
    type: u16,
};
/// Netlink Attribute Header Length (Aligned to 4 Bytes for Netlink messaging.)
pub const attr_hdr_len: usize = mem.alignForward(usize, @sizeOf(AttributeHeader), 4);

/// Netlink Attribute w/ Data
pub const Attribute = struct {
    hdr: AttributeHeader,
    data: []const u8,
};

/// Netlink Error Header
pub const ErrorHeader = extern struct {
    /// Error ID
    err: i32,
    /// Netlink Message Header
    nlh: MessageHeader,
};

/// Netlink Message Flags (NLM_F)
pub const NLM_F = enum(u16) {
    /// Request a response from the kernel
    REQUEST = 1,
    /// Multi-part message (additional messages follow)
    MULTI = 2,
    /// End of a multi-part message
    ACK = 4,
    /// Request acknowledgement of a successful operation
    ECHO = 8,
    /// Dump was interrupted (message will follow)
    DUMP_INTR = 16,
    /// Replace existing matching object
    REPLACE = 256,
    /// Start operation from the root (for dump operations)
    /// Shares the same value as REPLACE, but used differently
    /// ROOT = 256, 
    /// Create a new object if it doesn't exist
    EXCL = 512,
    /// Don't replace if the object exists
    CREATE = 1024,
    /// Add to an existing object
    APPEND = 2048,
    /// Dump filtered (data returned is influenced by input)
    DUMP_FILTERED = 8192,

    // Combined Flags
    /// Dump large amounts of data (combination of REQUEST and ROOT)
    /// DUMP = REQUEST | ROOT,
    DUMP = 1 | 256,
    /// Combine REQUEST and CREATE for creating new objects
    /// REQUEST_CREATE = REQUEST | CREATE,
    REQUEST_CREATE = 1 | 1024,
    /// Combine REQUEST, EXCL, and CREATE for exclusive creation of new objects
    /// REQUEST_EXCL_CREATE = REQUEST | EXCL | CREATE,
    REQUEST_EXCL_CREATE = 1 | 512 | 1024,
    /// Combine REQUEST and REPLACE for replacing existing objects
    /// REQUEST_REPLACE = REQUEST | REPLACE,
    //REQUEST_REPLACE = 1 | 256,
    /// Combine REQUEST and APPEND for appending to existing objects
    /// REQUEST_APPEND = REQUEST | APPEND,
    REQUEST_APPEND = 1 | 2048,
};

/// Common-to-All Netlink Message Header Types
pub const NLMSG = enum(u32) {
    /// No operation
    NOOP = 1,
    /// Error message
    ERROR = 2,
    /// End of a multi-part message
    DONE = 3,
    /// Message indicating an overrun (data was lost due to buffer overflow)
    OVERRUN = 4,
};

/// Initialize a Netlink Socket
pub fn initSock(nl_sock_kind: comptime_int, timeout: posix.timeval) !posix.socket_t {
    const nl_sock = try posix.socket(AF.NETLINK, SOCK.RAW | SOCK.CLOEXEC, nl_sock_kind);
    errdefer posix.close(nl_sock);
    try posix.setsockopt(
        nl_sock,
        posix.SOL.SOCKET,
        posix.SO.RCVTIMEO,
        mem.toBytes(timeout)[0..],
    );
    try posix.setsockopt(
        nl_sock,
        posix.SOL.NETLINK,
        NETLINK_OPT.NO_ENOBUFS,
        mem.toBytes(@as(u32, 1))[0..],
    );
    return nl_sock;
}

/// Send a Netlink Request
pub fn request(
    alloc: mem.Allocator,
    /// Netlink Socket Kind
    nl_sock_kind: comptime_int,
    /// Netlink Request Type
    RequestT: type,
    /// Raw Netlink Request (Before Length Calculation)
    nl_req_raw: RequestT,
    /// Attributes (Before Length Calculation) Array
    attrs_raw: []const Attribute,
) !posix.socket_t {
    const timeout = posix.timeval{ .tv_sec = 3, .tv_usec = 0 };
    const nl_sock = try initSock(nl_sock_kind, timeout);
    errdefer posix.close(nl_sock);
    try reqOnSock(alloc, nl_sock, RequestT, nl_req_raw, attrs_raw);
    return nl_sock;
}

/// Send a Netlink Request on the provided Socket `nl_sock`.
pub fn reqOnSock(
    alloc: mem.Allocator,
    /// Netlink Socket,
    nl_sock: posix.socket_t,
    /// Netlink Request Type
    RequestT: type,
    /// Raw Netlink Request (Before Length Calculation)
    nl_req_raw: RequestT,
    /// Attributes (Before Length Calculation) Array
    attrs_raw: []const Attribute,
) !void {
    const req_len = mem.alignForward(u32, @sizeOf(RequestT), 4);
    const attrs,
    const attrs_len: usize = attrsLen: {
        if (attrs_raw.len == 0) break :attrsLen .{ &.{}, 0 };
        var attrs_buf = try std.ArrayListUnmanaged(Attribute).initCapacity(alloc, attrs_raw.len);
        var len: usize = 0;
        for (attrs_raw[0..], 0..) |raw_attr, idx| {
            attrs_buf.appendAssumeCapacity(raw_attr);
            var attr = &attrs_buf.items[idx];
            if (attr.hdr.len == 0) attr.hdr.len = mem.alignForward(u16, @intCast(attr_hdr_len + attr.data.len), 4);
            len += mem.alignForward(u16, attr.hdr.len, 4);
        }
        break :attrsLen .{ 
            try attrs_buf.toOwnedSlice(alloc), 
            mem.alignForward(usize, len, 4) 
        };
    };
    defer if (attrs.len > 0) alloc.free(@as([]align(8)const Attribute, @alignCast(attrs)));
    var nl_req = nl_req_raw;
    const msg_len = mem.alignForward(u32, @intCast(req_len + attrs_len), 4);
    nl_req.nlh.len = msg_len;
    var req_buf = try std.ArrayListUnmanaged(u8).initCapacity(alloc, msg_len);
    defer req_buf.deinit(alloc);
    try req_buf.appendSlice(alloc, mem.toBytes(nl_req)[0..]);
    if (attrs.len > 0) {
        for (attrs[0..]) |attr| {
            try req_buf.appendSlice(alloc, mem.toBytes(attr.hdr)[0..]);
            try req_buf.appendSlice(alloc, attr.data[0..]);
            const len = req_buf.items.len;
            try req_buf.appendNTimes(alloc, 0, mem.alignForward(usize, len, 4) - len);
        }
    }
    if (req_buf.items.len < msg_len) {
        for (req_buf.items.len..msg_len) |_| req_buf.appendAssumeCapacity(0);
    }
    _ = try posix.send(
        nl_sock,
        req_buf.items[0..],
        0,
    );
}

/// Handle a Netlink ACK Response.
pub fn handleAck(nl_sock: posix.socket_t) !void {
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
            const nl_resp_hdr: *const MessageHeader = @alignCast(@ptrCast(resp_buf[start..end]));
            if (nl_resp_hdr.len < @sizeOf(MessageHeader))
                return error.InvalidMessage;
            if (nl_resp_hdr.type > 4) return;
            if (@as(NLMSG, @enumFromInt(nl_resp_hdr.type)) == .ERROR) {
                start = end;
                end += @sizeOf(ErrorHeader);
                const nl_err: *const ErrorHeader = @alignCast(@ptrCast(resp_buf[start..end]));
                switch (posix.errno(@as(isize, @intCast(nl_err.err)))) {
                    .SUCCESS => return,
                    .BUSY => return error.BUSY,
                    .NOLINK => return error.NOLINK,
                    .ALREADY => return error.ALREADY,
                    .EXIST => return error.EXIST,
                    .ADDRNOTAVAIL => return error.ADDRNOTAVAIL,
                    .SRCH => return error.SRCH,
                    .NETUNREACH => return error.NETUNREACH,
                    .INPROGRESS => return error.INPROGRESS,
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

/// Config for Handling Responses
pub const HandleConfig = struct {
    /// Netlink Header Type / Family ID
    nl_type: u16,
    /// Family Command Value (only applies for Generic Netlink Headers)
    fam_cmd: ?u8 = null,
};

/// Handle one ore more Netlink Responses containing a specific Type (`ResponseT`).
pub fn handleType(
    alloc: mem.Allocator, 
    nl_sock: posix.socket_t, 
    /// This must be a derivative of the `Request()` Type.
    ResponseHdrT: type,
    ResponseT: type,
    /// Function to Parse data. (Typically, this will be `nl.parse.fromBytes`.)
    parseFn: *const fn(mem.Allocator, []const u8) anyerror!ResponseT,
    config: HandleConfig,
) ![]const ResponseT {
    const buf_size: u32 = 64_000;
    try posix.setsockopt(
        nl_sock, 
        posix.SOL.SOCKET, 
        NETLINK_OPT.RX_RING, 
        mem.toBytes(buf_size)[0..],
    );
    const FamHdrT = comptime famHdrT: {
        for (meta.fields(ResponseHdrT)) |field| {
            if (mem.eql(u8, field.name, "msg")) break :famHdrT field.type;
        } else @compileError(fmt.comptimePrint("The Type `{s}` is not a `Request` Type.", .{ @typeName(ResponseHdrT) }));
    };
    const fam_hdr_len = @sizeOf(FamHdrT);
    // Parse Links
    var resp_list = try std.ArrayListUnmanaged(ResponseT).initCapacity(alloc, 0);
    errdefer resp_list.deinit(alloc);
    // - Handle Multi-part
    multiPart: while (true) {
        var resp_buf: [buf_size]u8 = .{ 0 } ** buf_size;
        const resp_len = try posix.recv(
            nl_sock,
            resp_buf[0..],
            0,
        );
        if (resp_len == 0) break :multiPart;
        // Handle Dump
        var msg_iter: parse.Iterator(MessageHeader, .{}) = .{ .bytes = resp_buf[0..resp_len] };
        while (msg_iter.next()) |msg| {
            if (msg.hdr.type == c(NLMSG).DONE) break :multiPart;
            const match_hdr = msg.hdr.type == config.nl_type;
            const match_cmd = matchCmd: {
                const cmd = config.fam_cmd orelse break :matchCmd true;
                inline for (meta.fields(FamHdrT)) |field| {
                    if (mem.eql(u8, field.name, "cmd")) {
                        const fam_hdr = mem.bytesToValue(FamHdrT, msg.data[0..fam_hdr_len]);
                        break :matchCmd @field(fam_hdr, field.name) == cmd; // Wtf Zig? This is convoluted!
                   }
                }
                log.err("The Generic Family Command '{d}' was provided for the non-Generic Header '{s}'", .{ cmd, @typeName(FamHdrT) });
                return error.GenericHeaderRequired;
            };
            if (!(match_hdr and match_cmd)) continue;
            const instance = parseFn(alloc, msg.data) catch |err| {
                log.warn("Parsing Error: {s}", .{ @errorName(err) });
                continue;
            };
            try resp_list.append(alloc, instance);
            //log.debug("Parsed {d} '{s}'", .{ resp_list.items.len, @typeName(ResponseT) });
        }
    }

    return try resp_list.toOwnedSlice(alloc);
}


