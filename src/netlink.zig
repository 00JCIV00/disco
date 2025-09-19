//! Basic Netlink Functions

const std = @import("std");
const atomic = std.atomic;
const fmt = std.fmt;
const log = std.log.scoped(.netlink);
const math = std.math;
const mem = std.mem;
const meta = std.meta;
const os = std.os;
const posix = std.posix;
const ArrayList = std.ArrayListUnmanaged;

pub const AF = os.linux.AF;
pub const IFLA = os.linux.IFLA;
pub const NETLINK = os.linux.NETLINK;
const SOCK = posix.SOCK;

pub const io = @import("netlink/io.zig");
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
    /// If this is left as `0` it will be given a Unique Sequence ID when sent as a request.
    seq: u32 = 0,
    /// Port ID. This is useful for tracking this specific Request/Response.
    /// If this is left as `0` it will be changed to the PID of the corresponding socket.
    pid: u32 = 0,
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


/// Netlink Socket Config
pub const NetlinkSocketConfig = struct {
    /// Netlink Socket Kind
    /// Derived from the `NETLINK` struct
    //kind: ?comptime_int = null,
    kind: u32,
    /// Blocking I/O for the Netlink Socket
    blocking: bool = true,
    /// Optional Timeout period for the Netlink Socket
    timeout: ?posix.timeval = null,
    /// Process ID for the Netlink Socket
    /// If this is left `null` a unique pid will be created
    pid: ?u32 = null,
    
    /// Current Unique PID f/ new Netlink Sockets
    var unique_pid: atomic.Value(u32) = .init(12321);
};
/// Initialize a Netlink Socket
pub fn initSock(nl_sock_conf: NetlinkSocketConfig) !posix.socket_t {
    defer if (nl_sock_conf.pid == null) {
        _ = NetlinkSocketConfig.unique_pid.fetchAdd(1, .acquire);
        if (NetlinkSocketConfig.unique_pid.load(.acquire) >= math.maxInt(u32)) NetlinkSocketConfig.unique_pid.store(12321, .monotonic);
    };
    const nl_sock = try posix.socket(AF.NETLINK, SOCK.RAW | SOCK.CLOEXEC, nl_sock_conf.kind);
    errdefer posix.close(nl_sock);
    const nl_addr: posix.sockaddr.nl = .{
        .pid = nl_sock_conf.pid orelse NetlinkSocketConfig.unique_pid.load(.acquire),
        .groups = 0,
    };
    try posix.bind(nl_sock, @ptrCast(&nl_addr), @sizeOf(posix.sockaddr.nl));
    if (!nl_sock_conf.blocking)
        _ = try posix.fcntl(nl_sock, posix.F.SETFL, os.linux.SOCK.NONBLOCK);
    if (nl_sock_conf.timeout) |timeout| {
        try posix.setsockopt(
            nl_sock,
            posix.SOL.SOCKET,
            posix.SO.RCVTIMEO,
            mem.toBytes(timeout)[0..],
        );
    }
    try posix.setsockopt(
        nl_sock,
        posix.SOL.NETLINK,
        NETLINK_OPT.NO_ENOBUFS,
        mem.toBytes(@as(u32, 1))[0..],
    );
    return nl_sock;
}

/// Request Context
pub const RequestContext = struct {
    /// Netlink Sequence ID
    seq_id: u32,
    /// Netlink Socket
    sock: i32,
    /// Optional Netlink Request Handler
    handler: ?*io.Handler = null,
    /// Async Request Timeout in milliseconds (ms)
    timeout: u32 = 1_000,

    /// Current Unique Sequence ID f/ new Netlink Requests
    var unique_seq_id: atomic.Value(u32) = .init(1000);

    /// Netlink Socket Data
    pub const NetlinkSocketData = union(enum) {
        /// The Netlink Handler info that will be used to handle this Request
        handler: struct {
            /// Netlink Request Handler
            handler: *io.Handler,
            /// Request Timeout in milliseconds (ms)
            timeout: u32 = 1_000,
        },
        /// POSIX ID of the Netlink Socket for this Request
        /// Use this if you already have an existing Netlink Socket
        id: posix.socket_t,
        /// Netlink Socket Config
        /// Use this to create a new Socket with this Request
        conf: NetlinkSocketConfig,
    };

    /// Get a Unique Netlink Sequence ID
    fn getSeqID() u32 {
        defer if (unique_seq_id.load(.acquire) >= math.maxInt(u32) - 1)
            unique_seq_id.store(1000, .monotonic);
        return unique_seq_id.fetchAdd(1, .acquire);
    }

    /// Initialize a new Request Context
    pub fn init(nl_sock_data: NetlinkSocketData) !@This() {
        var self: @This() = .{
            .seq_id = getSeqID(),
            .sock = nlSock: switch (nl_sock_data) {
                .handler => |handler| handler.handler.nl_sock,
                .conf => |conf| {
                    continue :nlSock .{ .id = try initSock(conf) };
                },
                .id => |id| id,
            },
        };
        if (nl_sock_data == .handler) {
            self.handler = nl_sock_data.handler.handler;
            self.timeout = nl_sock_data.handler.timeout;
        }
        return self;
    }

    /// Get another Netlink Sequence ID for this Request Context
    pub fn nextSeqID(self: *@This()) void {
        self.seq_id = getSeqID();
    }

    /// Get the Response Data for this Request Context.
    /// This only works if the Request Context was initialized with a `handler`.
    pub fn getResponse(self: *const @This()) ?anyerror![]const u8 {
        const handler = self.handler orelse return null;
        return handler.getResponse(self.seq_id);
    }

    /// Check for the Response Data to this Request Context.
    /// This only works if the Request Context was initialized with a `handler`.
    pub fn checkResponse(self: *const @This()) bool {
        const handler = self.handler orelse return false;
        return handler.checkResponse(self.seq_id);
    }
};
/// Send a Netlink Request
pub fn request(
    alloc: mem.Allocator,
    /// Netlink Request Type
    RequestT: type,
    /// Raw Netlink Request (Before Length Calculation)
    raw_req: RequestT,
    /// Attributes (Before Length Calculation) Array
    attrs_raw: []const Attribute,
    /// Netlink Request Context
    ctx: *RequestContext,
) !void {
    // Netlink Request
    const req_len = mem.alignForward(u32, @sizeOf(RequestT), 4);
    const attrs,
    const attrs_len: usize = attrsLen: {
        if (attrs_raw.len == 0) break :attrsLen .{ &.{}, 0 };
        var attrs_buf: ArrayList(Attribute) = try .initCapacity(alloc, attrs_raw.len);
        var len: usize = 0;
        for (attrs_raw[0..], 0..) |raw_attr, idx| {
            attrs_buf.appendAssumeCapacity(raw_attr);
            var attr = &attrs_buf.items[idx];
            if (attr.hdr.len == 0) attr.hdr.len = mem.alignForward(u16, @intCast(attr_hdr_len + attr.data.len), 4);
            len += mem.alignForward(u16, attr.hdr.len, 4);
        }
        break :attrsLen .{
            try attrs_buf.toOwnedSlice(alloc),
            mem.alignForward(usize, len, 4),
        };
    };
    defer if (attrs.len > 0) alloc.free(@as([]align(8) const Attribute, @alignCast(attrs)));
    var req = raw_req;
    const msg_len = mem.alignForward(u32, @intCast(req_len + attrs_len), 4);
    var sock_info: posix.sockaddr.nl = undefined;
    var sock_size: u32 = @sizeOf(posix.sockaddr.nl);
    try posix.getsockname(ctx.sock, @ptrCast(&sock_info), &sock_size);
    if (req.nlh.pid == 0) req.nlh.pid = sock_info.pid;
    //log.debug("PID: {d}", .{ nl_req.nlh.pid });
    if (req.nlh.seq == 0) req.nlh.seq = ctx.seq_id;
    //log.debug("SID: {d}", .{ nl_req.nlh.seq });
    req.nlh.len = msg_len;
    var req_buf: ArrayList(u8) = try .initCapacity(alloc, msg_len);
    defer req_buf.deinit(alloc);
    try req_buf.appendSlice(alloc, mem.toBytes(req)[0..]);
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
    if (ctx.handler) |handler| try handler.trackRequest(ctx.*);
    _ = try posix.send(
        ctx.sock,
        req_buf.items[0..],
        0,
    );
}

/// Handle a Netlink ACK Response from the provided `msg_buf`
pub fn handleAckBuf(msg_buf: []const u8) !void {
    var start: usize = 0;
    var end: usize = (start + @sizeOf(MessageHeader));
    const nl_resp_hdr: *const MessageHeader = @alignCast(@ptrCast(msg_buf[start..end]));
    if (nl_resp_hdr.len < @sizeOf(MessageHeader))
        return error.InvalidMessage;
    if (nl_resp_hdr.type > 4) return;
    if (@as(NLMSG, @enumFromInt(nl_resp_hdr.type)) == .ERROR) {
        start = end;
        end += @sizeOf(ErrorHeader);
        const nl_err: *const ErrorHeader = @alignCast(@ptrCast(msg_buf[start..end]));
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
            .NODEV => return error.NODEV,
            else => |err| {
                log.err("OS Error: ({d}) {s}", .{ nl_err.err, @tagName(err) });
                return error.OSError;
            },
        }
    }
    return error.NetlinkAckError;
}
/// Handle a Netlink ACK Response on the provided Netlink Socket `nl_sock`.
pub fn handleAckSock(nl_sock: posix.socket_t) !void {
    var resp_buf: [4096]u8 = undefined;
    const resp_len = try posix.recv(
        nl_sock,
        resp_buf[0..],
        0,
    );
    return try handleAckBuf(resp_buf[0..resp_len]);
}

/// Config for Handling Responses
pub const HandleConfig = struct {
    /// Netlink Header Type / Family ID
    nl_type: u16,
    /// Family Command Value (only applies for Generic Netlink Headers)
    fam_cmd: ?u8 = null,
    /// Log Parsing Errors as Warnings
    warn_parse_err: bool = false,
    /// Split Field
    split_field: ?[]const u8 = null,
    /// Repeated Fields
    repeated_fields: []const []const u8 = &.{},
    /// Array Fields
    slice_fields: []const []const u8 = &.{},
};

/// Context for Handling Responses.
/// Note, this is only used for `handleTypeBuf()`.
pub const HandleContext = struct {
    /// Handle Config
    config: HandleConfig,
    /// Done Flag
    done: ?bool = null,
};

/// Handle one ore more Netlink Responses containing a specific Type (`ResponseT`) from the provided `msg_buf`.
pub fn handleTypeBuf(
    alloc: mem.Allocator,
    msg_buf: []const u8,
    /// This must be a derivative of the `Request()` Type.
    ResponseHdrT: type,
    ResponseT: type,
    /// Function to Parse data. (Typically, this will be `nl.parse.fromBytes(ResponseT)`.)
    parseFn: *const fn(mem.Allocator, []const u8) anyerror!ResponseT,
    ctx: *HandleContext,
) ![]const ResponseT {
    const FamHdrT = comptime famHdrT: {
        for (meta.fields(ResponseHdrT)) |field| {
            if (mem.eql(u8, field.name, "msg")) break :famHdrT field.type;
        }
        else @compileError(fmt.comptimePrint("The Type `{s}` is not a `Request` Type.", .{ @typeName(ResponseHdrT) }));
    };
    const fam_hdr_len = @sizeOf(FamHdrT);
    var resp_list: ArrayList(ResponseT) = .empty;
    var msg_iter: parse.Iterator(MessageHeader, .{}) = .{ .bytes = msg_buf[0..] };
    var base_instance: ?ResponseT = null;
    while (msg_iter.next()) |msg| {
        defer {
            if (msg.hdr.flags & c(NLM_F).MULTI == 0) //
                ctx.done = true;
        }
        if (msg.hdr.type == c(NLMSG).DONE) {
            ctx.done = true;
            break;
        }
        const match_hdr = msg.hdr.type == ctx.config.nl_type;
        const match_cmd = matchCmd: {
            const cmd = ctx.config.fam_cmd orelse break :matchCmd true;
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
        const next_instance = parseFn(alloc, msg.data) catch |err| {
            if (ctx.config.warn_parse_err) //
                log.warn("Parsing Error: {s}", .{ @errorName(err) });
            continue;
        };
        if (ctx.config.split_field) |split| {
            const instance = instance: {
                if (base_instance) |*inst| //
                    break :instance inst //
                else {
                    base_instance = next_instance;
                    continue;
                }
            };
            const fields = meta.fields(ResponseT);
            var same_instance: bool = false;
            inline for (fields) |field| {
                if (mem.eql(u8, split, field.name)) {
                    same_instance = switch (@typeInfo(field.type)) {
                        .int, .float => @field(instance.*, field.name) == @field(next_instance, field.name),
                        .pointer => |ptr_info| //
                            ptr_info.size == .slice and mem.eql(ptr_info.child, @field(instance.*, field.name), @field(next_instance, field.name)),
                        else => return error.IncompatibleSplitID,
                    };
                }
            }
            if (!same_instance) {
                try resp_list.append(alloc, base_instance.?);
                base_instance = next_instance;
                continue;
            }
            inline for (fields) |field| {
                const non_repeat = nonRepeat: {
                    for (ctx.config.repeated_fields) |r_field| {
                        if (mem.eql(u8, field.name, r_field)) break :nonRepeat false;
                    }
                    break :nonRepeat true;
                };
                if (non_repeat) nonRepeat: {
                    const is_slice = isSlice: {
                        for (ctx.config.slice_fields) |slice_field| {
                            if (mem.eql(u8, field.name, slice_field)) break :isSlice true;
                        }
                        break :isSlice false;
                    };
                    if (is_slice) sliceField: {
                        const next_field = @field(next_instance, field.name);
                        const type_info = @typeInfo(@TypeOf(next_field));
                        const opt_child_info = switch (type_info) {
                            .optional => |opt| @typeInfo(opt.child),
                            else => break :sliceField,
                        };
                        if (opt_child_info != .pointer or opt_child_info.pointer.size != .slice) //
                            break :nonRepeat;
                        const next_slice = next_field orelse break :nonRepeat;
                        if (@field(instance, field.name)) |*base_field| {
                            const SliceChildT = switch (opt_child_info) {
                                .pointer => |ptr| ptr.child,
                                else => break :sliceField,
                            };
                            base_field.* = try mem.concat(
                                alloc,
                                SliceChildT,
                                &.{ base_field.*, next_slice },
                            );
                            break :nonRepeat;
                        }
                    }
                    @field(instance, field.name) = @field(next_instance, field.name);
                } //
                else //
                    parse.baseFreeBytes(alloc, field.type, @field(next_instance, field.name));
            }
        } //
        else {
            base_instance = next_instance;
            try resp_list.append(alloc, base_instance.?);
        }
        //log.debug("Parsed {d} '{s}'", .{ resp_list.items.len, @typeName(ResponseT) });
    }
    if (ctx.config.split_field) |_| if (base_instance) |instance| //
        try resp_list.append(alloc, instance);
    return try resp_list.toOwnedSlice(alloc);
}

/// Handle one ore more Netlink Responses containing a specific Type (`ResponseT`) on the provided Netlink Socket `nl_sock`.
pub fn handleTypeSock(
    alloc: mem.Allocator,
    nl_sock: posix.socket_t,
    /// This must be a derivative of the `Request()` Type.
    ResponseHdrT: type,
    ResponseT: type,
    /// Function to Parse data. (Typically, this will be `nl.parse.fromBytes(ResponseT)`.)
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
    // Parse Links
    var resp_list: ArrayList(ResponseT) = .empty;
    errdefer {
        for (resp_list.items) |item| parse.freeBytes(alloc, ResponseT, item);
        resp_list.deinit(alloc);
    }
    // - Handle Multi-part
    var handle_ctx: HandleContext = .{
        .config = config,
    };
    multiPart: while (!handle_ctx.done or resp_list.items.len == 0) {
        var resp_buf: [buf_size]u8 = undefined;
        const resp_len = try posix.recv(
            nl_sock,
            resp_buf[0..],
            0,
        );
        if (resp_len == 0) break :multiPart;
        // Handle Dump
        const resp_slice: []const ResponseT = try handleTypeBuf(
            alloc,
            resp_buf[0..resp_len],
            ResponseHdrT,
            ResponseT,
            parseFn,
            &handle_ctx,
        );
        resp_list.appendSlice(alloc, resp_slice);
    }
    return try resp_list.toOwnedSlice(alloc);
}
