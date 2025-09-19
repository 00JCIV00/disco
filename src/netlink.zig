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
const ArrayList = std.ArrayList;

pub const AF = os.linux.AF;
pub const IFLA = os.linux.IFLA;
pub const NETLINK = os.linux.NETLINK;
pub const SOCK = posix.SOCK;

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


