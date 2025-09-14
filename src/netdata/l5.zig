//! Application Layer Structs and Functions.

const c = @import("../utils.zig").toStruct;


pub const BOOTP = struct {
    pub const OP = enum(u8) {
        /// BOOTREQUEST
        REQUEST = 1,
        /// BOOTREPLY
        REPLY = 2,
    };

    pub const Header = extern struct {
        /// Message op code / message type
        op: u8 = c(OP).REQUEST,
        /// Hardware address type (Ethernet = 1)
        hw_addr_type: u8 = 1,
        /// Hardware address length (Ethernet = 6)
        hw_addr_len: u8 = 6,
        /// Number of hops
        hops: u8 = 0,
        /// Transaction ID
        tx_id: u32,
        /// Seconds elapsed
        secs: u16 = 0,
        /// Flags
        flags: u16 = 0,
        /// Client IP address (if known)
        client_addr: [4]u8 align(1) = @splat(0),
        /// 'Your' (client) IP address
        self_addr: [4]u8 align(1) = @splat(0),
        /// Server IP address
        server_addr: [4]u8 align(1) = @splat(0),
        /// Relay agent IP address
        gw_addr: [4]u8 align(1) = @splat(0),
        /// Client hardware address
        //client_hw_addr: u128 = 0,
        client_hw_addr: [16]u8 align(1) = @splat(0),
        /// Server host name
        //server_hostname: u512 = 0,
        server_hostname: [64]u8 align(1) = @splat(0),
        /// Boot file name
        //file: u1024 = 0,
        file: [128]u8 align(1) = @splat(0),
        /// Magic cookie
        cookie: [4]u8 align(1) = [_]u8{ 0x63, 0x82, 0x53, 0x63 },
    };

    pub const OptionHeader = extern struct {
        code: u8,
        len: u8,
        //data: []const u8,
    };
};

pub const DHCP = struct {
    pub const MessageType = enum(u8) {
        DISCOVER = 1,
        OFFER = 2,
        REQUEST = 3,
        DECLINE = 4,
        ACK = 5,
        NAK = 6,
        RELEASE = 7,
        INFORM = 8,
    };

    pub const OptionCode = enum(u8) {
        PAD = 0,
        SUBNET_MASK = 1,
        ROUTER = 3,
        DNS = 6,
        HOSTNAME = 12,
        DOMAIN = 15,
        BROADCAST = 28,
        REQUESTED_IP = 50,
        LEASE_TIME = 51,
        MESSAGE_TYPE = 53,
        SERVER_ID = 54,
        PARAMETER_REQUEST = 55,
        ERROR_MESSAGE = 56,
        MAX_MESSAGE_SIZE = 57,
        RENEWAL_TIME = 58,
        REBINDING_TIME = 59,
        CLIENT_ID = 61,
        CLASSLESS_STATIC_ROUTE = 121,
        END = 255,
    };
};
