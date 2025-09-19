//! Basic Netlink Route (rtnetlink) Functions

const std = @import("std");
const fmt = std.fmt;
const heap = std.heap;
const json = std.json;
const log = std.log.scoped(.rtnetlink);
const math = std.math;
const mem = std.mem;
const os = std.os;
const posix = std.posix;
const ArrayList = std.ArrayList;

const nl = @import("../netlink.zig");
const utils = @import("../utils.zig");
const netdata = @import("../netdata.zig");
const address = netdata.address;
const c = utils.toStruct;


/// Interface Info Message (ifinfomsg)
pub const InterfaceInfoMessage = extern struct {
    family: u8,
    _padding: u8 = 0,
    type: u16,
    index: i32,
    flags: u32,
    change: u32,
};
/// Interface Address Message (ifaddrmsg)
pub const InterfaceAddressMessage = extern struct {
    family: u8,
    prefix_len: u8,
    flags: u8,
    scope: u8,
    index: i32,
};
/// Route Message (rtmsg)
pub const RouteMessage = extern struct {
    /// Address family
    family: u8,
    /// Destination length
    dst_len: u8,
    /// Source length
    src_len: u8,
    /// Type of Service
    tos: u8,
    /// Routing table ID
    table: u8,
    /// Routing protocol
    protocol: u8,
    /// Routing scope
    scope: u8,
    /// Routing type
    type: u8,
    /// Routing flags
    flags: u32,
};
/// Netlink Route Interface Info (ifi) Request
pub const RequestIFI = nl.Request(InterfaceInfoMessage);
/// Netlink Route Interface Address (ifa) Request
pub const RequestIFA = nl.Request(InterfaceAddressMessage);
/// Netlink Route Route Message (rtmsg) Request
pub const RequestRTM = nl.Request(RouteMessage);

/// Routing Attribute Types (RTA)
pub const RTA = enum(u16) {
    /// Unspecified routing attribute
    UNSPEC,
    /// Destination address
    DST,
    /// Source address
    SRC,
    /// Input interface
    IIF,
    /// Output interface
    OIF,
    /// Gateway address
    GATEWAY,
    /// Priority of the route
    PRIORITY,
    /// Preferred source address
    PREFSRC,
    /// Route metrics
    METRICS,
    /// Multipath information
    MULTIPATH,
    /// Protocol info (deprecated)
    PROTOINFO,
    /// Flow information
    FLOW,
    /// Cache information
    CACHEINFO,
    /// Session information (deprecated)
    SESSION,
    /// Multipath algorithm (deprecated)
    MP_ALGO,
    /// Routing table ID
    TABLE,
    /// Mark value
    MARK,
    /// Multicast forwarding cache stats
    MFC_STATS,
    /// Destination via another route
    VIA,
    /// New destination address
    NEWDST,
    /// Preference value
    PREF,
    /// Encapsulation type
    ENCAP_TYPE,
    /// Encapsulation data
    ENCAP,
    /// Expiration time
    EXPIRES,
    /// Padding
    PAD,
    /// User ID
    UID,
    /// TTL propagation
    TTL_PROPAGATE,
    /// IP protocol
    IP_PROTO,
    /// Source port
    SPORT,
    /// Destination port
    DPORT,
    /// Next-hop ID
    NH_ID,
};

/// Route Types
pub const RTN = enum(u8) {
    /// Unspecified route type
    UNSPEC,
    /// Gateway or direct route
    UNICAST,
    /// Accept locally
    LOCAL,
    /// Accept locally as broadcast, send as broadcast
    BROADCAST,
    /// Accept locally as broadcast, but send as unicast
    ANYCAST,
    /// Multicast route
    MULTICAST,
    /// Drop packets
    BLACKHOLE,
    /// Destination is unreachable
    UNREACHABLE,
    /// Administratively prohibited
    PROHIBIT,
    /// Not in this table
    THROW,
    /// Translate this address
    NAT,
    /// Use external resolver
    XRESOLVE,
    /// Maximum value for route types
    MAX,
};

/// Route Messages (RTM)
pub const RTM = enum(u16) {
    //BASE = 16,
    NEWLINK = 16,
    DELLINK = 17,
    GETLINK = 18,
    SETLINK = 19,
    NEWADDR = 20,
    DELADDR = 21,
    GETADDR = 22,
    NEWROUTE = 24,
    DELROUTE = 25,
    GETROUTE = 26,
    NEWNEIGH = 28,
    DELNEIGH = 29,
    GETNEIGH = 30,
    NEWRULE = 32,
    DELRULE = 33,
    GETRULE = 34,
    NEWQDISC = 36,
    DELQDISC = 37,
    GETQDISC = 38,
    NEWTCLASS = 40,
    DELTCLASS = 41,
    GETTCLASS = 42,
    NEWTFILTER = 44,
    DELTFILTER = 45,
    GETTFILTER = 46,
    NEWACTION = 48,
    DELACTION = 49,
    GETACTION = 50,
    NEWPREFIX = 52,
    GETMULTICAST = 58,
    GETANYCAST = 62,
    NEWNEIGHTBL = 64,
    GETNEIGHTBL = 66,
    SETNEIGHTBL = 67,
    NEWNSID = 68,
    DELNSID = 69,
    GETNSID = 70,
};
/// Route Message Flags (RTM_F)


/// Route Message Groups
pub const RTMGRP = enum(u32) {
    /// Multicast group for link layer (interface) events
    LINK = 1 << 0,
    /// Multicast group for IPv4 addresses
    IPV4_IFADDR = 1 << 1,
    /// Multicast group for IPv6 addresses
    IPV6_IFADDR = 1 << 2,
    /// Multicast group for IPv4 routing updates
    IPV4_ROUTE = 1 << 3,
    /// Multicast group for IPv6 routing updates
    IPV6_ROUTE = 1 << 4,
    /// Multicast group for notifications of IPv4 multicast routes
    IPV4_MROUTE = 1 << 5,
    /// Multicast group for notifications of IPv6 multicast routes
    IPV6_MROUTE = 1 << 6,
    /// Multicast group for IPv4 multicast membership changes
    NEIGH = 1 << 7,
    /// Multicast group for all network namespaces
    LISTEN_ALL_NSID = 1 << 8,
    /// Multicast group for notifications about network namespaces
    NSID = 1 << 9,
    /// Multicast group for IPv6 multicast membership changes
    IPV6_IFINFO = 1 << 10,
};

/// Interface Flags (IFF)
pub const IFF = enum(u32) {
    /// Interface is down
    DOWN = 0,
    /// Interface is up and running
    UP = 1 << 0,
    /// Broadcast address is valid
    BROADCAST = 1 << 1,
    /// Turn on debugging
    DEBUG = 1 << 2,
    /// Is a loopback net (e.g., `lo` interface)
    LOOPBACK = 1 << 3,
    /// Interface is point-to-point link
    POINTOPOINT = 1 << 4,
    /// Avoid using trailers
    NOTRAILERS = 1 << 5,
    /// Resources allocated and interface is running
    RUNNING = 1 << 6,
    /// No ARP protocol
    NOARP = 1 << 7,
    /// Receive all packets, not just those addressed to this interface
    PROMISC = 1 << 8,
    /// Receive all multicast packets
    ALLMULTI = 1 << 9,
    /// Master of a load balancer
    MASTER = 1 << 10,
    /// Slave of a load balancer
    SLAVE = 1 << 11,
    /// Supports multicast communication
    MULTICAST = 1 << 12,
    /// Can select the media type (e.g., Ethernet, Wi-Fi)
    PORTSEL = 1 << 13,
    /// Auto media selection active (automatically selects the best media)
    AUTOMEDIA = 1 << 14,
    /// Addresses are lost when the interface goes down
    DYNAMIC = 1 << 15,
    /// Indicates the driver signals that the link layer is up
    LOWER_UP = 1 << 16,
    /// Interface is in dormant state (not yet active but configured)
    DORMANT = 1 << 17,
    /// Echo link detection active
    ECHO = 1 << 18,
};

/// Interface Address Attributes
pub const IFA = enum(u16) {
    /// Unspecified
    UNSPEC = 0,
    /// Interface address
    ADDRESS = 1,
    /// Local address
    LOCAL = 2,
    /// Interface label
    LABEL = 3,
    /// Broadcast address
    BROADCAST = 4,
    /// Anycast address
    ANYCAST = 5,
    /// Cache information
    CACHEINFO = 6,
    /// Multicast address
    MULTICAST = 7,
    /// Address flags
    FLAGS = 8,
    /// Route priority/metric for prefix route
    RT_PRIORITY = 9,
    /// Target network namespace ID
    TARGET_NETNSID = 10,
    /// Address protocol
    PROTO = 11,

    /// Unknown Tag f/ Netlink Parsing
    __UNKNOWN__ = 64_000,
};

/// Interface Address Flags (IFA_F)
/// Address Flags
pub const IFA_F = enum(u32) {
    /// Secondary or Temporary address
    SECONDARY = 0x01,
    // TEMPORARY = 0x01, // Shared with SECONDARY
    /// No Duplicate Address Detection (DAD)
    NODAD = 0x02,
    /// Optimistic address (e.g., tentative)
    OPTIMISTIC = 0x04,
    /// Duplicate Address Detection failed
    DADFAILED = 0x08,
    /// Home address
    HOMEADDRESS = 0x10,
    /// Deprecated address
    DEPRECATED = 0x20,
    /// Tentative address
    TENTATIVE = 0x40,
    /// Permanent address
    PERMANENT = 0x80,
    /// Manage temporary addresses
    MANAGETEMPADDR = 0x100,
    /// No prefix route
    NOPREFIXROUTE = 0x200,
    /// Multicast auto-join
    MCAUTOJOIN = 0x400,
    /// Stable privacy address
    STABLE_PRIVACY = 0x800,
};

/// Interface Address Attributes
pub const InterfaceAddress = struct {
    pub const AttrE = IFA;

    /// Unspecified attribute.
    UNSPEC: ?[]const u8 = null,
    /// Interface address.
    ADDRESS: ?[4]u8 = null,
    /// Local (logical) address.
    LOCAL: ?[4]u8 = null,
    /// Interface name.
    LABEL: ?[]const u8 = null,
    /// Broadcast address.
    BROADCAST: ?[4]u8 = null,
    /// Anycast address.
    ANYCAST: ?[4]u8 = null,
    /// Cache information structure.
    CACHEINFO: ?[]const u8 = null,
    /// Multicast information.
    MULTICAST: ?[]const u8 = null,
    /// Flags for the interface address.
    FLAGS: ?u32 = null,
    /// Route priority/metric for prefix route.
    RT_PRIORITY: ?[]const u8 = null,
    /// Target network namespace ID.
    TARGET_NETNSID: ?[]const u8 = null,
    /// Address protocol.
    PROTO: ?[]const u8 = null,
};

/// Interface Link Attributes (IFLA)
pub const IFLA = enum(u16) {
    /// Unspecified attribute
    UNSPEC,
    /// Interface MAC address
    ADDRESS,
    /// Interface broadcast address
    BROADCAST,
    /// Interface name
    IFNAME,
    /// MTU size
    MTU,
    /// Link type
    LINK,
    /// Queueing discipline
    QDISC,
    /// Interface statistics
    STATS,
    /// Cost
    COST,
    /// Priority
    PRIORITY,
    /// Master interface
    MASTER,
    /// Wireless extensions (from wireless.h)
    WIRELESS,
    /// Protocol-specific information for a link
    PROTINFO,
    /// Transmit queue length
    TXQLEN,
    /// Device map
    MAP,
    /// Device weight
    WEIGHT,
    /// Operational state
    OPERSTATE,
    /// Link mode
    LINKMODE,
    /// Link information
    LINKINFO,
    /// Network namespace PID
    NET_NS_PID,
    /// Interface alias
    IFALIAS,
    /// Number of VFs if the device is SR-IOV PF
    NUM_VF,
    /// VF information list
    VFINFO_LIST,
    /// 64-bit interface statistics
    STATS64,
    /// VF ports
    VF_PORTS,
    /// Self port
    PORT_SELF,
    /// Address family-specific info
    AF_SPEC,
    /// Group the device belongs to
    GROUP,
    /// Network namespace file descriptor
    NET_NS_FD,
    /// Extended info mask, VFs, etc.
    EXT_MASK,
    /// Promiscuity count (>0 means acts PROMISC)
    PROMISCUITY,
    /// Number of TX queues
    NUM_TX_QUEUES,
    /// Number of RX queues
    NUM_RX_QUEUES,
    /// Carrier state
    CARRIER,
    /// Physical port ID
    PHYS_PORT_ID,
    /// Carrier changes
    CARRIER_CHANGES,
    /// Physical switch ID
    PHYS_SWITCH_ID,
    /// Link network namespace ID
    LINK_NETNSID,
    /// Physical port name
    PHYS_PORT_NAME,
    /// Protocol down state
    PROTO_DOWN,
    /// Maximum GSO segments
    GSO_MAX_SEGS,
    /// Maximum GSO size
    GSO_MAX_SIZE,
    /// Padding
    PAD,
    /// XDP (eXpress Data Path) info
    XDP,
    /// Event
    EVENT,
    /// New network namespace ID
    NEW_NETNSID,
    /// Interface network namespace ID
    /// Alias for TARGET_NETNSID
    IF_NETNSID,
    /// Carrier up count
    CARRIER_UP_COUNT,
    /// Carrier down count
    CARRIER_DOWN_COUNT,
    /// New interface index
    NEW_IFINDEX,
    /// Minimum MTU
    MIN_MTU,
    /// Maximum MTU
    MAX_MTU,
    /// Property list
    PROP_LIST,
    /// Alternative interface name
    ALT_IFNAME,
    /// Permanent address
    PERM_ADDRESS,
    /// Protocol down reason
    PROTO_DOWN_REASON,
    /// Parent device name
    PARENT_DEV_NAME,
    /// Parent device bus name
    PARENT_DEV_BUS_NAME,
    /// Maximum GRO size
    GRO_MAX_SIZE,
    /// Maximum TSO size
    TSO_MAX_SIZE,
    /// Maximum TSO segments
    TSO_MAX_SEGS,
    /// Allmulti count (>0 means acts ALLMULTI)
    ALLMULTI,
    /// Devlink port
    DEVLINK_PORT,
    /// Maximum GSO IPv4 size
    GSO_IPV4_MAX_SIZE,
    /// Maximum GRO IPv4 size
    GRO_IPV4_MAX_SIZE,
    /// DPLL pin
    DPLL_PIN,
    /// Maximum pacing offload horizon
    MAX_PACING_OFFLOAD_HORIZON,

    /// Unknown f/ Netlink Parsing
    __UNKNOWN__ = 64_000,
};


/// Interface Link 
pub const InterfaceLink = struct {
    pub const AttrE = IFLA;

    /// Unspecified attribute.
    UNSPEC: ?[]const u8 = null,
    /// Interface MAC address.
    ADDRESS: ?[6]u8 = null,
    /// Interface broadcast address.
    BROADCAST: ?[6]u8 = null,
    /// Interface name.
    IFNAME: ?[]const u8 = null,
    /// MTU size.
    MTU: u32,
    /// Link type
    LINK: ?u32 = null,
    /// Queueing discipline
    QDISC: ?[]const u8 = null,
    /// Interface statistics
    STATS: ?[]const u8 = null,
    /// Cost
    COST: ?u32 = null,
    /// Priority
    PRIORITY: ?u32 = null,
    /// Master interface
    MASTER: ?u32 = null,
    /// Wireless extensions (from wireless.h)
    WIRELESS: ?[]const u8 = null,
    /// Protocol-specific information for a link
    PROTINFO: ?[]const u8 = null,
    /// Transmit queue length
    TXQLEN: ?u32 = null,
    /// Device map
    MAP: ?[]const u8 = null,
    /// Device weight
    WEIGHT: ?u32 = null,
    /// Operational state
    OPERSTATE: ?u8 = null,
    /// Link mode
    LINKMODE: ?u8 = null,
    /// Link information
    LINKINFO: ?[]const u8 = null,
    /// Network namespace PID
    NET_NS_PID: ?u32 = null,
    /// Interface alias
    IFALIAS: ?[]const u8 = null,
    /// Number of VFs if the device is SR-IOV PF
    NUM_VF: ?u32 = null,
    /// VF information list
    VFINFO_LIST: ?[]const u8 = null,
    /// 64-bit interface statistics
    STATS64: ?[]const u8 = null,
    /// VF ports
    VF_PORTS: ?[]const u8 = null,
    /// Self port
    PORT_SELF: ?[]const u8 = null,
    /// Address family-specific info
    AF_SPEC: ?[]const u8 = null,
    /// Group the device belongs to
    GROUP: ?u32 = null,
    /// Network namespace file descriptor
    NET_NS_FD: ?u32 = null,
    /// Extended info mask, VFs, etc.
    EXT_MASK: ?u32 = null,
    /// Promiscuity count (>0 means acts PROMISC)
    PROMISCUITY: ?u32 = null,
    /// Number of TX queues
    NUM_TX_QUEUES: ?u32 = null,
    /// Number of RX queues
    NUM_RX_QUEUES: ?u32 = null,
    /// Carrier state
    CARRIER: ?u8 = null,
    /// Physical port ID
    PHYS_PORT_ID: ?[]const u8 = null,
    /// Carrier changes
    CARRIER_CHANGES: ?u32 = null,
    /// Physical switch ID
    PHYS_SWITCH_ID: ?[]const u8 = null,
    /// Link network namespace ID
    LINK_NETNSID: ?u32 = null,
    /// Physical port name
    PHYS_PORT_NAME: ?[]const u8 = null,
    /// Protocol down state
    PROTO_DOWN: ?u8 = null,
    /// Maximum GSO segments
    GSO_MAX_SEGS: ?u32 = null,
    /// Maximum GSO size
    GSO_MAX_SIZE: ?u32 = null,
    /// Padding
    PAD: ?[]const u8 = null,
    /// XDP (eXpress Data Path) info
    XDP: ?[]const u8 = null,
    /// Event
    EVENT: ?u32 = null,
    /// New network namespace ID
    NEW_NETNSID: ?u32 = null,
    /// Interface network namespace ID
    IF_NETNSID: ?u32 = null,
    /// Carrier up count
    CARRIER_UP_COUNT: ?u32 = null,
    /// Carrier down count
    CARRIER_DOWN_COUNT: ?u32 = null,
    /// New interface index
    NEW_IFINDEX: ?u32 = null,
    /// Minimum MTU
    MIN_MTU: ?u32 = null,
    /// Maximum MTU
    MAX_MTU: ?u32 = null,
    /// Property list
    PROP_LIST: ?[]const u8 = null,
    /// Alternative interface name
    ALT_IFNAME: ?[]const u8 = null,
    /// Permanent address
    PERM_ADDRESS: ?[6]u8 = null,
    /// Protocol down reason
    PROTO_DOWN_REASON: ?[]const u8 = null,
    /// Parent device name
    PARENT_DEV_NAME: ?[]const u8 = null,
    /// Parent device bus name
    PARENT_DEV_BUS_NAME: ?[]const u8 = null,
    /// Maximum GRO size
    GRO_MAX_SIZE: ?u32 = null,
    /// Maximum TSO size
    TSO_MAX_SIZE: ?u32 = null,
    /// Maximum TSO segments
    TSO_MAX_SEGS: ?u32 = null,
    /// Allmulti count (>0 means acts ALLMULTI)
    ALLMULTI: ?u32 = null,
    /// Devlink port
    DEVLINK_PORT: ?[]const u8 = null,
    /// Maximum GSO IPv4 size
    GSO_IPV4_MAX_SIZE: ?u32 = null,
    /// Maximum GRO IPv4 size
    GRO_IPV4_MAX_SIZE: ?u32 = null,
    /// DPLL pin
    DPLL_PIN: ?[]const u8 = null,
    /// Maximum pacing offload horizon
    MAX_PACING_OFFLOAD_HORIZON: ?u32 = null,
};

/// Operational states for network interfaces.
pub const IF_OPER = enum(u8) {
    /// Unknown operational state.
    UNKNOWN,
    /// Interface is operationally up.
    UP,
    /// Interface is not operationally up.
    DOWN,
    /// Interface is testing mode.
    TESTING,
    /// Interface is dormant.
    DORMANT,
    /// Interface is operationally lower-layer down.
    LOWERLAYERDOWN,
    /// Interface is not present.
    NOTPRESENT,
};


/// Scope of the Route
pub const RT_SCOPE = enum(u8) {
    /// Universal scope
    UNIVERSE = 0,
    /// Site-specific scope (user-defined)
    SITE = 200,
    /// Link-specific scope
    LINK = 253,
    /// Host-specific scope
    HOST = 254,
    /// Nowhere (invalid scope)
    NOWHERE = 255,
};

/// Routing Table (RT_TABLE) Classes
pub const RT_TABLE = enum(u8) {
    /// Unspecified routing table
    UNSPEC = 0,
    /// Compatibility routing table
    COMPAT = 252,
    /// Default routing table
    DEFAULT = 253,
    /// Main routing table
    MAIN = 254,
    /// Local routing table
    LOCAL = 255,
    ///// Maximum value for routing tables
    //MAX = 0xFFFFFFFF,
};

/// Routing Netlink Groups
pub const RTNLGRP = enum(u32) {
    NONE,
    LINK,
    NOTIFY,
    NEIGH,
    TC,
    IPV4_IFADDR,
    IPV4_MROUTE,
    IPV4_ROUTE,
    IPV4_RULE,
    IPV6_IFADDR,
    IPV6_MROUTE,
    IPV6_ROUTE,
    IPV6_IFINFO,
    DECnet_IFADDR,
    NOP2,
    DECnet_ROUTE,
    DECnet_RULE,
    NOP4,
    IPV6_PREFIX,
    IPV6_RULE,
    ND_USEROPT,
    PHONET_IFADDR,
    PHONET_ROUTE,
    DCB,
    IPV4_NETCONF,
    IPV6_NETCONF,
    MDB,
    MPLS_ROUTE,
    NSID,
    MPLS_NETCONF,
    IPV4_MROUTE_R,
    IPV6_MROUTE_R,
    NEXTHOP,
    BRVLAN,
    MCTP_IFADDR,
    TUNNEL,
    STATS,
    __RTNLGRP_MAX,
};

/// Route Protocol
pub const RTPROT = enum(u8) {
    /// non-route, used when new device is added
    UNSPEC = 0,
    /// route installed due to ICMP redirect
    REDIRECT = 1,
    /// route installed by kernel
    KERNEL = 2,
    /// route installed during boot
    BOOT = 3,
    /// route installed by administrator
    STATIC = 4,
    /// route installed by gated
    GATED = 8,
    /// route installed by Router Advertisement
    RA = 9,
    /// route installed by Merit MRT
    MRT = 10,
    /// route installed by Zebra/Quagga
    ZEBRA = 11,
    /// route installed by Bird
    BIRD = 12,
    /// route installed by DECnet routing daemon
    DNROUTED = 13,
    /// route installed by XORP
    XORP = 14,
    /// route installed by Netsukuku
    NTK = 15,
    /// route installed by DHCP
    DHCP = 16,
    /// route installed by multicast routing
    MROUTED = 17,
    /// route installed by Babel
    BABEL = 42,
    /// route installed by BGP
    BGP = 186,
    /// route installed by IS-IS
    ISIS = 187,
    /// route installed by OSPF
    OSPF = 188,
    /// route installed by RIP
    RIP = 189,
    /// route installed by EIGRP
    EIGRP = 192,
    _,
};

/// Request the Index of an Interface from the provided Interface Name (`if_name`).
pub fn requestIFIdx(alloc: mem.Allocator, req_ctx: *nl.io.RequestContext, if_name: []const u8) !void {
    try nl.io.request(
        alloc,
        RequestIFI,
        .{
            .nlh = .{
                .len = 0,
                .type = c(RTM).GETLINK,
                .flags = c(nl.NLM_F).REQUEST | c(nl.NLM_F).DUMP,
            },
            .msg = .{
                .family = nl.AF.PACKET,
                .index = 0,
                .flags = 0,
                .change = 0,
                .type = 0,
            },
        },
        &.{ .{ .hdr = .{ .type = c(nl.IFLA).IFNAME }, .data = if_name } },
        req_ctx,
    );
}
/// Get the Index of an Interface from the provided Interface Name (`if_name`).
/// This is a utility function that combines `requestIFIdx()` with Interface parsing.
/// Implicitly allocates double the message length to the stack.
pub fn getIfIdx(if_name: []const u8) !i32 {
    const buf_len = comptime mem.alignForward(usize, (RequestIFI.len + nl.attr_hdr_len + posix.IFNAMESIZE) * 2, 4);
    var req_buf: [buf_len]u8 = undefined;
    var fba = heap.FixedBufferAllocator.init(req_buf[0..]);
    var req_ctx: nl.io.RequestContext = try .init(.{ .conf = .{ .kind = nl.NETLINK.ROUTE } });
    try requestIFIdx(fba.allocator(), &req_ctx, if_name);
    defer posix.close(req_ctx.sock);
    var resp_idx: usize = 0;
    while (resp_idx <= 10) : (resp_idx += 1) {
        var resp_buf: [4096]u8 = undefined;
        const resp_len = posix.recv(
            req_ctx.sock,
            resp_buf[0..],
            0,
        ) catch |err| switch (err) {
            error.WouldBlock => return error.NoInterfaceFound,
            else => return err,
        };
        var offset: usize = 0;
        while (offset < resp_len) {
            var start: usize = offset;
            var end: usize = (offset + @sizeOf(nl.MessageHeader));
            const nl_resp_hdr: *nl.MessageHeader = mem.bytesAsValue(nl.MessageHeader, resp_buf[start..end]);
            if (nl_resp_hdr.len < @sizeOf(nl.MessageHeader))
                return error.InvalidMessage;
            if (nl_resp_hdr.type == c(nl.NLMSG).ERROR) {
                start = end;
                end += @sizeOf(nl.ErrorHeader);
                const nl_err: nl.ErrorHeader = mem.bytesToValue(nl.ErrorHeader, resp_buf[start..end]);
                switch (posix.errno(@as(isize, @intCast(nl_err.err)))) {
                    .SUCCESS => {},
                    .BUSY => return error.BUSY,
                    else => |err| {
                        log.err("OS Error: ({d}) {s}", .{ nl_err.err, @tagName(err) });
                        return error.OSError;
                    },
                }
            }
            if (nl_resp_hdr.type == c(RTM).NEWLINK) ifi: {
                start = end;
                end += @sizeOf(os.linux.ifinfomsg);
                const ifi: InterfaceInfoMessage = mem.bytesToValue(InterfaceInfoMessage, resp_buf[start..end]);
                start = end;
                end += @sizeOf(nl.AttributeHeader);
                const _attr: nl.AttributeHeader = mem.bytesAsValue(nl.AttributeHeader, resp_buf[start..end]);
                if (@as(nl.IFLA, @enumFromInt(_attr.type)) != .IFNAME) break :ifi;
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

/// Interface Link w/ Interface Info
pub const IFInfoAndLink = struct {
    info: InterfaceInfoMessage,
    link: InterfaceLink,
};
/// Request an Interface Link from the provided Interface (`if_index`).
pub fn requestIFLink(alloc: mem.Allocator, req_ctx: *nl.io.RequestContext, if_index: i32) !void {
    try nl.io.request(
        alloc,
        RequestIFI,
        .{
            .nlh = .{
                .len = 0,
                .type = c(RTM).GETLINK,
                .flags = c(nl.NLM_F).REQUEST,
            },
            .msg = .{
                .family = nl.AF.UNSPEC,
                .index = if_index,
                .type = 0,
                .change = 0,
                .flags = 0,
            },
        },
        &.{},
        req_ctx,
    );
}
/// Request All Interface Links w/ their Interface Info.
pub fn requestAllIFLinks(alloc: mem.Allocator, req_ctx: *nl.io.RequestContext) !void {
    try nl.io.request(
        alloc,
        nl.RequestRaw,
        .{
            .nlh = .{
                .len = 20,
                .type = c(RTM).GETLINK,
                .flags = c(nl.NLM_F).REQUEST | c(nl.NLM_F).REPLACE | c(nl.NLM_F).EXCL,
            },
            .msg = 0,
        },
        &.{},
        req_ctx,
    );
}
/// Get an Interface Link from the provided Interface (`if_index`).
pub fn getIFLink(alloc: mem.Allocator, if_index: i32) !InterfaceLink {
    // Request
    var req_ctx: nl.io.RequestContext = try .init(.{ .conf = .{ .kind = nl.NETLINK.ROUTE } });
    try requestIFLink(alloc, &req_ctx, if_index);
    defer posix.close(req_ctx.sock);
    // Response
    var resp_buf: [4096]u8 = undefined;
    const resp_len = posix.recv(
        req_ctx.sock,
        resp_buf[0..],
        0,
    ) catch |err| switch (err) {
        error.WouldBlock => return error.NoInterfaceFound,
        else => return err,
    };
    // Parse Message Header
    var start: usize = 0;
    var end: usize = @sizeOf(nl.MessageHeader);
    const nl_resp_hdr = mem.bytesAsValue(nl.MessageHeader, resp_buf[start..end]);
    if (nl_resp_hdr.len < @sizeOf(nl.MessageHeader))
        return error.InvalidMessage;
    if (nl_resp_hdr.type == c(nl.NLMSG).ERROR) {
        start = end;
        end += @sizeOf(nl.ErrorHeader);
        const nl_err = mem.bytesAsValue(nl.ErrorHeader, resp_buf[start..end]);
        switch (posix.errno(@as(isize, @intCast(nl_err.err)))) {
            .SUCCESS => {},
            .BUSY => return error.BUSY,
            else => |err| {
                log.err("OS Error: ({d}) {s}", .{ nl_err.err, @tagName(err) });
                return error.OSError;
            },
        }
    }
    // Parse Interface Link
    if (nl_resp_hdr.type != c(RTM).NEWLINK) return error.NonIFLinkResponse;
    start = end + @sizeOf(InterfaceInfoMessage);
    end = resp_len;
    return try nl.parse.fromBytes(alloc, InterfaceLink, resp_buf[start..end]);
}
/// Get All Interface Links w/ their Interface Info.
pub fn getAllIFLinks(alloc: mem.Allocator) ![]const IFInfoAndLink {
    // Request
    var req_ctx: nl.io.RequestContext = try .init(.{ .conf = .{ .kind = nl.NETLINK.ROUTE } });
    try requestAllIFLinks(alloc, &req_ctx);
    defer posix.close(req_ctx.sock);
    // Response
    const buf_size: u32 = 64_000;
    try posix.setsockopt(
        req_ctx.sock, 
        posix.SOL.SOCKET, 
        nl.NETLINK_OPT.RX_RING, 
        mem.toBytes(buf_size)[0..],
    );
    return try handleIFLinksSock(alloc, req_ctx.sock);
}
/// Parse the given `data` into an `IFInfoAndLink`.
pub fn parseIFInfoAndLink(alloc: mem.Allocator, data: []const u8) !IFInfoAndLink {
    const info = try nl.parse.fromBytes(alloc, InterfaceInfoMessage, data[0..@sizeOf(InterfaceInfoMessage)]);
    const link = try nl.parse.fromBytes(alloc, InterfaceLink, data[@sizeOf(InterfaceInfoMessage)..]);
    return .{ .info = info, .link = link };
}
/// Handle Interface Links and Info on the provided `msg_buf`.
pub fn handleIFLinksBuf(alloc: mem.Allocator, msg_buf: []const u8) ![]const IFInfoAndLink {
    var handle_ctx: nl.parse.HandleContext = .{ .config = .{ .nl_type = c(RTM).NEWLINK } };
    return try nl.parse.handleTypeBuf(
        alloc,
        msg_buf,
        RequestIFI,
        IFInfoAndLink,
        parseIFInfoAndLink,
        &handle_ctx,
    );
}
/// Handle Interface Links and Info on the provided Netlink Socket (`nl_sock`).
pub fn handleIFLinksSock(alloc: mem.Allocator, nl_sock: posix.socket_t) ![]IFInfoAndLink {
    return try nl.parse.handleTypeSock(
        alloc,
        nl_sock,
        RequestIFI,
        IFInfoAndLink,
        parseIFInfoAndLink,
        .{ .nl_type = c(RTM).NEWLINK },
    );
}

/// Interface Address w/ Interface Info
pub const IFInfoAndAddr = struct {
    info: InterfaceAddressMessage,
    addr: InterfaceAddress,
};
/// Request the Interface IP Address for the provided Interface (`if_index`)
pub fn requestIFAddr(alloc: mem.Allocator, req_ctx: *nl.io.RequestContext, if_index: i32) !void {
    try nl.io.request(
        alloc,
        RequestIFI,
        .{
            .nlh = .{
                .len = 0,
                .type = c(RTM).GETADDR,
                .flags = c(nl.NLM_F).REQUEST,
            },
            .msg = .{
                .family = nl.AF.UNSPEC,
                .index = if_index,
                .type = 0,
                .change = 0,
                .flags = 0,
            },
        },
        &.{},
        req_ctx,
    );
}
/// Request All Interface Addresses w/ their Interface Info
pub fn requestAllIFAddrs(alloc: mem.Allocator, req_ctx: *nl.io.RequestContext) !void {
    try nl.io.request(
        alloc,
        nl.RequestRaw,
        .{
            .nlh = .{
                .len = 20,
                .type = c(RTM).GETADDR,
                .flags = c(nl.NLM_F).REQUEST | c(nl.NLM_F).REPLACE | c(nl.NLM_F).EXCL,
            },
            .msg = 0,
        },
        &.{},
        req_ctx,
    );
}
/// Get the Interface IP Addresses for the provided Interface (`if_index`).
pub fn getIFAddr(alloc: mem.Allocator, if_index: i32) ![]const IFInfoAndAddr {
    var req_ctx: nl.io.RequestContext = try .init(.{ .conf = .{ .kind = nl.NETLINK.ROUTE } });
    try requestIFAddr(alloc, &req_ctx, if_index);
    defer posix.close(req_ctx.sock);
    return try handleIFAddrsSock(alloc, req_ctx.sock);
}
/// Get All Interface Addresses w/ their Interface Info
pub fn getAllIFAddrs(alloc: mem.Allocator) ![]const IFInfoAndAddr {
    var req_ctx: nl.io.RequestContext = try .init(.{ .conf = .{ .kind = nl.NETLINK.ROUTE } });
    try requestAllIFAddrs(alloc, &req_ctx);
    defer posix.close(req_ctx.sock);
    return try handleIFAddrsSock(alloc, req_ctx.sock);
}
/// Parse the given `data` into an `IFInfoAndAddr`.
pub fn parseIFInfoAndAddr(alloc: mem.Allocator, data: []const u8) !IFInfoAndAddr {
    const info = try nl.parse.fromBytes(alloc, InterfaceAddressMessage, data[0..@sizeOf(InterfaceAddressMessage)]);
    const addr = try nl.parse.fromBytes(alloc, InterfaceAddress, data[@sizeOf(InterfaceAddressMessage)..]);
    return .{ .info = info, .addr = addr };
}
/// Handle Interface Address Responses from the provided `msg_buf`.
pub fn handleIFAddrsBuf(alloc: mem.Allocator, msg_buf: []const u8) ![]const IFInfoAndAddr {
    var handle_ctx: nl.parse.HandleContext = .{ .config = .{ .nl_type = c(RTM).NEWADDR } };
    return try nl.parse.handleTypeBuf(
        alloc,
        msg_buf,
        RequestIFA,
        IFInfoAndAddr,
        parseIFInfoAndAddr,
        &handle_ctx,
    );
}
/// Handle Interface Address Responses on the provided `nl_sock`.
pub fn handleIFAddrsSock(alloc: mem.Allocator, nl_sock: posix.socket_t) ![]const IFInfoAndAddr {
    return try nl.parse.handleTypeSock(
        alloc,
        nl_sock,
        RequestIFA,
        IFInfoAndAddr,
        parseIFInfoAndAddr,
        .{ .nl_type = c(RTM).NEWADDR },
    );
}

/// Request that the provided Interface (`if_index`) be Set to the Up or Down State (`state`).
pub fn requestSetState(
    alloc: mem.Allocator, 
    req_ctx: *nl.io.RequestContext, 
    if_index: i32,
    state: u32,
) !void {
    try nl.io.request(
        alloc,
        RequestIFI,
        .{
            .nlh = .{
                .len = 0,
                .type = c(RTM).SETLINK,
                .flags = c(nl.NLM_F).REQUEST | c(nl.NLM_F).ACK,
            },
            .msg = .{
                .family = nl.AF.UNSPEC,
                .index = if_index,
                .change = 0xFFFFFFFF,
                .flags = state,
                .type = 0,
            },
        },
        &.{},
        req_ctx,
    );
}
/// Set the provided Interface (`if_index`) to the Up or Down State (`state`).
/// Implicitly allocates double the message length to the stack.
pub fn setState(if_index: i32, state: u32) !void {
    const buf_len = comptime mem.alignForward(usize, (RequestIFI.len + nl.attr_hdr_len + 4) * 2, 4);
    var req_buf: [buf_len]u8 = undefined;
    var fba: heap.FixedBufferAllocator = .init(req_buf[0..]);
    var req_ctx: nl.io.RequestContext = try .init(.{ .conf = .{ .kind = nl.NETLINK.ROUTE } });
    try requestSetState(fba.allocator(), &req_ctx, if_index, state);
    defer posix.close(req_ctx.sock);
    try nl.parse.handleAckSock(req_ctx.sock);
}

/// Request that the provided Interface (`if_index`) be given the provided MAC (`mac`).
pub fn requestSetMAC(
    alloc: mem.Allocator,
    req_ctx: *nl.io.RequestContext,
    if_index: i32,
    mac: [6]u8,
) !void {
    try nl.io.request(
        alloc,
        RequestIFI,
        .{
            .nlh = .{
                .type = c(RTM).NEWLINK,
                .flags = c(nl.NLM_F).REQUEST | c(nl.NLM_F).ACK,
            },
            .msg = .{
                .family = nl.AF.UNSPEC,
                .index = if_index,
                .change = 0,
                .flags = 0,
                .type = 0,
            },
        },
        &.{ .{ .hdr = .{ .type = c(nl.IFLA).ADDRESS }, .data = mac[0..] } },
        req_ctx,
    );
}
/// Set the MAC (`mac`) of the provided Interface (`if_index`).
/// Implicitly allocates double the message length to the stack.
pub fn setMAC(if_index: i32, mac: [6]u8) !void {
    const buf_len = comptime mem.alignForward(usize, (RequestIFI.len + nl.attr_hdr_len + 6) * 2, 4);
    var req_buf: [buf_len]u8 = undefined;
    var fba: heap.FixedBufferAllocator = .init(req_buf[0..]);
    var req_ctx: nl.io.RequestContext = try .init(.{ .conf = .{ .kind = nl.NETLINK.ROUTE } });
    //try setState(if_index, c(IFF).DOWN);
    try requestSetMAC(
        fba.allocator(), 
        &req_ctx, 
        if_index, 
        mac
    );
    defer posix.close(req_ctx.sock);
    try nl.parse.handleAckSock(req_ctx.sock);
    //try setState(if_index, c(IFF).UP);
}


/// Request to Add IP address (`ip`) to the Interface (`if_index`)
pub fn requestAddIP(
    alloc: mem.Allocator,
    req_ctx: *nl.io.RequestContext,
    if_index: i32,
    ip: [4]u8,
    prefix_len: u8,
) !void {
    const flags = c(IFA_F).PERMANENT;
    try nl.io.request(
        alloc,
        RequestIFA,
        .{
            .nlh = .{
                .len = 0,
                .type = c(RTM).NEWADDR,
                .flags = c(nl.NLM_F).REQUEST | c(nl.NLM_F).ACK | c(nl.NLM_F).EXCL,
            },
            .msg = .{
                .family = nl.AF.INET,
                .prefix_len = prefix_len,
                .flags = @intCast(flags & 0xFF),
                .scope = c(RT_SCOPE).UNIVERSE,
                .index = if_index,
            },
        },
        &.{
            .{
                .hdr = .{ .type = c(IFA).LOCAL },
                .data = &ip,
            },
            .{
                .hdr = .{ .type = c(IFA).FLAGS },
                .data = mem.toBytes(flags)[0..],
            },
        },
        req_ctx,
    );
}
/// Add IP address (`ip`) to the Interface (`if_index`)
pub fn addIP(
    alloc: mem.Allocator,
    if_index: i32,
    ip: [4]u8,
    prefix_len: u8,
) !void {
    var req_ctx: nl.io.RequestContext = try .init(.{ .conf = .{ .kind = nl.NETLINK.ROUTE } });
    try requestAddIP(alloc, &req_ctx, if_index, ip, prefix_len);
    defer posix.close(req_ctx.sock);
    try nl.parse.handleAckSock(req_ctx.sock);
}

/// Request to Delete IP address from Interface (`if_index`)
pub fn requestDeleteIP(
    alloc: mem.Allocator,
    req_ctx: *nl.io.RequestContext,
    if_index: i32,
    ip: [4]u8,
    prefix_len: u8,
) !void {
    try nl.io.request(
        alloc,
        RequestIFA,
        .{
            .nlh = .{
                .len = 0,
                .type = c(RTM).DELADDR,
                .flags = c(nl.NLM_F).REQUEST | c(nl.NLM_F).ACK,
            },
            .msg = .{
                .family = nl.AF.INET,
                .prefix_len = prefix_len,
                .flags = 0,
                .scope = c(RT_SCOPE).UNIVERSE,
                .index = if_index,
            },
        },
        &.{
            .{
                .hdr = .{ .type = c(IFA).LOCAL },
                .data = &ip,
            },
        },
        req_ctx,
    );

}
/// Delete IP address from Interface (`if_index`)
pub fn deleteIP(
    alloc: mem.Allocator,
    if_index: i32,
    ip: [4]u8,
    prefix_len: u8,
) !void {
    var req_ctx: nl.io.RequestContext = try .init(.{ .conf = .{ .kind = nl.NETLINK.ROUTE } });
    try requestDeleteIP(alloc, &req_ctx, if_index, ip, prefix_len);
    defer posix.close(req_ctx.sock);
    try nl.parse.handleAckSock(req_ctx.sock);
}

/// Route Config
pub const RouteConfig = struct {
    cidr: u8 = 24,
    gateway: ?[4]u8 = null,
};

/// Request to Add the Route Destination (`dest`) to the provided Interface's (`if_index`) routing table
pub fn requestAddRoute(
    alloc: mem.Allocator,
    req_ctx: *nl.io.RequestContext,
    if_index: i32,
    dest: [4]u8,
    config: RouteConfig,
) !void {
    var attrs: ArrayList(nl.Attribute) = .empty;
    defer attrs.deinit(alloc);
    // Always add destination network
    try attrs.append(alloc, .{
        .hdr = .{ .type = c(RTA).DST },
        .data = &dest,
    });
    // Add gateway if provided
    if (config.gateway) |gw| {
        try attrs.append(alloc, .{
            .hdr = .{ .type = c(RTA).GATEWAY },
            .data = &gw,
        });
    }
    // Add output interface
    try attrs.append(alloc, .{
        .hdr = .{ .type = c(RTA).OIF },
        .data = mem.toBytes(if_index)[0..],
    });
    try nl.io.request(
        alloc,
        RequestRTM,
        .{
            .nlh = .{
                .len = 0,
                .type = c(RTM).NEWROUTE,
                .flags = c(nl.NLM_F).REQUEST | c(nl.NLM_F).ACK | c(nl.NLM_F).CREATE | c(nl.NLM_F).EXCL,
            },
            .msg = .{
                .family = nl.AF.INET,
                .dst_len = config.cidr,
                .src_len = 0,
                .tos = 0,
                .table = c(RT_TABLE).MAIN,
                .protocol = c(RTPROT).BOOT,
                .scope = if (config.gateway != null) c(RT_SCOPE).UNIVERSE else c(RT_SCOPE).LINK,
                .type = c(RTN).UNICAST,
                .flags = 0,
            },
        },
        attrs.items,
        req_ctx,
    );
}
/// Add the Route Destination (`dest`) to the provided Interface's (`if_index`) routing table
pub fn addRoute(
    alloc: mem.Allocator,
    if_index: i32,
    dest: [4]u8,
    config: RouteConfig,
) !void {
    var req_ctx: nl.io.RequestContext = try .init(.{ .conf = .{ .kind = nl.NETLINK.ROUTE } });
    try requestAddRoute(alloc, &req_ctx, if_index, dest, config);
    defer posix.close(req_ctx.sock);
    try nl.parse.handleAckSock(req_ctx.sock);
}

/// Request the Delete the Route Destination (`dest`) from the provided Interface's (`if_index`) routing table
pub fn requestDeleteRoute(
    alloc: mem.Allocator,
    req_ctx: *nl.io.RequestContext,
    if_index: i32,
    dest: [4]u8,
    config: RouteConfig,
) !void {
    var attrs: ArrayList(nl.Attribute) = .empty;
    defer attrs.deinit(alloc);
    // Always add destination network
    try attrs.append(alloc, .{
        .hdr = .{ .type = c(RTA).DST },
        .data = &dest,
    });
    // Add gateway if provided
    if (config.gateway) |gw| {
        try attrs.append(alloc, .{
            .hdr = .{ .type = c(RTA).GATEWAY },
            .data = &gw,
        });
    }
    // Add output interface
    try attrs.append(alloc, .{
        .hdr = .{ .type = c(RTA).OIF },
        .data = mem.toBytes(if_index)[0..],
    });
    try nl.io.request(
        alloc,
        RequestRTM,
        .{
            .nlh = .{
                .len = 0,
                .type = c(RTM).DELROUTE,
                .flags = c(nl.NLM_F).REQUEST | c(nl.NLM_F).ACK,
            },
            .msg = .{
                .family = nl.AF.INET,
                .dst_len = config.cidr,
                .src_len = 0,
                .tos = 0,
                .table = c(RT_TABLE).MAIN,
                .protocol = c(RTPROT).BOOT,
                .scope = if (config.gateway != null) c(RT_SCOPE).UNIVERSE else c(RT_SCOPE).LINK,
                .type = c(RTN).UNICAST,
                .flags = 0,
            },
        },
        attrs.items,
        req_ctx,
    );
}
/// Delete the Route Destination (`dest`) from the provided Interface's (`if_index`) routing table
pub fn deleteRoute(
    alloc: mem.Allocator,
    if_index: i32,
    dest: [4]u8,
    config: RouteConfig,
) !void {
    var req_ctx: nl.io.RequestContext = try .init(.{ .conf = .{ .kind = nl.NETLINK.ROUTE } });
    try requestDeleteRoute(alloc, &req_ctx, if_index, dest, config);
    defer posix.close(req_ctx.sock);
    try nl.parse.handleAckSock(req_ctx.sock);
}
