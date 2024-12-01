//! Basic Netlink Route (rtnetlink) Functions

const std = @import("std");
const fmt = std.fmt;
const heap = std.heap;
const json = std.json;
const log = std.log;
const math = std.math;
const mem = std.mem;
const os = std.os;
const posix = std.posix;

const nl = @import("../nl.zig");
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
pub const InterfaceAddress = extern struct {
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
pub const RequestIFA = nl.Request(InterfaceAddress);
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
   _,
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

const IFNAMESIZE = posix.IFNAMESIZE;


/// Get the Index of an Interface from the provided Interface Name (`if_name`).
/// Implicitly allocates double the message length to the stack.
pub fn getIfIdx(if_name: []const u8) !i32 {
    const buf_len = comptime mem.alignForward(usize, (RequestIFI.len + nl.attr_hdr_len + IFNAMESIZE) * 2, 4);
    var req_buf: [buf_len]u8 = .{ 0 } ** buf_len;
    var fba = heap.FixedBufferAllocator.init(req_buf[0..]);
    const nl_sock = try nl.request(
        fba.allocator(),
        nl.NETLINK.ROUTE,
        RequestIFI,
        .{
            .nlh = .{
                .len = 0,
                .type = c(RTM).GETLINK,
                .flags = c(nl.NLM_F).REQUEST | c(nl.NLM_F).DUMP,
                .seq = 12321,
                .pid = 0,
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
            var end: usize = (offset + @sizeOf(nl.MessageHeader));
            const nl_resp_hdr: *nl.MessageHeader = @alignCast(@ptrCast(resp_buf[start..end]));
            if (nl_resp_hdr.len < @sizeOf(nl.MessageHeader))
                return error.InvalidMessage;
            if (nl_resp_hdr.type == c(nl.NLMSG).ERROR) {
                start = end;
                end += @sizeOf(nl.ErrorHeader);
                const nl_err: *nl.ErrorHeader = @alignCast(@ptrCast(resp_buf[start..end]));
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
                const ifi: *const InterfaceInfoMessage = @alignCast(@ptrCast(resp_buf[start..end]));
                start = end;
                end += @sizeOf(nl.AttributeHeader);
                const _attr: *const nl.AttributeHeader = @alignCast(@ptrCast(resp_buf[start..end]));
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

/// Set the provided Interface (`if_index`) to the Up or Down State (`state`).
/// Implicitly allocates double the message length to the stack.
pub fn setState(if_index: i32, state: u32) !void {
    const buf_len = comptime mem.alignForward(usize, (RequestIFI.len + nl.attr_hdr_len + 4) * 2, 4);
    var req_buf: [buf_len]u8 = .{ 0 } ** buf_len;
    var fba = heap.FixedBufferAllocator.init(req_buf[0..]);
    const nl_sock = try nl.request(
        fba.allocator(),
        nl.NETLINK.ROUTE,
        RequestIFI,
        .{
            .nlh = .{
                .len = 0,
                .type = c(RTM).SETLINK,
                .flags = c(nl.NLM_F).REQUEST | c(nl.NLM_F).ACK,
                .seq = 12321,
                .pid = 0,
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
    );
    defer posix.close(nl_sock);
    try nl.handleAck(nl_sock);
}

/// Set the MAC (`mac`) of the provided Interface (`if_index`).
/// Implicitly allocates double the message length to the stack.
pub fn setMAC(if_index: i32, mac: [6]u8) !void {
    const buf_len = comptime mem.alignForward(usize, (RequestIFI.len + nl.attr_hdr_len + 6) * 2, 4);
    var req_buf: [buf_len]u8 = .{ 0 } ** buf_len;
    var fba = heap.FixedBufferAllocator.init(req_buf[0..]);
    try setState(if_index, c(IFF).DOWN);
    const nl_sock = try nl.request(
        fba.allocator(),
        nl.NETLINK.ROUTE,
        RequestIFI,
        .{
            .nlh = .{
                .type = c(RTM).NEWLINK,
                .flags = c(nl.NLM_F).REQUEST | c(nl.NLM_F).ACK,
                .seq = 12321,
                .pid = 0,
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
    );
    defer posix.close(nl_sock);
    try nl.handleAck(nl_sock);
    try setState(if_index, c(IFF).UP);
}

/// Add IP address to interface
pub fn addIP(
    alloc: mem.Allocator,
    if_index: i32,
    ip: [4]u8,
    prefix_len: u8,
) !void {
    const flags = c(IFA_F).PERMANENT;
    const nl_sock = try nl.request(
        alloc,
        nl.NETLINK.ROUTE,
        RequestIFA,
        .{
            .nlh = .{
                .len = 0,
                .type = c(RTM).NEWADDR,
                .flags = c(nl.NLM_F).REQUEST | c(nl.NLM_F).ACK | c(nl.NLM_F).EXCL,
                .seq = 12321,
                .pid = 0,
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
    );
    defer posix.close(nl_sock);
    try nl.handleAck(nl_sock);
}

/// Delete IP address from interface
pub fn deleteIP(
    alloc: mem.Allocator,
    if_index: i32,
    ip: [4]u8,
    prefix_len: u8,
) !void {
    const nl_sock = try nl.request(
        alloc,
        nl.NETLINK.ROUTE,
        RequestIFA,
        .{
            .nlh = .{
                .len = 0,
                .type = c(RTM).DELADDR,
                .flags = c(nl.NLM_F).REQUEST | c(nl.NLM_F).ACK,
                .seq = 12321,
                .pid = 0,
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
    );
    defer posix.close(nl_sock);
    try nl.handleAck(nl_sock);
}

/// Route Config
pub const RouteConfig = struct {
    cidr: u8 = 24,
    gateway: ?[4]u8 = null,
};
/// Add route to routing table
pub fn addRoute(
    alloc: mem.Allocator,
    if_index: i32,
    dest: [4]u8,
    config: RouteConfig,
) !void {
    var attrs = std.ArrayListUnmanaged(nl.Attribute){};
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
    const nl_sock = try nl.request(
        alloc,
        nl.NETLINK.ROUTE,
        RequestRTM,
        .{
            .nlh = .{
                .len = 0,
                .type = c(RTM).NEWROUTE,
                .flags = c(nl.NLM_F).REQUEST | c(nl.NLM_F).ACK | c(nl.NLM_F).CREATE | c(nl.NLM_F).EXCL,
                .seq = 12321,
                .pid = 0,
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
    );
    defer posix.close(nl_sock);
    try nl.handleAck(nl_sock);
}

/// Delete route from routing table
pub fn deleteRoute(
    alloc: mem.Allocator,
    if_index: i32,
    dest: [4]u8,
    config: RouteConfig,
) !void {
    var attrs = std.ArrayListUnmanaged(nl.Attribute){};
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
    const nl_sock = try nl.request(
        alloc,
        nl.NETLINK.ROUTE,
        RequestRTM,
        .{
            .nlh = .{
                .len = 0,
                .type = c(RTM).DELROUTE,
                .flags = c(nl.NLM_F).REQUEST | c(nl.NLM_F).ACK,
                .seq = 12321,
                .pid = 0,
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
    );
    defer posix.close(nl_sock);
    try nl.handleAck(nl_sock);
}

/// Device Info. Simple Struct for common Device data from rtnetlink 
pub const DeviceInfo = struct {
    index: i32,
    mac: [6]u8,
    mtu: usize,
    ips: [10]?[4]u8 = .{ null } ** 10,

    pub fn get(if_index: i32) !@This() {
        var dev: @This() = undefined;
        dev.index = if_index;
        dev.ips = .{ null } ** 10;

        const l2_buf_len = comptime mem.alignForward(usize, (RequestIFI.len + nl.attr_hdr_len + 6) * 2, 4);
        var l2_req_buf: [l2_buf_len]u8 = .{ 0 } ** l2_buf_len;
        var l2_fba = heap.FixedBufferAllocator.init(l2_req_buf[0..]);
        const l2_sock = try nl.request(
            l2_fba.allocator(),
            nl.NETLINK.ROUTE,
            RequestIFI,
            .{
                .nlh = .{
                    .len = 0,
                    .type = c(RTM).GETLINK,
                    .flags = c(nl.NLM_F).REQUEST,
                    .seq = 12321,
                    .pid = 0,
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
        );
        defer posix.close(l2_sock);

        var set_count: u8 = 0;
        var resp_buf: [4096]u8 = .{ 0 } ** 4096;
        var resp_len = posix.recv(
            l2_sock,
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
            const nl_resp_hdr: *const nl.MessageHeader = @alignCast(@ptrCast(resp_buf[start..end]));
            if (nl_resp_hdr.len < @sizeOf(nl.MessageHeader))
                return error.InvalidMessage;
            if (nl_resp_hdr.type == c(nl.NLMSG).ERROR) {
                start = end;
                end += @sizeOf(nl.ErrorHeader);
                const nl_err: *nl.ErrorHeader = @alignCast(@ptrCast(resp_buf[start..end]));
                switch (posix.errno(@as(isize, @intCast(nl_err.err)))) {
                    .SUCCESS => {},
                    .BUSY => return error.BUSY,
                    else => |err| {
                        log.err("OS Error: ({d}) {s}", .{ nl_err.err, @tagName(err) });
                        return error.OSError;
                    },
                }
            }
            if (nl_resp_hdr.type == c(RTM).NEWLINK) {
                start = end + @sizeOf(InterfaceInfoMessage);
                end += @sizeOf(InterfaceInfoMessage) + nl.attr_hdr_len;
                while (end < offset + nl_resp_hdr.len) {
                    const attr: *const nl.AttributeHeader = @alignCast(@ptrCast(resp_buf[start..end]));
                    start = end;
                    end += (attr.len -| nl.attr_hdr_len);
                    switch (@as(nl.IFLA, @enumFromInt(attr.type))) {
                        .ADDRESS => {
                            @memcpy(dev.mac[0..], resp_buf[start..start + 6]);
                            set_count += 1;
                        },
                        .MTU => {
                            dev.mtu = @as(*const u32, @alignCast(@ptrCast(resp_buf[start..start + 4]))).*;
                            set_count += 1;
                        },
                        else => {}
                    }
                    end = mem.alignForward(usize, end, 4);
                    start = end;
                    end += nl.attr_hdr_len;
                }
            }
            offset += mem.alignForward(usize, nl_resp_hdr.len, 4);
        }
        if (set_count < 2) return error.DetailsNotProvided;

        const l3_buf_len = comptime mem.alignForward(usize, (RequestIFA.len + nl.attr_hdr_len + 6) * 2, 4);
        var l3_req_buf: [l3_buf_len]u8 = .{ 0 } ** l3_buf_len;
        var l3_fba = heap.FixedBufferAllocator.init(l3_req_buf[0..]);
        const l3_sock = try nl.request(
            l3_fba.allocator(),
            nl.NETLINK.ROUTE,
            RequestIFA,
            .{
                .nlh = .{
                    .len = 0,
                    .type = c(RTM).GETADDR,
                    .flags = c(nl.NLM_F).REQUEST | c(nl.NLM_F).DUMP,
                    .seq = 12321,
                    .pid = 0,
                },
                .msg = .{
                    .family = nl.AF.INET,
                    .index = if_index,
                    .prefix_len = 24,
                    .scope = 0,
                    .flags = 0,
                },
            },
            &.{},
        );
        defer posix.close(l3_sock);

        var resp_idx: usize = 0;
        respL3: while (resp_idx <= 10) : (resp_idx += 1) {
            resp_buf = .{ 0 } ** 4096;
            resp_len = posix.recv(
                l3_sock,
                resp_buf[0..],
                0,
            ) catch |err| switch (err) {
                error.WouldBlock => break,
                else => return err,
            };

            offset = 0;
            while (offset < resp_len) {
                var start: usize = offset;
                var end: usize = (offset + @sizeOf(nl.MessageHeader));
                const nl_resp_hdr: *const nl.MessageHeader = @alignCast(@ptrCast(resp_buf[start..end]));
                if (nl_resp_hdr.len < @sizeOf(nl.MessageHeader))
                    return error.InvalidMessage;
                if (nl_resp_hdr.type == c(nl.NLMSG).ERROR) {
                    start = end;
                    end += @sizeOf(nl.ErrorHeader);
                    const nl_err: *nl.ErrorHeader = @alignCast(@ptrCast(resp_buf[start..end]));
                    switch (posix.errno(@as(isize, @intCast(nl_err.err)))) {
                        .SUCCESS => {},
                        .BUSY => return error.BUSY,
                        else => |err| {
                            log.err("OS Error: ({d}) {s}", .{ nl_err.err, @tagName(err) });
                            return error.OSError;
                        },
                    }
                }
                if (nl_resp_hdr.type == c(nl.NLMSG).DONE) break :respL3;
                if (nl_resp_hdr.type == c(RTM).NEWADDR) ipAddr: {
                    start = end;
                    end += @sizeOf(InterfaceAddress);
                    const ifa_msg: *const InterfaceAddress = @alignCast(@ptrCast(resp_buf[start..end]));
                    if (ifa_msg.index != if_index) break :ipAddr;
                    start = end;
                    end += nl.attr_hdr_len;
                    while (end < offset + nl_resp_hdr.len) {
                        const attr: *const nl.AttributeHeader = @alignCast(@ptrCast(resp_buf[start..end]));
                        start = end;
                        end += (attr.len -| nl.attr_hdr_len);
                        switch (attr.type) {
                            1 => {
                                for (dev.ips[0..]) |*ip| {
                                    if (ip.*) |_| continue;
                                    ip.* = .{ 0 } ** 4;
                                    @memcpy(ip.*.?[0..], resp_buf[start..start + 4]);
                                    set_count += 1;
                                    break;
                                }
                            },
                            else => {},
                        }
                        end = mem.alignForward(usize, end, 4);
                        start = end;
                        end += nl.attr_hdr_len;
                    }
                }
                offset += mem.alignForward(usize, nl_resp_hdr.len, 4);
            }
        }
        return dev;
    }

    pub fn format(
        self: @This(), 
        _: []const u8, 
        _: fmt.FormatOptions, 
        writer: anytype,
    ) !void {
        try writer.print("- Index: {d}\n", .{ self.index });
        try writer.print("- MAC:   ", .{});
        try address.printAddr(self.mac[0..], ":", "{X:0>2}", writer);
        try writer.print("\n", .{});
        try writer.print("- MTU:   {d}\n", .{ self.mtu });
        if (self.ips[0] == null) return;
        try writer.print("- IPs:\n", .{});
        for (self.ips) |ip| {
            const _ip = ip orelse return;
            try writer.print("  - ", .{});
            try address.printAddr(_ip[0..], ".", "{d}", writer);
            try writer.print("\n", .{});
        }
    }
};

///// Get All Interface Details (WIP)
//pub fn getAllIF(if_name: []const u8) !void {
//    const nl_sock = try netlinkRequest(
//        .{
//            .nlh = .{
//                .len = 0,
//                .type = RTM.GETLINK,
//                .flags = nl.NLM_F.REQUEST | nl.NLM_F.DUMP,
//                .seq = 0,
//                .pid = 50505,
//            },
//            .msg = .{
//                .family = AF.PACKET,
//                .index = 0,
//                .flags = 0,
//                .change = 0,
//                .type = 0,
//            },
//        },
//        attr,
//        .{
//            .len = 0,
//            .type = .IFNAME,
//        },
//        if_name,
//        IFNAMESIZE,
//    );
//    defer posix.close(nl_sock);
//
//    var resp_idx: usize = 0;
//    while (resp_idx <= 10) : (resp_idx += 1) {
//        var resp_buf: [4096]u8 = undefined;
//        const resp_len = posix.recv(
//            nl_sock,
//            resp_buf[0..],
//            0,
//        ) catch |err| switch (err) {
//            error.WouldBlock => return error.NoInterfaceFound,
//            else => return err,
//        };
//
//        var offset: usize = 0;
//        while (offset < resp_len) {
//            var start: usize = offset;
//            var end: usize = (offset + @sizeOf(os.linux.nlmsghdr));
//            const nl_resp_hdr: *os.linux.nlmsghdr = @alignCast(@ptrCast(resp_buf[start..end]));
//            if (nl_resp_hdr.len < @sizeOf(os.linux.nlmsghdr))
//                return error.InvalidMessage;
//            if (nl_resp_hdr.type == .ERROR)
//                return error.NetlinkMessageError;
//            if (nl_resp_hdr.type == RTM.NEWLINK) ifi: {
//                start = end;
//                end += @sizeOf(os.linux.ifinfomsg);
//                //const ifi: *const os.linux.ifinfomsg = @alignCast(@ptrCast(resp_buf[start..end]));
//                start = end;
//                end += @sizeOf(attr);
//                const attr: *const attr = @alignCast(@ptrCast(resp_buf[start..end]));
//                if (attr.type != .IFNAME) break :ifi;
//                start = end;
//                end += attr.len;
//                const name = resp_buf[start..end];
//                if (!mem.eql(u8, if_name, name[0..@min(attr.len, if_name.len)])) break :ifi;
//                //return ifi.index;
//            }
//
//            offset += mem.alignForward(usize, nl_resp_hdr.len, 4);
//        }
//    }
//    return error.NoInterfaceIndexFound;
//}
