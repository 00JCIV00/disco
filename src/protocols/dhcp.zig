//! DHCP Functions f/ DisCo.

const std = @import("std");
const crypto = std.crypto;
const log = std.log.scoped(.dhcp);
const mem = std.mem;
const net = std.net;
const posix = std.posix;
const os = std.os;

const netdata = @import("../netdata.zig");
const l5 = netdata.l5;
const address = netdata.address;
const MACF = address.MACFormatter;
const IPF = address.IPFormatter;
const Eth = netdata.l2.Eth;
const IP = netdata.l3.IP;
const UDP = netdata.l4.UDP;
const eth_len = @sizeOf(Eth.Header);
const ip_len = @sizeOf(IP.NetHeader);
const udp_len = @sizeOf(UDP.Header);
const utils = @import("../utils.zig");
const c = utils.toStruct;


/// Send DHCP message with Raw Socket
fn sendDHCPMsg(
    msg_sock: posix.socket_t,
    client_mac: [6]u8,
    dst_ip: [4]u8,
    msg: []u8,
) !void {
    var eth_hdr: netdata.l2.Eth.Header = .{
        .dst_mac_addr = .{ 0xFF } ** 6,
        .src_mac_addr = client_mac,
        .ether_type = mem.nativeToBig(u16, c(netdata.l2.Eth.ETH_P).IPv4),
    };
    var ip_hdr: netdata.l3.IP.Header = .{
        .id = id: {
            var id_buf: [2]u8 = undefined;
            crypto.random.bytes(id_buf[0..]);
            break :id mem.bytesToValue(u16, id_buf[0..]);
        },
        .src_ip_addr = 0,
        .dst_ip_addr = mem.bytesToValue(u32, dst_ip[0..]),
    };
    var udp_hdr: netdata.l4.UDP.Header = .{
        .src_port = mem.nativeToBig(u16, 68),
        .dst_port = mem.nativeToBig(u16, 67),
        .length = mem.nativeToBig(u16, @as(u16, @intCast(udp_len + msg.len))),
    };
    const pseudo_hdr: IP.SegmentPseudoHeader = .{
        .src_ip_addr = ip_hdr.src_ip_addr,
        .dst_ip_addr = ip_hdr.dst_ip_addr,
        .protocol = ip_hdr.protocol,
        .len = udp_hdr.length,
    };
    var frame_buf: [1500]u8 = .{ 0 } ** 1500;
    const frame_end = eth_len + ip_len + udp_len + msg.len;
    const frame_len = frame_end + 4;
    var end: usize = frame_end;
    var start: usize = end - msg.len;
    @memcpy(frame_buf[start..end], msg);
    end -= msg.len;
    start = end - udp_len;
    @memcpy(frame_buf[start..end], mem.asBytes(&udp_hdr));
    end -= udp_len;
    start = end - @sizeOf(IP.SegmentPseudoHeader);
    @memcpy(frame_buf[start..end], mem.asBytes(&pseudo_hdr));
    udp_hdr.checksum = netdata.calcChecksum(frame_buf[start..frame_end]);
    start = end;
    end += udp_len;
    @memcpy(frame_buf[start..end], mem.asBytes(&udp_hdr));
    end -= udp_len;
    start = end - ip_len;
    ip_hdr.total_len = @intCast(ip_len + udp_len + msg.len);
    var net_ip_hdr: IP.NetHeader = IP.NetHeader.fromHeader(ip_hdr);
    @memcpy(frame_buf[start..end], mem.asBytes(&net_ip_hdr));
    net_ip_hdr.checksum = netdata.calcChecksum(frame_buf[start..end]);
    @memcpy(frame_buf[start..end], mem.asBytes(&net_ip_hdr));
    end -= ip_len;
    start = 0;
    @memcpy(frame_buf[start..end], mem.asBytes(&eth_hdr));
    const eth_crc = try netdata.calcCRC(frame_buf[start..frame_end]);
    @memcpy(frame_buf[frame_end..frame_len], mem.asBytes(&eth_crc));
    _ = try posix.send(msg_sock, frame_buf[0..frame_len], 0);
}

pub fn recvDHCPMsg(
    msg_sock: posix.socket_t,
    client_mac: [6]u8,
    recv_buf: []u8,
) !usize {
    var frame_buf: [1500]u8 = undefined;
    const frame_len = try posix.recv(msg_sock, frame_buf[0..], 0);
    var start: usize = 0;
    var end: usize = eth_len;
    const eth_hdr = netdata.asNativeHeader(Eth.Header, frame_buf[start..end]);
    if (eth_hdr.ether_type != c(Eth.ETH_P).IPv4) return error.IncorrectFrameProto;
    if (!mem.eql(u8, eth_hdr.dst_mac_addr[0..], client_mac[0..])) return error.IncorrectDestMAC;
    start = end;
    end += ip_len;
    const ip_hdr = mem.bytesToValue(IP.NetHeader, frame_buf[start..end]).toHeader();
    if (ip_hdr.protocol != c(IP.Header.Protocols).UDP) return error.IncorrectIPProto;
    start = end;
    end += udp_len;
    const udp_hdr = netdata.asNativeHeader(UDP.Header, frame_buf[start..end]);
    if (udp_hdr.src_port != 67 or udp_hdr.dst_port != 68) return error.NonUDPPort;
    start = end;
    end = frame_len;
    @memcpy(recv_buf[0..(end - start)], frame_buf[start..end]);
    return frame_len;
}

/// DHCP Lease Config
pub const LeaseConfig = struct {
    /// Requested IP Address
    ip_addr: ?[4]u8 = null,
    /// Requested lease time in seconds (default: 1 hour)
    lease_time: ?u32 = null,
    /// Requested renewal time, T1, in seconds (default: 0.5 * lease_time)
    renewal_time: ?u32 = null,
    /// Requested rebinding time, T2, in seconds (default: 0.875 * lease_time)
    rebinding_time: ?u32 = null,
    /// An Optional Hostname to send to the Server
    hostname: ?[]const u8 = null,
    /// Error on Request/Offer Mismatch
    err_on_mismatch: bool = true,
};

/// DHCP Info. This is returned from `handleDHCP()` and passed to `releasedDHCP()`.
pub const Info = struct {
    assigned_ip: [4]u8,
    subnet_mask: [4]u8,
    router: [4]u8,
    server_id: [4]u8,
    dns_ips: [4]?[4]u8,
};

/// Handle the DHCP process
pub fn handleDHCP(
    if_name: []const u8,
    if_index: i32,
    mac_addr: [6]u8,
    config: LeaseConfig,
) !Info {
    log.debug("Starting DHCP...", .{});
    defer log.debug("Finished DHCP!", .{});
    const dhcp_sock = try posix.socket(posix.AF.PACKET, posix.SOCK.RAW, mem.nativeToBig(u16, c(Eth.ETH_P).IPv4));
    defer posix.close(dhcp_sock);
    const sock_addr = posix.sockaddr.ll{
        .ifindex = if_index,
        .protocol = mem.nativeToBig(u16, c(Eth.ETH_P).IPv4),
        .hatype = 0,
        .pkttype = 0,
        .halen = 6,
        .addr = .{ 0 } ** 8,
    };
    // Bind to the Interface
    try posix.setsockopt(
        dhcp_sock,
        posix.SOL.SOCKET,
        posix.SO.BINDTODEVICE,
        if_name,
    );
    // Set receive timeout
    try posix.setsockopt(
        dhcp_sock,
        posix.SOL.SOCKET,
        posix.SO.RCVTIMEO,
        mem.asBytes(&posix.timeval{ .sec = 3, .usec = 0 }),
    );
    try posix.bind(dhcp_sock, @ptrCast(&sock_addr), @sizeOf(posix.sockaddr.ll));
    const bootp_hdr_len = @sizeOf(l5.BOOTP.Header);
    const attempts_max: u8 = 3;
    var attempts: u8 = 0;
    while (attempts < attempts_max) {
        defer attempts += 1;
        const transaction_id: u32 = transaction_id: {
            var bytes: [4]u8 = undefined;
            crypto.random.bytes(bytes[0..]);
            break :transaction_id mem.bytesToValue(u32, bytes[0..]);
        };
        // DISCOVER
        var disc_buf: [1500]u8 = undefined;
        var start: usize = 0;
        var end: usize = bootp_hdr_len;
        // - Create and write BOOTP header
        var disc_hdr = l5.BOOTP.Header{
            .op = c(l5.BOOTP.OP).REQUEST,
            .tx_id = transaction_id,
        };
        @memcpy(disc_hdr.client_hw_addr[0..6], mac_addr[0..]);
        @memcpy(disc_buf[start..end], mem.asBytes(&disc_hdr));
        // - Add DHCP Message Type option
        start = end;
        end += 2;
        const dhcp_msg_type: l5.BOOTP.OptionHeader = .{
            .code = c(l5.DHCP.OptionCode).MESSAGE_TYPE,
            .len = 1,
        };
        @memcpy(disc_buf[start..end], mem.asBytes(&dhcp_msg_type));
        start = end;
        end += 1;
        disc_buf[start] = c(l5.DHCP.MessageType).DISCOVER;
        // - Add Parameter Request List
        start = end;
        end += 2;
        const params_req_list: l5.BOOTP.OptionHeader = .{
            .code = c(l5.DHCP.OptionCode).PARAMETER_REQUEST,
            .len = 4,
        };
        @memcpy(disc_buf[start..end], mem.asBytes(&params_req_list));
        start = end;
        end += 4;
        @memcpy(disc_buf[start..end], @as([]const u8, &.{
            c(l5.DHCP.OptionCode).SUBNET_MASK,
            c(l5.DHCP.OptionCode).ROUTER,
            c(l5.DHCP.OptionCode).DNS,
            c(l5.DHCP.OptionCode).DOMAIN,
        }));
        // - Add Client ID option
        start = end;
        end += 2;
        const client_id: l5.BOOTP.OptionHeader = .{
            .code = c(l5.DHCP.OptionCode).CLIENT_ID,
            .len = 7,
        };
        @memcpy(disc_buf[start..end], mem.asBytes(&client_id));
        start = end;
        end += 1;
        disc_buf[start] = 1;
        start = end;
        end += 6;
        @memcpy(disc_buf[start..end], mac_addr[0..]);
        // - Add Max Message Size option
        start = end;
        end += 2;
        const max_msg_size: l5.BOOTP.OptionHeader = .{
            .code = c(l5.DHCP.OptionCode).MAX_MESSAGE_SIZE,
            .len = 2,
        };
        @memcpy(disc_buf[start..end], mem.asBytes(&max_msg_size));
        start = end;
        end += 2;
        @memcpy(disc_buf[start..end], mem.asBytes(&mem.nativeToBig(u16, 1500)));
        // - Custom IP
        if (config.ip_addr) |ip| {
            start = end;
            end += 2;
            const req_ip_addr: l5.BOOTP.OptionHeader = .{
                .code = c(l5.DHCP.OptionCode).REQUESTED_IP,
                .len = 4,
            };
            @memcpy(disc_buf[start..end], mem.asBytes(&req_ip_addr));
            start = end;
            end += 4;
            @memcpy(disc_buf[start..end], ip[0..]);
        }
        // - End Option
        start = end;
        end += 1;
        disc_buf[start] = c(l5.DHCP.OptionCode).END;
        // - Send Discovery
        try sendDHCPMsg(
            dhcp_sock, 
            mac_addr, 
            .{ 255 } ** 4,
            disc_buf[0..end], 
        );
        log.debug(
            \\
            \\-------------------------------------
            \\DISCOVER:
            \\ - Transaction ID: 0x{X:0>8}
            \\ - Client MAC:     {s}
            \\ - Options Length: {d}B
            \\
            , .{
                transaction_id,
                MACF{ .bytes = mac_addr[0..] },
                end - bootp_hdr_len,
            },
        );
        // OFFER
        var offer_buf: [1500]u8 = undefined;
        const offer_len = offerLen: while (attempts < attempts_max) {
            break :offerLen recvDHCPMsg(
                dhcp_sock,
                mac_addr,
                offer_buf[0..],
            ) catch |err| {
                log.warn("Unexpected DHCP Response: {s}", .{ @errorName(err) });
                attempts += 1;
                continue;
            };
        }
        else return error.CouldNotCompleteDHCP;
        // - Parse BOOTP header
        start = 0;
        end = bootp_hdr_len;
        const offer_hdr = mem.bytesAsValue(l5.BOOTP.Header, offer_buf[start..end]);
        if (offer_hdr.tx_id != transaction_id) {
            log.warn(
                \\Transaction ID Mismatch:
                \\ - Expected: 0x{X:0>8}
                \\ - Received: 0x{X:0>8}
                , .{
                    transaction_id,
                    offer_hdr.tx_id,
                }
            );
            continue;
        }
        if (offer_hdr.op != c(l5.BOOTP.OP).REPLY) {
            log.warn("Not a BOOTP reply", .{});
            continue;
        }
        // - Parse DHCP options
        var offer_msg_type_buf: ?u8 = null;
        var offer_server_id_buf: ?[4]u8 = null;
        var offer_lease_time_buf: ?u32 = null;
        var offer_subnet_mask_buf: ?[4]u8 = null;
        var offer_router_buf: ?[4]u8 = null;
        var offer_dns_buf: ?[4]u8 = null;
        start = end;
        while (start < offer_len) {
            const opt_code = offer_buf[start];
            // Check for end of options
            if (opt_code == c(l5.DHCP.OptionCode).END) break;
            // Skip pad option
            if (opt_code == c(l5.DHCP.OptionCode).PAD) {
                start += 1;
                continue;
            }
            const opt_len = offer_buf[start + 1];
            const opt_data = offer_buf[start + 2 .. start + 2 + opt_len];
            switch (opt_code) {
                c(l5.DHCP.OptionCode).MESSAGE_TYPE => {
                    if (opt_len == 1) offer_msg_type_buf = opt_data[0];
                },
                c(l5.DHCP.OptionCode).SERVER_ID => {
                    if (opt_len == 4) offer_server_id_buf = opt_data[0..4].*;
                },
                c(l5.DHCP.OptionCode).LEASE_TIME => {
                    if (opt_len == 4) offer_lease_time_buf = mem.bigToNative(u32, mem.bytesToValue(u32, opt_data[0..4]));
                },
                c(l5.DHCP.OptionCode).SUBNET_MASK => {
                    if (opt_len == 4) offer_subnet_mask_buf = opt_data[0..4].*;
                },
                c(l5.DHCP.OptionCode).ROUTER => {
                    if (opt_len == 4) offer_router_buf = opt_data[0..4].*;
                },
                c(l5.DHCP.OptionCode).DNS => {
                    if (opt_len == 4) offer_dns_buf = opt_data[0..4].*;
                },
                else => {},
            }
            start += 2 + opt_len;
        }
        // - Validate OFFER
        const offer_msg_type = offer_msg_type_buf orelse {
            log.warn("Missing Message Type", .{});
            continue;
        };
        if (offer_msg_type != c(l5.DHCP.MessageType).OFFER) {
            log.warn("Not a DHCP OFFER message", .{});
            continue;
        }
        const offer_server_id = offer_server_id_buf orelse {
            log.warn("No Server Identifier in OFFER", .{});
            continue;
        };
        const offer_subnet_mask = offer_subnet_mask_buf orelse {
            log.warn("No Subnet Mask in OFFER", .{});
            continue;
        };
        const offer_router = offer_router_buf orelse {
            log.warn("No Router in OFFER", .{});
            continue;
        };
        const offer_lease_time = offer_lease_time_buf orelse {
            log.warn("No Lease Time in OFFER", .{});
            continue;
        };
        const offered_ip = offer_hdr.self_addr;
        log.debug(
            \\
            \\-------------------------------------
            \\OFFER:
            \\ - Server ID:   {s}
            \\ - Offered IP:  {s}
            \\ - Subnet Mask: {s}
            \\ - Router:      {s}
            \\ - Lease Time:  {d}s
            \\
            , .{
                IPF{ .bytes = offer_server_id[0..] },
                IPF{ .bytes = offered_ip[0..] },
                IPF{ .bytes = offer_subnet_mask[0..] },
                IPF{ .bytes = offer_router[0..] },
                offer_lease_time,
            },
        );
        // - Check Requested Options
        if (config.ip_addr) |req_ip| {
            const mismatch = !mem.eql(u8, offered_ip[0..], req_ip[0..]);
            if (mismatch and config.err_on_mismatch) {
                log.err("Requested IP: {d} | Offered IP: {d}", .{ req_ip, offered_ip });
                return error.NotGivenRequestedIP;
            }
            if (mismatch and !config.err_on_mismatch) {
                log.warn("Requested IP: {d} | Offered IP: {d}", .{ req_ip, offered_ip });
                continue;
            }
        }
        //// REQUEST
        var req_buf: [1500]u8 = undefined;
        start = 0;
        end = bootp_hdr_len;
        // - Create and write BOOTP header
        var req_hdr = l5.BOOTP.Header{
            .op = c(l5.BOOTP.OP).REQUEST,
            .tx_id = transaction_id,
        };
        @memcpy(req_hdr.client_hw_addr[0..6], mac_addr[0..]);
        @memcpy(req_buf[start..end], mem.toBytes(req_hdr)[0..]);
        // - Add DHCP Message Type option
        start = end;
        end += 2;
        @memcpy(req_buf[start..end], mem.asBytes(&dhcp_msg_type));
        start = end;
        end += 1;
        req_buf[start] = c(l5.DHCP.MessageType).REQUEST;
        // - Add Parameter Request List
        start = end;
        end += 2;
        @memcpy(req_buf[start..end], mem.asBytes(&params_req_list));
        start = end;
        end += 4;
        @memcpy(req_buf[start..end], @as([]const u8, &.{
            c(l5.DHCP.OptionCode).SUBNET_MASK,
            c(l5.DHCP.OptionCode).ROUTER,
            c(l5.DHCP.OptionCode).DNS,
            c(l5.DHCP.OptionCode).DOMAIN,
        }));
        // - Add Client ID option
        start = end;
        end += 2;
        @memcpy(req_buf[start..end], mem.asBytes(&client_id));
        start = end;
        end += 1;
        req_buf[start] = 1;
        start = end;
        end += 6;
        @memcpy(req_buf[start..end], mac_addr[0..]);
        // - Add Max Message Size option
        start = end;
        end += 2;
        @memcpy(req_buf[start..end], mem.asBytes(&max_msg_size));
        start = end;
        end += 2;
        @memcpy(req_buf[start..end], mem.asBytes(&mem.nativeToBig(u16, 1500)));

        // - Add Requested IP option
        start = end;
        end += 2;
        const req_ip_hdr: l5.BOOTP.OptionHeader = .{
            .code = c(l5.DHCP.OptionCode).REQUESTED_IP,
            .len = 4,
        };
        @memcpy(req_buf[start..end], mem.asBytes(&req_ip_hdr));
        start = end;
        end += 4;
        @memcpy(req_buf[start..end], offered_ip[0..]);
        // - Add Server ID option
        start = end;
        end += 2;
        const server_id_hdr: l5.BOOTP.OptionHeader = .{
            .code = c(l5.DHCP.OptionCode).SERVER_ID,
            .len = 4,
        };
        @memcpy(req_buf[start..end], mem.asBytes(&server_id_hdr));
        start = end;
        end += 4;
        @memcpy(req_buf[start..end], offer_server_id[0..]);
        // - Custom Lease Time Options
        if (config.lease_time) |lease_time| {
            start = end;
            end += 2;
            const lease_time_hdr: l5.BOOTP.OptionHeader = .{
                .code = c(l5.DHCP.OptionCode).LEASE_TIME,
                .len = 4,
            };
            @memcpy(req_buf[start..end], mem.asBytes(&lease_time_hdr));
            start = end;
            end += 4;
            @memcpy(req_buf[start..end], mem.asBytes(&lease_time));
        }
        if (config.renewal_time) |renewal_time| {
            start = end;
            end += 2;
            const renewal_time_hdr: l5.BOOTP.OptionHeader = .{
                .code = c(l5.DHCP.OptionCode).RENEWAL_TIME,
                .len = 4,
            };
            @memcpy(req_buf[start..end], mem.asBytes(&renewal_time_hdr));
            start = end;
            end += 4;
            @memcpy(req_buf[start..end], mem.asBytes(&renewal_time));
        }
        if (config.rebinding_time) |rebinding_time| {
            start = end;
            end += 2;
            const rebinding_time_hdr: l5.BOOTP.OptionHeader = .{
                .code = c(l5.DHCP.OptionCode).REBINDING_TIME,
                .len = 4,
            };
            @memcpy(req_buf[start..end], mem.asBytes(&rebinding_time_hdr));
            start = end;
            end += 4;
            @memcpy(req_buf[start..end], mem.asBytes(&rebinding_time));
        }
        // -----------------------------
        // - Add Host Name if configured
        if (config.hostname) |hostname| {
            log.debug("Using Hostname '{s}'.", .{ hostname });
            start = end;
            end += 2;
            const hostname_hdr: l5.BOOTP.OptionHeader = .{
                .code = c(l5.DHCP.OptionCode).HOSTNAME,
                .len = @truncate(hostname.len),
            };
            @memcpy(req_buf[start..end], mem.asBytes(&hostname_hdr));
            start = end;
            end += hostname.len;
            @memcpy(req_buf[start..end], hostname);
        }
        // - End Option
        start = end;
        end += 1;
        req_buf[start] = c(l5.DHCP.OptionCode).END;
        // - Send Request
        try sendDHCPMsg(
            dhcp_sock,
            mac_addr,
            .{ 255 } ** 4,
            req_buf[0..end],
        );
        log.debug(
            \\
            \\-------------------------------------
            \\REQUEST:
            \\ - Transaction ID: 0x{X:0>8}
            \\ - Client MAC:     {s}
            \\ - Server ID:      {s}
            \\ - Requested IP:   {s}
            \\ - Options Length: {d}B
            \\
            , .{
                transaction_id,
                MACF{ .bytes = mac_addr[0..] },
                IPF{ .bytes = offer_server_id[0..] },
                IPF{ .bytes = offered_ip[0..] },
                end - bootp_hdr_len,
            },
        );
        // ACK/NAK
        var ack_buf: [1500]u8 = undefined;
        const ack_len = try recvDHCPMsg(
            dhcp_sock,
            mac_addr,
            ack_buf[0..],
        );
        // - Parse BOOTP header
        start = 0;
        end = bootp_hdr_len;
        const ack_header = mem.bytesAsValue(l5.BOOTP.Header, offer_buf[start..end]);
        // - Validate transaction ID
        if (ack_header.tx_id != transaction_id) {
            log.warn(
                \\Transaction ID Mismatch:
                \\ - Expected: 0x{X:0>8}
                \\ - Received: 0x{X:0>8}
                , .{
                    transaction_id,
                    ack_header.tx_id,
                }
            );
            continue;
        }
        if (ack_header.op != c(l5.BOOTP.OP).REPLY) {
            log.warn("Not a BOOTP reply", .{});
            continue;
        }
        // - Parse DHCP options
        var ack_msg_type_buf: ?u8 = null;
        var ack_server_id_buf: ?[4]u8 = null;
        var ack_lease_time_buf: ?u32 = null;
        var ack_subnet_mask_buf: ?[4]u8 = null;
        var ack_router_buf: ?[4]u8 = null;
        var ack_dns_buf: [4]?[4]u8 = .{ null } ** 4;
        start = end;
        while (start < ack_len) {
            const opt_code = ack_buf[start];
            // Check for end of options
            if (opt_code == c(l5.DHCP.OptionCode).END) break;
            // Skip pad option
            if (opt_code == c(l5.DHCP.OptionCode).PAD) {
                start += 1;
                continue;
            }
            const opt_len = ack_buf[start + 1];
            const opt_data = ack_buf[(start + 2)..(start + 2 + opt_len)];
            switch (opt_code) {
                c(l5.DHCP.OptionCode).MESSAGE_TYPE => {
                    if (opt_len == 1) ack_msg_type_buf = opt_data[0];
                },
                c(l5.DHCP.OptionCode).SERVER_ID => {
                    if (opt_len == 4) ack_server_id_buf = opt_data[0..4].*;
                },
                c(l5.DHCP.OptionCode).LEASE_TIME => {
                    if (opt_len == 4) ack_lease_time_buf = mem.bigToNative(u32, mem.bytesToValue(u32, opt_data[0..4]));
                },
                c(l5.DHCP.OptionCode).SUBNET_MASK => {
                    if (opt_len == 4) ack_subnet_mask_buf = opt_data[0..4].*;
                },
                c(l5.DHCP.OptionCode).ROUTER => {
                    if (opt_len == 4) ack_router_buf = opt_data[0..4].*;
                },
                c(l5.DHCP.OptionCode).DNS => {
                    //if (opt_len == 4) ack_dns_buf = opt_data[0..4].*;
                    var dns_count: u8 = 0;
                    dns: while (dns_count < opt_len) : (dns_count += 4) {
                        for (ack_dns_buf[0..]) |*dns_ip| {
                            if (dns_ip.*) |_| continue;
                            dns_ip.* = opt_data[0..4].*;
                            continue :dns;
                        }
                        break;
                    }
                },
                else => {},
            }
            start += 2 + opt_len;
        }
        // - Validate ACK
        const ack_msg_type = ack_msg_type_buf orelse {
            log.warn("Missing Message Type", .{});
            continue;
        };
        const ack_server_id = ack_server_id_buf orelse {
            log.warn("No Server Identifier in ACK", .{});
            continue;
        };
        const ack_subnet_mask = ack_subnet_mask_buf orelse {
            log.warn("No Subnet Mask in ACK", .{});
            continue;
        };
        const ack_router = ack_router_buf orelse {
            log.warn("No Router in ACK", .{});
            continue;
        };
        const ack_lease_time = ack_lease_time_buf orelse {
            log.warn("No Lease Time in ACK", .{});
            continue;
        };
        const ack_dns = ack_dns_buf[0] orelse {
            log.warn("No DNS in ACK", .{});
            continue;
        };
        switch (ack_msg_type) {
            c(l5.DHCP.MessageType).ACK => {
                const assigned_ip = mem.bytesToValue([4]u8, &ack_header.self_addr);
                log.debug(
                    \\
                    \\-------------------------------------
                    \\ACK:
                    \\ - Server ID:   {s}
                    \\ - Assigned IP: {s}
                    \\ - Subnet Mask: {s}
                    \\ - Router:      {s}
                    \\ - DNS:         {s}
                    \\ - Lease Time:  {?d}s
                    \\
                    , .{
                        IPF{ .bytes = ack_server_id[0..] },
                        IPF{ .bytes = assigned_ip[0..] },
                        IPF{ .bytes = ack_subnet_mask[0..] },
                        IPF{ .bytes = ack_router[0..] },
                        IPF{ .bytes = ack_dns[0..] },
                        ack_lease_time,
                    },
                );
                return .{
                    .assigned_ip = assigned_ip,
                    .subnet_mask = ack_subnet_mask,
                    .router = ack_router,
                    .server_id = ack_server_id,
                    .dns_ips = ack_dns_buf,
                };
            },
            c(l5.DHCP.MessageType).NAK => {
                log.warn("Received DHCP NAK", .{});
                continue;
            },
            else => {
                log.warn(
                    "Unexpected message type: {d}",
                    .{ ack_msg_type },
                );
                continue;
            },
        }
    }
    return error.CouldNotCompleteDHCP;
}

/// Release DHCP lease
pub fn releaseDHCP(
    if_name: []const u8,
    if_index: i32,
    mac_addr: [6]u8,
    server_id: [4]u8,
    client_ip: [4]u8,
) !void {
    log.debug("Releasing DHCP lease...", .{});
    defer log.debug("DHCP lease released!", .{});
    const dhcp_sock = try posix.socket(posix.AF.PACKET, posix.SOCK.RAW, mem.nativeToBig(u16, c(Eth.ETH_P).IPv4));
    defer posix.close(dhcp_sock);
    const sock_addr = posix.sockaddr.ll{
        .ifindex = if_index,
        .protocol = mem.nativeToBig(u16, c(Eth.ETH_P).IPv4),
        .hatype = 0,
        .pkttype = 0,
        .halen = 6,
        .addr = .{ 0 } ** 8,
    };
    // Bind to the Interface
    try posix.setsockopt(
        dhcp_sock,
        posix.SOL.SOCKET,
        posix.SO.BINDTODEVICE,
        if_name,
    );
    try posix.bind(dhcp_sock, @ptrCast(&sock_addr), @sizeOf(posix.sockaddr.ll));
    // BOOTP Setup
    const bootp_hdr_len = @sizeOf(l5.BOOTP.Header);
    var rel_buf: [1500]u8 = undefined;
    var start: usize = 0;
    var end: usize = bootp_hdr_len;
    // - Create transaction ID
    const transaction_id: u32 = transactionID: {
        var bytes: [4]u8 = undefined;
        crypto.random.bytes(bytes[0..]);
        break :transactionID mem.bytesToValue(u32, bytes[0..]);
    };
    // - Create and write BOOTP header
    var rel_hdr = l5.BOOTP.Header{
        .op = c(l5.BOOTP.OP).REQUEST,
        .tx_id = transaction_id,
    };
    @memcpy(rel_hdr.client_hw_addr[0..6], mac_addr[0..]);
    @memcpy(rel_hdr.client_addr[0..], client_ip[0..]);  
    @memcpy(rel_buf[start..end], mem.asBytes(&rel_hdr));
    // - Add DHCP Message Type option
    start = end;
    end += 2;
    const dhcp_msg_type: l5.BOOTP.OptionHeader = .{
        .code = c(l5.DHCP.OptionCode).MESSAGE_TYPE,
        .len = 1,
    };
    @memcpy(rel_buf[start..end], mem.asBytes(&dhcp_msg_type));
    start = end;
    end += 1;
    rel_buf[start] = c(l5.DHCP.MessageType).RELEASE;
    // - Add Server ID option
    start = end;
    end += 2;
    const server_id_hdr: l5.BOOTP.OptionHeader = .{
        .code = c(l5.DHCP.OptionCode).SERVER_ID,
        .len = 4,
    };
    @memcpy(rel_buf[start..end], mem.asBytes(&server_id_hdr));
    start = end;
    end += 4;
    @memcpy(rel_buf[start..end], server_id[0..]);
    // - Add Client ID Option
    start = end;
    end += 2;
    const client_id: l5.BOOTP.OptionHeader = .{
        .code = c(l5.DHCP.OptionCode).CLIENT_ID,
        .len = 7,
    };
    @memcpy(rel_buf[start..end], mem.asBytes(&client_id));
    start = end;
    end += 1;
    // - Hardware Type (ethernet)
    rel_buf[start] = 1;
    start = end;
    end += 6;
    @memcpy(rel_buf[start..end], mac_addr[0..]);
    // - End Option
    start = end;
    end += 1;
    rel_buf[start] = c(l5.DHCP.OptionCode).END;
    // Send Release
    try sendDHCPMsg(
        dhcp_sock,
        mac_addr,
        server_id,
        rel_buf[0..end],
    );
    log.debug(
        \\
        \\-------------------------------------
        \\RELEASE:
        \\ - Transaction ID: 0x{X:0>8}
        \\ - Client MAC:     {s}
        \\ - Client IP:      {s}
        \\ - Server ID:      {s}
        \\ - Options Length: {d}B
        \\
        , .{
            transaction_id,
            MACF{ .bytes = mac_addr[0..] },
            IPF{ .bytes = client_ip[0..] },
            IPF{ .bytes = server_id[0..] },
            end - bootp_hdr_len,
        },
    );
}
