//! DHCP Functions f/ DisCo.

const std = @import("std");
const crypto = std.crypto;
const linux = std.os.linux;
const log = std.log.scoped(.dhcp);
const mem = std.mem;
const net = std.net;
const posix = std.posix;
const time = std.time;
const Io = std.Io;

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
const pseudo_len = @sizeOf(IP.SegmentPseudoHeader);
const udp_len = @sizeOf(UDP.Header);
const hdr_len = eth_len + ip_len + udp_len;
const utils = @import("../utils.zig");
const c = utils.toStruct;
const SockReader = utils.SocketReader;
const SockWriter = utils.SocketWriter;


/// Send DHCP message with Raw Socket
fn sendDHCPMsg(
    sock_w: *Io.Writer,
    client_mac: [6]u8,
    dst_ip: [4]u8,
) !void {
    const msg_len = sock_w.end;
    const eth_hdr: netdata.l2.Eth.Header = .{
        .dst_mac_addr = @splat(0xFF),
        .src_mac_addr = client_mac,
        .ether_type = c(netdata.l2.Eth.ETH_P).IPv4,
    };
    const ip_hdr: netdata.l3.IP.Header = .{
        .id = id: {
            var id_buf: [2]u8 = undefined;
            crypto.random.bytes(id_buf[0..]);
            break :id mem.bytesToValue(u16, id_buf[0..]);
        },
        .src_ip_addr = 0,
        .dst_ip_addr = mem.bytesToValue(u32, dst_ip[0..]),
        .total_len = @intCast(ip_len + udp_len + msg_len),
    };
    var net_ip_hdr: IP.NetHeader = IP.NetHeader.fromHeader(ip_hdr);
    var udp_hdr: netdata.l4.UDP.Header = .{
        .src_port = 68,
        .dst_port = 67,
        .length = @intCast(udp_len + msg_len),
    };
    const pseudo_hdr: IP.SegmentPseudoHeader = .{
        .src_ip_addr = mem.toBytes(ip_hdr.src_ip_addr),
        .dst_ip_addr = mem.toBytes(ip_hdr.dst_ip_addr),
        .protocol = ip_hdr.protocol,
        .len = udp_hdr.length,
    };
    // UDP
    var full_len = pseudo_len + udp_len + msg_len;
    //const full_len = hdr_len + msg_len;
    @memmove(sock_w.buffer[(pseudo_len + udp_len)..(full_len)], sock_w.buffered());
    sock_w.end = 0;
    try sock_w.writeStruct(pseudo_hdr, .big);
    try sock_w.writeStruct(udp_hdr, .big);
    sock_w.end = full_len;
    udp_hdr.checksum = netdata.calcChecksum(sock_w.buffered(), .big);
    // IP
    full_len = ip_len + udp_len + msg_len;
    @memmove(sock_w.buffer[(ip_len + udp_len)..(full_len)], sock_w.buffered()[(pseudo_len + udp_len)..]);
    sock_w.end = 0;
    try sock_w.writeStruct(net_ip_hdr, .big);
    try sock_w.writeStruct(udp_hdr, .big);
    sock_w.end = full_len;
    net_ip_hdr.checksum = netdata.calcChecksum(sock_w.buffered()[0..ip_len], .big);
    // Eth
    full_len = eth_len + ip_len + udp_len + msg_len;
    @memmove(sock_w.buffer[(eth_len + ip_len)..(full_len)], sock_w.buffered()[ip_len..]);
    sock_w.end = 0;
    try sock_w.writeStruct(eth_hdr, .big);
    try sock_w.writeStruct(net_ip_hdr, .big);
    sock_w.end = full_len;
    const eth_crc = try netdata.calcCRC(sock_w.buffered()[eth_len..]);
    try sock_w.writeInt(u32, eth_crc, .big);
    // Send
    try sock_w.flush();
}

pub fn recvDHCPMsg(
    sock_r: *Io.Reader,
    client_mac: [6]u8,
) !void {
    sock_r.tossBuffered();
    sock_r.seek = 0;
    sock_r.end = 0;
    try sock_r.fillMore();
    const eth_hdr = try sock_r.takeStruct(Eth.Header, .big);
    if (eth_hdr.ether_type != c(Eth.ETH_P).IPv4) //
        return error.IncorrectFrameProto;
    if (!mem.eql(u8, eth_hdr.dst_mac_addr[0..], client_mac[0..])) //
        return error.IncorrectDestMAC;
    const net_ip_hdr = try sock_r.takeStruct(IP.NetHeader, .big);
    if (net_ip_hdr.protocol != c(IP.Header.Protocols).UDP) {
        log.err("Incorrect IP Protocol: {d}", .{ net_ip_hdr.protocol });
        return error.IncorrectIPProto;
    }
    const udp_hdr = try sock_r.takeStruct(UDP.Header, .big);
    _ = udp_hdr;
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
    /// Max Retries
    max_attempts: u8 = 10,
};

/// DHCP Info. This is returned from `handleDHCP()` and passed to `releasedDHCP()`.
pub const Info = struct {
    assigned_ip: [4]u8,
    subnet_mask: [4]u8,
    router: [4]u8,
    server_id: [4]u8,
    dns_ips: [4]?[4]u8,
};

/// DORA State
pub const DORAState = union(enum) {
    discover,
    offer,
    request,
    ack,
    end: Info,
};

/// Handler for the DHCP DORA Process
pub const Handler = struct {
    state: DORAState,
    sock: posix.socket_t,
    reader: SockReader,
    writer: SockWriter,
    r_buf: []const u8,
    w_buf: []const u8,
    mac_addr: [6]u8,
    config: LeaseConfig = .{},
    transaction_id: u32,
    ctx: Context = undefined,
    timer: time.Timer,
    timeout: u64,

    const Context = struct {
        offered_ip: [4]u8,
        offer_server_id: [4]u8,
        offer_subnet_mask: [4]u8,
        offer_router: [4]u8,
        offer_lease_time: u32,
    };

    const bootp_hdr_len = @sizeOf(l5.BOOTP.Header);
    const dhcp_msg_type: l5.BOOTP.OptionHeader = .{
        .code = c(l5.DHCP.OptionCode).MESSAGE_TYPE,
        .len = 1,
    };
    const params_req_hdr: l5.BOOTP.OptionHeader = .{
        .code = c(l5.DHCP.OptionCode).PARAMETER_REQUEST,
        .len = 4,
    };
    const params_reqs_list: []const u8 = &.{
        c(l5.DHCP.OptionCode).SUBNET_MASK,
        c(l5.DHCP.OptionCode).ROUTER,
        c(l5.DHCP.OptionCode).DNS,
        c(l5.DHCP.OptionCode).DOMAIN,
    };
    const client_id: l5.BOOTP.OptionHeader = .{
        .code = c(l5.DHCP.OptionCode).CLIENT_ID,
        .len = 7,
    };
    const max_msg_size: l5.BOOTP.OptionHeader = .{
        .code = c(l5.DHCP.OptionCode).MAX_MESSAGE_SIZE,
        .len = 2,
    };

    pub fn init(
        alloc: mem.Allocator,
        if_name: []const u8,
        if_index: i32,
        mac_addr: [6]u8,
        timeout: u64,
        config: LeaseConfig,
    ) !@This() {
        const sock = try posix.socket(
            posix.AF.PACKET,
            linux.SOCK.RAW,
            mem.nativeToBig(u16, c(Eth.ETH_P).IPv4),
        );
        errdefer posix.close(sock);
        const sock_addr = posix.sockaddr.ll{
            .ifindex = if_index,
            .protocol = mem.nativeToBig(u16, c(Eth.ETH_P).IPv4),
            .hatype = 0,
            .pkttype = 0,
            .halen = 6,
            .addr = @splat(0),
        };
        // Bind to the Interface
        try posix.setsockopt(
            sock,
            posix.SOL.SOCKET,
            posix.SO.BINDTODEVICE,
            if_name,
        );
        // Set receive timeout
        try posix.setsockopt(
            sock,
            posix.SOL.SOCKET,
            posix.SO.RCVTIMEO,
            mem.asBytes(&posix.timeval{ .sec = 3, .usec = 0 }),
        );
        try posix.bind(sock, @ptrCast(&sock_addr), @sizeOf(posix.sockaddr.ll));
        const r_buf = try alloc.alloc(u8, 4096);
        errdefer alloc.free(r_buf);
        const w_buf = try alloc.alloc(u8, 4096);
        errdefer alloc.free(w_buf);
        return .{
            .state = .discover,
            .sock = sock,
            .reader = .init(sock, r_buf, posix.MSG.DONTWAIT),
            .writer = .init(sock, w_buf, 0),
            .r_buf = r_buf,
            .w_buf = w_buf,
            .timer = try .start(),
            .timeout = timeout,
            .mac_addr = mac_addr,
            .config = config,
            .transaction_id = transactionID: {
                var bytes: [4]u8 = undefined;
                crypto.random.bytes(bytes[0..]);
                break :transactionID mem.bytesToValue(u32, bytes[0..]);
            },
        };
    }

    /// Deinitialize this DORA Handler
    pub fn deinit(self: *@This(), alloc: mem.Allocator) void {
        posix.close(self.sock);
        alloc.free(self.r_buf);
        alloc.free(self.w_buf);
    }

    /// Step through the DORA Process
    pub fn step(self: *@This()) !void {
        if (self.timer.lap() >= self.timeout * time.ns_per_ms) //
            return error.Timeout;
        state: switch (self.state) {
            // DISCOVER
            .discover => {
                var sock_w = &self.writer.io_writer;
                // - Create and write BOOTP header
                const disc_hdr = l5.BOOTP.Header {
                    .op = c(l5.BOOTP.OP).REQUEST,
                    .tx_id = self.transaction_id,
                    .client_hw_addr = self.mac_addr ++ @as([10]u8, @splat(0)),
                };
                try sock_w.writeStruct(disc_hdr, .big);
                // - Add DHCP Message Type option
                try sock_w.writeStruct(dhcp_msg_type, .big);
                try sock_w.writeByte(c(l5.DHCP.MessageType).DISCOVER);
                // - Add Parameter Request List
                try sock_w.writeStruct(params_req_hdr, .big);
                _ = try sock_w.write(params_reqs_list);
                // - Add Client ID option
                try sock_w.writeStruct(client_id, .big);
                try sock_w.writeByte(1);
                _ = try sock_w.write(self.mac_addr[0..]);
                // - Add Max Message Size option
                try sock_w.writeStruct(max_msg_size, .big);
                try sock_w.writeInt(u16, 1500, .big);
                // - Custom IP
                if (self.config.ip_addr) |ip| {
                    const req_ip_addr: l5.BOOTP.OptionHeader = .{
                        .code = c(l5.DHCP.OptionCode).REQUESTED_IP,
                        .len = 4,
                    };
                    try sock_w.writeStruct(req_ip_addr, .big);
                    _ = try sock_w.write(ip[0..]);
                }
                // - End Option
                try sock_w.writeByte(c(l5.DHCP.OptionCode).END);
                // - Send Discovery
                try sendDHCPMsg(
                    sock_w,
                    self.mac_addr,
                    @splat(0xFF),
                );
                log.debug(
                    \\
                    \\-------------------------------------
                    \\DISCOVER:
                    \\ - Transaction ID: 0x{X:0>8}
                    \\ - Client MAC:     {f}
                    //\\ - Options Length: {d}B
                    \\
                    , .{
                        self.transaction_id,
                        MACF{ .bytes = self.mac_addr[0..] },
                        //sock_w.end - bootp_hdr_len,
                    },
                );
                self.state = .offer;
                continue :state self.state;
            },
            // OFFER
            .offer => {
                var sock_r = &self.reader.io_reader;
                const offer_hdr: l5.BOOTP.Header = offerHdr: {
                    recvDHCPMsg(sock_r, self.mac_addr) catch |err| switch (err) {
                        error.ReadFailed => return err,
                        else => {
                            log.warn("Unexpected DHCP Response: {t}", .{ err });
                            return error.UnexpectedResponse;
                        },
                    };
                    // - Parse BOOTP header
                    const offer_hdr = try sock_r.takeStruct(l5.BOOTP.Header, .big);
                    if (offer_hdr.tx_id != self.transaction_id) {
                        log.warn(
                            \\Transaction ID Mismatch:
                            \\ - Expected: 0x{X:0>8}
                            \\ - Received: 0x{X:0>8}
                            , .{
                                self.transaction_id,
                                offer_hdr.tx_id,
                            }
                        );
                        return error.TransactionIDMismatch;
                    }
                    if (offer_hdr.op != c(l5.BOOTP.OP).REPLY) {
                        log.warn("Not a BOOTP reply", .{});
                        return error.NonBOOTPReply;
                    }
                    break :offerHdr offer_hdr;
                };
                // - Parse DHCP options
                var offer_msg_type_buf: ?u8 = null;
                var offer_server_id_buf: ?[4]u8 = null;
                var offer_lease_time_buf: ?u32 = null;
                var offer_subnet_mask_buf: ?[4]u8 = null;
                var offer_router_buf: ?[4]u8 = null;
                var offer_dns_buf: ?[4]u8 = null;
                while (sock_r.seek < sock_r.end) {
                    const opt_code = try sock_r.takeByte();
                    // Check for end of options
                    if (opt_code == c(l5.DHCP.OptionCode).END) //
                        break;
                    // Skip pad option
                    if (opt_code == c(l5.DHCP.OptionCode).PAD) //
                        continue;
                    const opt_len = try sock_r.takeByte();
                    const opt_data = try sock_r.take(opt_len);
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
                }
                // - Validate OFFER
                const offer_msg_type = offer_msg_type_buf orelse {
                    log.warn("Missing Message Type", .{});
                    return error.MissingMessageType;
                };
                if (offer_msg_type != c(l5.DHCP.MessageType).OFFER) {
                    log.warn("Not a DHCP OFFER message", .{});
                    return error.NonOfferMessage;
                }
                self.ctx.offer_server_id = offer_server_id_buf orelse {
                    log.warn("No Server Identifier in OFFER", .{});
                    return error.NoServerID;
                };
                self.ctx.offer_subnet_mask = offer_subnet_mask_buf orelse {
                    log.warn("No Subnet Mask in OFFER", .{});
                    return error.NoSubnetMask;
                };
                self.ctx.offer_router = offer_router_buf orelse {
                    log.warn("No Router in OFFER", .{});
                    return error.NoRouter;
                };
                self.ctx.offer_lease_time = offer_lease_time_buf orelse {
                    log.warn("No Lease Time in OFFER", .{});
                    return error.NoLeaseTime;
                };
                self.ctx.offered_ip = offer_hdr.self_addr;
                log.debug(
                    \\
                    \\-------------------------------------
                    \\OFFER:
                    \\ - Server ID:   {f}
                    \\ - Offered IP:  {f}
                    \\ - Subnet Mask: {f}
                    \\ - Router:      {f}
                    \\ - Lease Time:  {d}s
                    \\
                    , .{
                        IPF{ .bytes = self.ctx.offer_server_id[0..] },
                        IPF{ .bytes = self.ctx.offered_ip[0..] },
                        IPF{ .bytes = self.ctx.offer_subnet_mask[0..] },
                        IPF{ .bytes = self.ctx.offer_router[0..] },
                        self.ctx.offer_lease_time,
                    },
                );
                // - Check Requested Options
                if (self.config.ip_addr) |req_ip| {
                    const mismatch = !mem.eql(u8, self.ctx.offered_ip[0..], req_ip[0..]);
                    if (mismatch and self.config.err_on_mismatch) {
                        log.err("Requested IP: {f} | Offered IP: {f}", .{ IPF{ .bytes = req_ip[0..] }, IPF{ .bytes = self.ctx.offered_ip[0..] } });
                        return error.NotGivenRequestedIP;
                    }
                    if (mismatch and !self.config.err_on_mismatch) {
                        log.warn("Requested IP: {f} | Offered IP: {f}", .{ IPF{ .bytes = req_ip[0..] }, IPF{ .bytes = self.ctx.offered_ip[0..] } });
                        return;
                    }
                }
                self.state = .request;
                continue :state self.state;
            },
            // REQUEST
            .request => {
                var sock_w = &self.writer.io_writer;
                try sock_w.flush();
                // - Create and write BOOTP header
                const req_hdr = l5.BOOTP.Header{
                    .op = c(l5.BOOTP.OP).REQUEST,
                    .tx_id = self.transaction_id,
                    .client_hw_addr = self.mac_addr ++ @as([10]u8, @splat(0)),
                };
                try sock_w.writeStruct(req_hdr, .big);
                // - Add DHCP Message Type option
                try sock_w.writeStruct(dhcp_msg_type, .big);
                try sock_w.writeByte(c(l5.DHCP.MessageType).REQUEST);
                // - Add Parameter Request List
                try sock_w.writeStruct(params_req_hdr, .big);
                _ = try sock_w.write(params_reqs_list);
                // - Add Client ID option
                try sock_w.writeStruct(client_id, .big);
                try sock_w.writeByte(1);
                _ = try sock_w.write(self.mac_addr[0..]);
                // - Add Max Message Size option
                try sock_w.writeStruct(max_msg_size, .big);
                try sock_w.writeInt(u16, 1500, .big);
                // - Add Requested IP option
                const req_ip_hdr: l5.BOOTP.OptionHeader = .{
                    .code = c(l5.DHCP.OptionCode).REQUESTED_IP,
                    .len = 4,
                };
                try sock_w.writeStruct(req_ip_hdr, .big);
                _ = try sock_w.write(self.ctx.offered_ip[0..]);
                // - Add Server ID option
                const server_id_hdr: l5.BOOTP.OptionHeader = .{
                    .code = c(l5.DHCP.OptionCode).SERVER_ID,
                    .len = 4,
                };
                try sock_w.writeStruct(server_id_hdr, .big);
                _ = try sock_w.write(self.ctx.offer_server_id[0..]);
                // - Custom Lease Time Options
                if (self.config.lease_time) |lease_time| {
                    const lease_time_hdr: l5.BOOTP.OptionHeader = .{
                        .code = c(l5.DHCP.OptionCode).LEASE_TIME,
                        .len = 4,
                    };
                    try sock_w.writeStruct(lease_time_hdr, .big);
                    try sock_w.writeInt(u32, lease_time, .big);
                }
                if (self.config.renewal_time) |renewal_time| {
                    const renewal_time_hdr: l5.BOOTP.OptionHeader = .{
                        .code = c(l5.DHCP.OptionCode).RENEWAL_TIME,
                        .len = 4,
                    };
                    try sock_w.writeStruct(renewal_time_hdr, .big);
                    try sock_w.writeInt(u32, renewal_time, .big);
                }
                if (self.config.rebinding_time) |rebinding_time| {
                    const rebinding_time_hdr: l5.BOOTP.OptionHeader = .{
                        .code = c(l5.DHCP.OptionCode).REBINDING_TIME,
                        .len = 4,
                    };
                    try sock_w.writeStruct(rebinding_time_hdr, .big);
                    try sock_w.writeInt(u32, rebinding_time, .big);
                }
                // -----------------------------
                // - Add Host Name if configured
                if (self.config.hostname) |hostname| {
                    log.debug("Using Hostname '{s}'.", .{ hostname });
                    const hostname_hdr: l5.BOOTP.OptionHeader = .{
                        .code = c(l5.DHCP.OptionCode).HOSTNAME,
                        .len = @truncate(hostname.len),
                    };
                    try sock_w.writeStruct(hostname_hdr, .big);
                    _ = try sock_w.write(hostname);
                }
                // - End Option
                try sock_w.writeByte(c(l5.DHCP.OptionCode).END);
                // - Send Request
                try sendDHCPMsg(
                    sock_w,
                    self.mac_addr,
                    @splat(0xFF),
                );
                log.debug(
                    \\
                    \\-------------------------------------
                    \\REQUEST:
                    \\ - Transaction ID: 0x{X:0>8}
                    \\ - Client MAC:     {f}
                    \\ - Server ID:      {f}
                    \\ - Requested IP:   {f}
                    //\\ - Options Length: {d}B
                    \\
                    , .{
                        self.transaction_id,
                        MACF{ .bytes = self.mac_addr[0..] },
                        IPF{ .bytes = self.ctx.offer_server_id[0..] },
                        IPF{ .bytes = self.ctx.offered_ip[0..] },
                        //sock_w.end - bootp_hdr_len,
                    },
                );
                self.state = .ack;
                continue :state self.state;
            },
            // ACK/NAK
            .ack => {
                var sock_r = &self.reader.io_reader;
                const ack_header: l5.BOOTP.Header = ack: {
                    recvDHCPMsg(sock_r, self.mac_addr) catch |err| switch (err) {
                        error.ReadFailed => return err,
                        else => {
                            log.warn("Unexpected DHCP Response: {t}", .{ err });
                            return error.UnexpectedResponse;
                        },
                    };
                    // - Parse BOOTP header
                    const ack_header = try sock_r.takeStruct(l5.BOOTP.Header, .big);
                    // - Validate transaction ID
                    if (ack_header.tx_id != self.transaction_id) {
                        log.warn(
                            \\Transaction ID Mismatch:
                            \\ - Expected: 0x{X:0>8}
                            \\ - Received: 0x{X:0>8}
                            , .{
                                self.transaction_id,
                                ack_header.tx_id,
                            }
                        );
                        return error.TransactionIDMismatch;
                    }
                    if (ack_header.op != c(l5.BOOTP.OP).REPLY) {
                        log.warn("Not a BOOTP reply", .{});
                        return error.NonBOOTPReply;
                    }
                    break :ack ack_header;
                };
                // - Parse DHCP options
                var ack_msg_type_buf: ?u8 = null;
                var ack_server_id_buf: ?[4]u8 = null;
                var ack_lease_time_buf: ?u32 = null;
                var ack_subnet_mask_buf: ?[4]u8 = null;
                var ack_router_buf: ?[4]u8 = null;
                var ack_dns_buf: [4]?[4]u8 = @splat(null);
                while (sock_r.seek < sock_r.end) {
                    const opt_code = try sock_r.takeByte();
                    // Check for end of options
                    if (opt_code == c(l5.DHCP.OptionCode).END) //
                        break;
                    // Skip pad option
                    if (opt_code == c(l5.DHCP.OptionCode).PAD) //
                        continue;
                    const opt_len = try sock_r.takeByte();
                    const opt_data = try sock_r.take(opt_len);
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
                }
                // - Validate ACK
                const ack_msg_type = ack_msg_type_buf orelse {
                    log.warn("Missing Message Type", .{});
                    return error.MissingMessageType;
                };
                const ack_server_id = ack_server_id_buf orelse {
                    log.warn("No Server Identifier in ACK", .{});
                    return error.NoServerID;
                };
                const ack_subnet_mask = ack_subnet_mask_buf orelse {
                    log.warn("No Subnet Mask in ACK", .{});
                    return error.NoSubnetMask;
                };
                const ack_router = ack_router_buf orelse {
                    log.warn("No Router in ACK", .{});
                    return error.NoRouter;
                };
                const ack_lease_time = ack_lease_time_buf orelse {
                    log.warn("No Lease Time in ACK", .{});
                    return error.NoLeaseTime;
                };
                const ack_dns = ack_dns_buf[0] orelse {
                    log.warn("No DNS in ACK", .{});
                    return error.NoDNS;
                };
                switch (ack_msg_type) {
                    c(l5.DHCP.MessageType).ACK => {
                        const assigned_ip = ack_header.self_addr;
                        log.info(
                            \\
                            \\-------------------------------------
                            \\ACK:
                            \\ - Server ID:   {f}
                            \\ - Assigned IP: {f}
                            \\ - Subnet Mask: {f}
                            \\ - Router:      {f}
                            \\ - DNS:         {f}
                            \\ - Lease Time:  {d}s
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
                        self.state = .{ .end = .{
                            .assigned_ip = assigned_ip,
                            .subnet_mask = ack_subnet_mask,
                            .router = ack_router,
                            .server_id = ack_server_id,
                            .dns_ips = ack_dns_buf,
                        } };
                        continue :state self.state;
                    },
                    c(l5.DHCP.MessageType).NAK => {
                        log.warn("Received DHCP NAK", .{});
                        return error.ReceivedDHCPNAK;
                    },
                    else => {
                        log.warn(
                            "Unexpected message type: {d}",
                            .{ ack_msg_type },
                        );
                        return error.UnexpectedMessageType;
                    },
                }
            },
            .end => {},
        }
    }
};

/// Release DHCP lease
pub fn releaseDHCP(
    if_name: []const u8,
    if_index: i32,
    mac_addr: [6]u8,
    server_id: [4]u8,
    client_ip: [4]u8,
) !void {
    log.info("Releasing DHCP lease...", .{});
    defer log.debug("DHCP lease released!", .{});
    const sock = try posix.socket(posix.AF.PACKET, posix.SOCK.RAW, mem.nativeToBig(u16, c(Eth.ETH_P).IPv4));
    defer posix.close(sock);
    const sock_addr = posix.sockaddr.ll{
        .ifindex = if_index,
        .protocol = mem.nativeToBig(u16, c(Eth.ETH_P).IPv4),
        .hatype = 0,
        .pkttype = 0,
        .halen = 6,
        .addr = @splat(0),
    };
    // Bind to the Interface
    try posix.setsockopt(
        sock,
        posix.SOL.SOCKET,
        posix.SO.BINDTODEVICE,
        if_name,
    );
    try posix.bind(sock, @ptrCast(&sock_addr), @sizeOf(posix.sockaddr.ll));
    var buf: [1500]u8 = undefined;
    var dhcp_writer: SockWriter = .init(sock, buf[0..], 0);
    var dhcp_w = &dhcp_writer.io_writer;
    // BOOTP Setup
    // - Create transaction ID
    const transaction_id: u32 = transactionID: {
        var bytes: [4]u8 = undefined;
        crypto.random.bytes(bytes[0..]);
        break :transactionID mem.bytesToValue(u32, bytes[0..]);
    };
    // - Create and write BOOTP header
    const rel_hdr = l5.BOOTP.Header{
        .op = c(l5.BOOTP.OP).REQUEST,
        .tx_id = transaction_id,
        .client_hw_addr = mac_addr ++ @as([10]u8, @splat(0)),
        .client_addr = client_ip,
    };
    try dhcp_w.writeStruct(rel_hdr, .big);
    // - Add DHCP Message Type option
    const dhcp_msg_type: l5.BOOTP.OptionHeader = .{
        .code = c(l5.DHCP.OptionCode).MESSAGE_TYPE,
        .len = 1,
    };
    try dhcp_w.writeStruct(dhcp_msg_type, .big);
    try dhcp_w.writeByte(c(l5.DHCP.MessageType).RELEASE);
    // - Add Server ID option
    const server_id_hdr: l5.BOOTP.OptionHeader = .{
        .code = c(l5.DHCP.OptionCode).SERVER_ID,
        .len = 4,
    };
    try dhcp_w.writeStruct(server_id_hdr, .big);
    _ = try dhcp_w.write(server_id[0..]);
    // - Add Client ID Option
    const client_id: l5.BOOTP.OptionHeader = .{
        .code = c(l5.DHCP.OptionCode).CLIENT_ID,
        .len = 7,
    };
    try dhcp_w.writeStruct(client_id, .big);
    try dhcp_w.writeByte(1);
    // - Hardware Type (ethernet)
    _ = try dhcp_w.write(mac_addr[0..]);
    // - End Option
    try dhcp_w.writeByte(c(l5.DHCP.OptionCode).END);
    // Send Release
    try sendDHCPMsg(
        dhcp_w,
        mac_addr,
        server_id,
    );
    log.info(
        \\
        \\-------------------------------------
        \\RELEASE:
        \\ - Transaction ID: 0x{X:0>8}
        \\ - Client MAC:     {f}
        \\ - Client IP:      {f}
        \\ - Server ID:      {f}
        //\\ - Options Length: {d}B
        \\
        , .{
            transaction_id,
            MACF{ .bytes = mac_addr[0..] },
            IPF{ .bytes = client_ip[0..] },
            IPF{ .bytes = server_id[0..] },
            //end - bootp_hdr_len,
        },
    );
}
