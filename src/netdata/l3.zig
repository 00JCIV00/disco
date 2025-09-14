//! Components of the base Packet structure for IP and ICMP packets.

const std = @import("std");
const mem = std.mem;

const utils = @import("../utils.zig");
const c = utils.toStruct;


/// IP - [IETC RFC 791](https://datatracker.ietf.org/doc/html/rfc791#section-3.1)
pub const IP = struct {
    /// Net IP Header
    pub const NetHeader = extern struct {
        ver_len: u8,
        service_type: u8,
        total_len: u16,
        id: u16,
        flag_frag: u16,
        ttl: u8,
        protocol: u8,
        checksum: u16,
        src: u32,
        dst: u32,

        pub fn fromHeader(hdr: Header) @This() {
            return .{
                .ver_len = @as(u8, @intCast(hdr.version)) << 4 | @as(u8, @intCast(hdr.ip_header_len)),
                .service_type = @bitCast(hdr.service_type),
                .total_len = mem.nativeToBig(u16, hdr.total_len),
                .id = mem.nativeToBig(u16, hdr.id),
                .flag_frag = mem.nativeToBig(u16, @as(u16, @as(u3, @bitCast(hdr.flags))) << 13 | @as(u16, @as(u13, @bitCast(hdr.frag_offset)))),
                .ttl = hdr.time_to_live,
                .protocol = hdr.protocol,
                .checksum = hdr.header_checksum,
                .src = hdr.src_ip_addr,
                .dst = hdr.dst_ip_addr,
            };
        }

        pub fn toHeader(self: *const @This()) Header {
            return .{
                .version = @intCast(self.ver_len >> 4),
                .ip_header_len = @truncate(self.ver_len),
                .service_type = @bitCast(self.service_type),
                .total_len = mem.bigToNative(u16, self.total_len),
                .id = mem.bigToNative(u16, self.id),
                .flags = @bitCast(@as(u3, @truncate(mem.bigToNative(u16, self.flag_frag) >> 13))),
                .frag_offset = @bitCast(@as(u13, @truncate(mem.bigToNative(u16, self.flag_frag)))),
                .time_to_live = self.ttl,
                .protocol = self.protocol,
                .header_checksum = mem.bigToNative(u16, self.checksum),
                .src_ip_addr = self.src,
                .dst_ip_addr = self.dst,
            };
        }
    };

    /// IP Header
    pub const Header = packed struct {
        version: u4 = 4,
        ip_header_len: u4 = 5,
        service_type: ServiceType = .{},
        total_len: u16 = 20,
        id: u16 = 0,
        flags: Flags = .{},
        frag_offset: u13 = 0,
        time_to_live: u8 = 64,
        protocol: u8 = c(Protocols).UDP,
        header_checksum: u16 = 0,
        src_ip_addr: u32 = 0,
        dst_ip_addr: u32 = 0,

        /// IP Header Service Type Info
        pub const ServiceType = packed struct(u8) {
            precedence: u3 = c(ServicePrecedence).ROUTINE,
            delay: u1 = 0,
            throughput: u1 = 0,
            relibility: u1 = 0,
            reserved: u2 = 0,
        };

        /// IP Header Flags Info
        pub const Flags = packed struct(u3) {
            reserved: bool = false,
            dont_frag: bool = false,
            more_frags: bool = false,
        };

        // IP Packet Service Precedence Levels
        pub const ServicePrecedence = enum(u3) {
            ROUTINE = 0,
            PRIORITY = 1,
            IMMEDIATE = 2,
            FLASH = 3,
            FLASH_OVERRIDE = 4,
            CRITIC = 5,
            INTERNETWORK_CONTROL = 6,
            NETWORK_CONTROL = 7,
        };

        /// IP Protocols
        pub const Protocols = enum(u8) {
            ICMP = 1,
            IGMP = 2,
            TCP = 6,
            UDP = 17,
            ENCAP = 41,
            OSPF = 89,
            SCTP = 132,
        };

        ///// Calculate the Total Length and Checksum of this IP Packet
        //pub fn calcLengthAndChecksum(self: *@This(), alloc: mem.Allocator, _: ?[]const u8, opts_len: u16, payload: []const u8) !void {
        //    const hdr_len: u16 = @bitSizeOf(IP.Header) / 8; 
        //    self.total_len = hdr_len + @as(u16, @intCast(payload.len));
        //    self.ip_header_len = @truncate((hdr_len + opts_len) / 4);
        //    self.header_checksum = 0;
        //    const header_bytes = try self.asNetBytesBFG(alloc);
        //    self.header_checksum = calcChecksum(header_bytes);
        //}
    };

    /// Segment Pseudo Header
    /// Does NOT include the Segment Length, which is handled at the Segment level (Layer 4).
    pub const SegmentPseudoHeader = extern struct {
        src_ip_addr: u32 = 0,
        dst_ip_addr: u32 = 0,
        __zeroes: u8 = 0,
        protocol: u8 = c(Header.Protocols).UDP,
        len: u16 = 0,
    };

    /// IP Options
    pub const Option = struct{
        opt_type: OptionType = .{},
        len: ?u8 = null,
        data: ?[]const u8 = null,

        ///// Create a new IP Option from the provided Byte Buffer (`byte_buf`).
        //pub fn from(byte_buf: []const u8) !@This() {
        //    if (byte_buf.len == 0) return error.EmptyByteBuffer;
        //    if (!OptionTypes.inEnum(byte_buf[0])) return error.UnimplementedType;
        //    return switch (@as(OptionTypes.Enum(), @enumFromInt(byte_buf[0]))) {
        //        .END_OF_OPTS, .NO_OP => .{ 
        //            .opt_type = @bitCast(byte_buf[0]),
        //            .data = byte_buf[3..7],
        //        },
        //        else =>  .{
        //            .opt_type = @bitCast(byte_buf[0]),
        //            .len = byte_buf[1],
        //            .data = byte_buf[2..(byte_buf[1] + (4 - (byte_buf[1] % 4 )))],
        //        }
        //    };
        //}
        
        /// IP Option Type
        pub const OptionType = packed struct{
            copied_flag: bool = false,
            opt_class: u2 = 0,
            opt_num: u5 = 0,

            pub const OptionClasses = enum(u2) {
                CONTROL = 0,
                RESERVED = 1,
                DEBUG = 2,
                RESERVED2 = 3,
            };
        };

        /// IP Option Types
        pub const OptionTypes = enum(u8) {
            END_OF_OPTS = 0,
            NO_OP = 1,
            RECORD_ROUTE = 7,
            TIMESTAMP = 68,
            SECURITY = 130,
            /// Loose Source and Record Route
            LSRR = 131,
            STREAM_ID = 136,
            /// Strict Source and Record Route
            SSRR = 137,
        };

        /// IP Option Lengths
        pub fn getLength(opt_type: OptionTypes.Enum) u8 {
            return switch (opt_type) {
                .RECORD_ROUTE => 0,
                .TIMESTAMP => 0,
                .SECURITY => 11,
                .LSRR => 131,
                .STREAM_ID => 136,
                .SSRR => 137,
                else => 0,
            };
        }
    };

    /// Create a new IP Packet from the provided Byte Buffer (`byte_buf`) using the provided Allocator (`alloc`).
    pub fn from(alloc: mem.Allocator, byte_buf: []const u8) !@This() {
        const hdr_end: u16 = @bitSizeOf(Header) / 8;
        if (byte_buf.len < hdr_end) return error.UnexpectedlySmallBuffer;
        var size_buf: [@sizeOf(Header)]u8 = @splat(0);
        for (size_buf[0..hdr_end], byte_buf[0..hdr_end]) |*s, b| s.* = b;
        var hdr: Header = mem.bytesToValue(Header, size_buf[0..]);
        try hdr.toLSB();
        const ip_len: u16 = hdr.ip_header_len * @as(u16, 4);
        //const ip_len: u16 = @intCast(hdr.ip_header_len * 4);
        const p_hdr_end: u16 = ip_len + @as(u16, switch (@as(Header.Protocols.Enum(), @enumFromInt(hdr.protocol))) {
            .TCP, .UDP => @bitSizeOf(SegmentPseudoHeader) / 8,
            else => 0,
        });
        return .{
            .header = hdr,
            .options = 
                if (ip_len > 20) opts: {
                    const opts_raw_buf = byte_buf[hdr_end..ip_len];
                    var opts_list = std.ArrayList(Option).init(alloc);
                    var idx: u16 = 0;
                    while (idx < opts_raw_buf.len) {
                        const opt = try Option.from(opts_raw_buf[idx..]);
                        idx += @bitSizeOf(@TypeOf(opt));
                        try opts_list.append(opt);
                    }
                    break :opts try opts_list.toOwnedSlice();
                }
                else null,
            .pseudo_header = 
                if (p_hdr_end -| hdr_end > 0) pHdr: {
                    const pseudo_size = @bitSizeOf(SegmentPseudoHeader) / 8;
                    var pseudo_buf: [@sizeOf(SegmentPseudoHeader)]u8 = @splat(0);
                    for (pseudo_buf[0..pseudo_size], byte_buf[hdr_end..(hdr_end + pseudo_size)]) |*s, b| s.* = b;
                    break :pHdr mem.bytesToValue(SegmentPseudoHeader, pseudo_buf[0..]);
                }
                else null,
            .len = ip_len,
        };
    }
};


/// ICMP - [IETF RFC 792](https://datatracker.ietf.org/doc/html/rfc792)
pub const ICMP = packed struct{
    /// ICMP Header
    pub const Header = packed struct(u64) {
        icmp_type: u8 = c(Types).DEST_UNREACHABLE,
        code: u8 = c(Codes.DEST_UNREACHABLE).NET,
        checksum: u16 = 0,
        // TODO - Create an Option for the final Word (32-bit) which can vary.
        id: u16 = 1,
        seq_num: u16 = 0,

        /// ICMP Types
        pub const Types = enum(u8) {
            ECHO_REPLY = 0,
            DEST_UNREACHABLE = 3,
            SRC_QUENCH = 4,
            REDIRECT = 5,
            ECHO = 8,
            TIME_EXCEEDED = 11,
            PARAM_PROBLEM = 12,
            TIMESTAMP = 13,
            TIMESTAMP_REPLY = 14,
            INFO_REQUEST = 15,
            INFO_REPLY = 16,
        };

        /// ICMP Codes
        pub const Codes = struct {
            pub const DEST_UNREACHABLE = enum(u8) {
                NET = 0,
                HOST = 1,
                PROTOCOL = 2,
                PORT = 3,
                FRAG_NEEDED = 4,
                SRC_ROUTE_FAILED = 5,
            };
            pub const TIME_EXCEEDED = enum(u8) {
                TTL = 0,
                FRAG_REASSEMBLY = 1,
            };
            pub const REDIRECT = enum(u8) {
                NETWORK = 0,
                HOST = 1,
                TOS_AND_NETWORK = 2,
                TOS_AND_HOST = 3,
            };
        };

        ///// Calculates the total Length (in Bytes) and the Checksum (from 16-bit words) of this ICMP Header with the given payload.
        //pub fn calcLengthAndChecksum(self: *@This(), alloc: mem.Allocator, _: ?[]const u8, _: u16, payload: []const u8) !void {
        //    var icmp_hdr_bytes = try self.asNetBytesBFG(alloc);
        //    const icmp_bytes = try mem.concat(alloc, u8, &.{ icmp_hdr_bytes[0..], payload });
        //    defer alloc.free(icmp_bytes);
        //    self.checksum = calcChecksum(icmp_bytes);
        //}
    };
};



