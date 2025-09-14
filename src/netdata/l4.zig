//! Components of the base Packet structure for TCP and UDP packets.

const std = @import("std");
const mem = std.mem;

/// UDP - [IETF RFC 768](https://datatracker.ietf.org/doc/html/rfc768)
pub const UDP = struct {
    /// Header
    pub const Header = extern struct {
        src_port: u16 = 0,
        dst_port: u16 = 0,
        length: u16 = 8,
        checksum: u16 = 0,

        ///// Calculates the total Length (in Bytes) and the Checksum (from 16-bit words) of this UDP Header with the given payload.
        //pub fn calcLengthAndChecksum(self: *@This(), alloc: mem.Allocator, pseudo_header: ?[]const u8, _: u16, payload: []const u8) !void {
        //    const pseudo_hdr = pseudo_header orelse return error.MissingSegmentHeader;
        //    self.length = @intCast(@bitSizeOf(@This()) / 8 + payload.len);
        //    var udp_hdr_bytes = try self.asNetBytesBFG(alloc);
        //    const udp_bytes = try mem.concat(alloc, u8, &.{ pseudo_hdr, udp_hdr_bytes[4..6], udp_hdr_bytes[0..], payload });
        //    defer alloc.free(udp_bytes);
        //    self.checksum = calcChecksum(udp_bytes);
        //}
    };
};

/// TCP - [IETF RFC 9293](https://www.ietf.org/rfc/rfc9293.html)
pub const TCP = struct {
    /// Header
    pub const Header = packed struct {
        src_port: u16 = 0,
        dst_port: u16 = 0,
        seq_num: u32 = 0,
        ack_num: u32 = 0,
        data_offset: u4 = 5,
        reserved: u4 = 0,
        flags: Flag = .{},
        window: u16 = 0,
        checksum: u16 = 0,
        urg_pointer: u16 = 0,

        pub const Flag = packed struct(u8) {
            cwr: bool = false,
            ece: bool = false,
            urg: bool = false,
            ack: bool = false,
            psh: bool = false,
            rst: bool = false,
            syn: bool = false,
            fin: bool = true,
        };

        pub const Flags = enum(u8) {
            CWR = @bitReverse(@as(u8, 0b10000000)),
            ECE = @bitReverse(@as(u8, 0b01000000)),
            URG = @bitReverse(@as(u8, 0b00100000)),
            ACK = @bitReverse(@as(u8, 0b00010000)),
            PSH = @bitReverse(@as(u8, 0b00001000)),
            RST = @bitReverse(@as(u8, 0b00000100)),
            SYN = @bitReverse(@as(u8, 0b00000010)),
            FIN = @bitReverse(@as(u8, 0b00000001)),
        };

        ///// Calculates the total Length (in Bytes) and the Checksum (from 16-bit words) of this UDP Header with the given payload.
        //pub fn calcLengthAndChecksum(self: *@This(), alloc: mem.Allocator, pseudo_header: ?[]const u8, opts_len: u16, payload: []const u8) !void {
        //    const pseudo_hdr = pseudo_header orelse return error.MissingSegmentHeader;

        //    self.data_offset = @as(u4, @intCast(@bitSizeOf(@This()) / 32)) + if (opts_len > 0) @as(u4, @truncate(opts_len / 4)) else 0;
        //    var tcp_hdr_bytes = try self.asNetBytesBFG(alloc);
        //    const tcp_hdr_len: u16 = mem.nativeToBig(u16, @as(u16, @truncate(tcp_hdr_bytes.len)) + @as(u16, @truncate(payload.len)));

        //    const tcp_bytes = try mem.concat(alloc, u8, &.{ pseudo_hdr, &@as([2]u8, @bitCast(tcp_hdr_len)), tcp_hdr_bytes[0..], payload });
        //    defer alloc.free(tcp_bytes);

        //    self.checksum = calcChecksum(tcp_bytes);
        //}
    };

    /// TCP Option
    pub const Option = struct{
        kind: u8 = 0,
        len: ?u8 = null,
        data: ?[]const u8 = null,

        /// Create a new TCP Option from the provided Byte Buffer (`byte_buf`).
        pub fn from(byte_buf: []const u8) !@This() {
            if (byte_buf.len == 0) return error.EmptyByteBuffer;
            return switch (@as(OptionKinds.Enum(), @enumFromInt(byte_buf[0]))) {
                .END_OF_OPTS, .NO_OP => .{ .kind = @bitCast(byte_buf[0]) },
                else =>  .{
                    .kind = @bitCast(byte_buf[0]),
                    .len = byte_buf[1],
                    .data = byte_buf[2..(byte_buf[1] + (4 - (byte_buf[1] % 4 )))],
                }
            };
        }
    };
    /// TCP Option Kinds
    pub const OptionKinds = enum(u8) {
        END_OF_OPTS = 0,
        NO_OP = 1,
        MAX_SEG_SIZE = 2,
    };

    /// Create a new TCP Packet from the provided Byte Buffer (`byte_buf`) using the provided Allocator (`alloc`).
    pub fn from(alloc: mem.Allocator, byte_buf: []const u8) !@This() {
        const hdr_end = @bitSizeOf(Header) / 8;
        if (byte_buf.len < hdr_end) return error.UnexpectedlySmallBuffer;
        var size_buf: [@sizeOf(Header)]u8 = @splat(0);
        for (size_buf[0..hdr_end], byte_buf[0..hdr_end]) |*s, b| s.* = b;
        var hdr: Header = mem.bytesToValue(Header, size_buf[0..]);
        try hdr.toLSB();
        const tcp_end = hdr.data_offset * @as(u16, 4);
        return .{
            .header = hdr,
            .options = 
                if (hdr_end > 20) opts: {
                    const opts_raw_buf = byte_buf[hdr_end..tcp_end];
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
            .len = tcp_end,
        };
    }
};
