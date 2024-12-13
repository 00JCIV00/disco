//! Network Address Types & Functions

const std = @import("std");
const ascii = std.ascii;
const crypto = std.crypto;
const io = std.io;
const fmt = std.fmt;
const mem = std.mem;

const oui = @import("oui.zig");


/// Print a Network Address (IPv4, IPv6, MAC) using the provided `writer`.
pub fn printAddr(
    bytes: []const u8, 
    comptime sep: []const u8, 
    comptime byte_fmt: []const u8, 
    writer: anytype,//io.AnyWriter,
) !void {
    if (bytes.len == 0) return;
    try writer.print(byte_fmt, .{ bytes[0] });
    if (bytes.len == 1) return;
    for (bytes[1..]) |byte| try writer.print(sep ++ byte_fmt, .{ byte });
}

/// Print a Network Address (IPv4, IPv6, MAC) using the provided Allocator (`alloc`).
pub fn printAddrAlloc(
    bytes: []const u8,
    comptime sep: []const u8,
    comptime byte_fmt: []const u8,
    alloc: mem.Allocator,
) ![]const u8 {
    var buf = std.ArrayListUnmanaged(u8){};
    errdefer buf.deinit(alloc);
    const writer = buf.writer(alloc).any();
    try printAddr(
        bytes,
        sep,
        byte_fmt,
        writer,
    );
    return try buf.toOwnedSlice(alloc);
}

/// Address Formatter f/ Inlining Address Printing
pub fn Formatter(comptime sep: []const u8, comptime byte_fmt: []const u8) type {
    return struct {
        bytes: []const u8,

        pub fn format(
            self: @This(), 
            _: []const u8, 
            _: fmt.FormatOptions, 
            writer: anytype,
        ) !void {
            try printAddr(
                self.bytes,
                sep,
                byte_fmt,
                writer,
            );
        }
    };
}
/// MAC Formatter
pub const MACFormatter = Formatter(":", "{X:0>2}");
/// IP Formatter
pub const IPFormatter = Formatter(".", "{d}");

/// IPv4 Address
pub const IPv4 = struct {
    pub const default = @This(){
        .addr = .{ 0, 0, 0, 0 },
        .cidr = 0,
    };
    addr: [4]u8,
    cidr: u8 = 24,

    /// Get an IPv4 w/ or w/o CIDR from the provided String (`str`);
    pub fn fromStr(str: []const u8) !@This() {
        if (ascii.eqlIgnoreCase(str, "default")) return default;
        var ip: @This() = undefined;
        ip.cidr = 24;
        var iter = mem.tokenizeScalar(u8, str, '/');
        var idx: usize = 0;
        while (iter.next()) |item| : (idx += 1) {
            switch (idx) {
                0 => ip.addr = try parseIP(item),
                1 => ip.cidr = try parseCIDR(item),
                else => return error.InvalidIPv4,
            }
        }
        return ip;
    }

    pub fn format(
        self: @This(), 
        _: []const u8, 
        _: fmt.FormatOptions, 
        writer: anytype,
    ) !void {
        try printAddr(
            self.addr[0..],
            ".",
            "{d}",
            writer,
        );
        try writer.print("/{d}", .{ self.cidr });
    }
};

/// Parse a MAC Address from the provided String (`str`).
/// Note, this supports OUIs by filling the last 3 Bytes w/ 0.
pub fn parseMAC(mac_str: []const u8) ![6]u8 {
    const str = mem.trim(u8, mac_str, ascii.whitespace[0..]);
    if (str.len < 6 or str.len > 17)
        return error.AddressNotValid;
    var text_buf: [12]u8 = undefined;
    var idx: usize = 0;
    for (str) |c| {
        if (mem.indexOfScalar(u8, "-_: ", c) != null) 
            continue;
        if (mem.indexOfScalar(u8, "0123456789abcdefABCDEF", c) == null) 
            return error.InvalidMAC;
        text_buf[idx] = if (c >= 'A' or c < 'a') c else c + 32;
        idx += 1;
    }
    var addr_buf: [6]u8 = .{ 0 } ** 6;
    for (addr_buf[0..(idx / 2)], 0..) |*byte, addr_idx| {
        const start = addr_idx * 2;
        const end = start + 2;
        byte.* = try fmt.parseInt(u8, text_buf[start..end], 16);
    }
    return addr_buf;
}

/// Random MAC Kind
pub const RandomMACKind = enum {
    /// Fully Random MAC
    full,
    /// Link Local MAC (Like a mobile phone)
    ll,
    /// Random OUI w/ Random Bytes
    oui
};

/// Get a Random MAC
pub fn getRandomMAC(kind: RandomMACKind) [6]u8 {
    var mac: [6]u8 = undefined;
    crypto.random.bytes(mac[0..]);
    switch (kind) {
        .full => {},
        .ll => {
            const nib_idx: u2 = crypto.random.int(u2);
            mac[0] = crypto.random.int(u8) << 4 | oui.ll_rand_mac_nibbles[nib_idx];
        },
        .oui => mac[0..3].* = oui.getRandomOUI(),
    }
    return mac;
}

/// Parse an IP Address from the provided String (`str`).
pub fn parseIP(ip_str: []const u8) ![4]u8 {
    const str = mem.trim(u8, ip_str, ascii.whitespace[0..]);
    const trimmed = mem.trim(u8, str[0..], ascii.whitespace[0..]);
    var iter = mem.splitScalar(u8, trimmed, '.');
    var bytes: [4]u8 = undefined;
    var count: u3 = 0;
    while (iter.next()) |int| : (count += 1)
        bytes[count] = try fmt.parseInt(u8, int, 0);
    if (count != 4) return error.InvalidIP;
    return bytes;
}

/// Parse a Subnet Mask in IPv4 Notation from the provided String (`str`).
pub fn parseSubnet(str: []const u8) ![4]u8 {
    if (str.len == 0 or str.len > 15) return error.InvalidSubnet;
    if (str.len < 4) {
        const cidr = try fmt.parseInt(u8, str, 10);
        if (cidr > 32) return error.InvalidCIDR;
        var bytes_int: u32 = 1;
        bytes_int <<= @intCast(32 - cidr);
        return mem.toBytes(bytes_int);
    }
    // TODO Rework unneeded allocator
    const subnet = try parseIP(str);
    for (subnet[1..4], 0..) |b, i| {
        if (b >= subnet[i]) continue;
        return error.InvalidSubnet;
    }
    return subnet;
}

/// Parse a Subnet Mask in CIDR Notation from the provided String (`str`).
pub fn parseCIDR(str: []const u8) !u8 {
    const cidr = switch (str.len) {
        1...4 => try fmt.parseInt(u8, str, 0),
        7...15 => subnet: {
            // TODO Rework unneeded allocator
            const bytes = try parseSubnet(str);
            break :subnet cidrFromSubnet(bytes[0..4].*);
        },
        else => return error.InvalidCIDR,
    };
    return if (cidr <= 32) cidr else error.InvalidCIDR;
}

/// Get a CIDR from the provided `subnet`.
pub fn cidrFromSubnet(subnet: [4]u8) u8 {
    const num = mem.bytesToValue(u32, subnet[0..]);
    var cidr: u8 = 0;
    for (0..32) |i| {
        if (num >> @intCast(i) & 1 == 1) cidr += 1;
    }
    return cidr;
}
