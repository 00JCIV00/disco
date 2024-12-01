//! Network Address Types & Functions

const std = @import("std");
const ascii = std.ascii;
const io = std.io;
const fmt = std.fmt;
const mem = std.mem;

/// Print a Network Address (IPv4, IPv6, MAC)
pub fn printAddr(
    bytes: []const u8, 
    comptime sep: []const u8, 
    comptime byte_fmt: []const u8, 
    writer: io.AnyWriter,
) !void {
    if (bytes.len == 0) return;
    try writer.print(byte_fmt, .{ bytes[0] });
    if (bytes.len == 1) return;
    for (bytes[1..]) |byte| try writer.print(sep ++ byte_fmt, .{ byte });
}

/// Parse a MAC Address from the provided String (`str`).
pub fn parseMAC(str: []const u8, _: mem.Allocator) ![6]u8 {
    if (str.len < 12 or str.len > 17)
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
    var addr_buf: [6]u8 = undefined;
    for (addr_buf[0..], 0..) |*byte, addr_idx| {
        const start = addr_idx * 2;
        const end = start + 2;
        byte.* = try fmt.parseInt(u8, text_buf[start..end], 16);
    }
    return addr_buf;
}

/// Parse an IP Address from the provided String (`str`).
pub fn parseIP(str: []const u8, _: mem.Allocator) ![4]u8 {
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
pub fn parseSubnet(str: []const u8, _: mem.Allocator) ![4]u8 {
    if (str.len == 0 or str.len > 15) return error.InvalidSubnet;
    if (str.len < 4) {
        const cidr = try fmt.parseInt(u8, str, 10);
        if (cidr > 32) return error.InvalidCIDR;
        var bytes_int: u32 = 1;
        bytes_int <<= @intCast(32 - cidr);
        return mem.toBytes(bytes_int);
    }
    // TODO Rework unneeded allocator
    const subnet = try parseIP(str, std.heap.page_allocator);
    for (subnet[1..4], 0..) |b, i| {
        if (b >= subnet[i]) continue;
        return error.InvalidSubnet;
    }
    return subnet;
}

/// Parse a Subnet Mask in CIDR Notation from the provided String (`str`).
pub fn parseCIDR(str: []const u8, _: mem.Allocator) !u8 {
    const cidr = switch (str.len) {
        1...4 => try fmt.parseInt(u8, str, 0),
        7...15 => subnet: {
            // TODO Rework unneeded allocator
            const bytes = try parseSubnet(str, std.heap.page_allocator);
            const num = mem.bytesToValue(u32, bytes[0..]);
            var cidr: u8 = 0;
            for (0..32) |i| {
                if (num >> @intCast(i) & 1 == 1) cidr += 1;
            }
            break :subnet cidr;
        },
        else => return error.InvalidCIDR,
    };
    return if (cidr <= 32) cidr else error.InvalidCIDR;
}
