//! Network Data Types & Functions for DisCo.

const std = @import("std");
const mem = std.mem;
const meta = std.meta;

pub const address = @import("netdata/address.zig");
pub const l2 = @import("netdata/l2.zig");
pub const l3 = @import("netdata/l3.zig");
pub const l4 = @import("netdata/l4.zig");
pub const l5 = @import("netdata/l5.zig");
pub const oui = @import("netdata/oui.zig");
pub const pcap = @import("netdata/pcap.zig");


/// Calculate the Cyclic Redundancy Check (CRC) using the provided `payload` for the Frame Check Sequence (FCS) of Ethernet-like Frame Footers.
pub fn calcCRC(payload: []u8) !u32 {
    const poly = 0xEDB88320;
    var crc: u32 = 0xFFFFFFFF;
    for (payload) |byte| {
        crc ^= byte;
        var i: u4 = 0;
        while (i < 8) : (i += 1) {
            const mask: u32 = @bitCast(-(@as(i32, @bitCast(crc)) & 1));
            crc = (crc >> 1) ^ (poly & mask);
        }
    }
    //return mem.nativeToBig(u32, ~crc);
    return ~crc;
}

/// Calculate the Checksum from the given bytes for IP-like Headers. TODO - Handle bit carryovers
pub fn calcChecksum(bytes: []u8) u16 {
    const buf_end = if (bytes.len % 2 == 0) bytes.len else bytes.len - 1;
    const words = mem.bytesAsSlice(u16, bytes[0..buf_end]);
    var sum: u32 = 0;
    for (words) |word| sum += word;
    if (buf_end < bytes.len) sum += @intCast(bytes[bytes.len - 1]);
    while ((sum >> 16) > 0) sum = (sum & 0xFFFF) + (sum >> 16);
    //return mem.nativeToBig(u16, @as(u16, @truncate(~sum)));
    return @as(u16, @truncate(~sum));
}

/// Return a Byte Array for the given Header Type (`HdrT`) instance (`hdr`) in Network Byte Order
pub fn asNetBytes(HdrT: type, hdr: HdrT) [@bitSizeOf(HdrT) / 8]u8 {
    var net_hdr: HdrT = undefined;
    inline for (meta.fields(HdrT)) |field| {
        switch (@typeInfo(field.type)) {
            .Int => @field(net_hdr, field.name) = mem.nativeToBig(field.type, @field(hdr, field.name)),
            else => {},
        }
    }
    return mem.toBytes(hdr);
}

/// Return an instance of the provided Header Type (`HdrT`) with Native Endian fields from the given `bytes`.
pub fn asNativeHeader(HdrT: type, bytes: []const u8) HdrT {
    var net_hdr: HdrT = mem.bytesToValue(HdrT, bytes);
    inline for (meta.fields(HdrT)) |field| cont: {
        if (@typeInfo(field.type) != .int) break :cont;
        @field(net_hdr, field.name) = mem.bigToNative(field.type, @field(net_hdr, field.name));
    }
    return net_hdr;
}
