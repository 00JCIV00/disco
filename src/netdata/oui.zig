//! Functions for easy OUI lookup.

const std = @import("std");
const ascii = std.ascii;
const crypto = std.crypto;
const fmt = std.fmt;
const mem = std.mem;

const address = @import("address.zig");
const oui_tbl = @embedFile("oui_table"); //@import("oui_table");

/// AP or Station
pub const DeviceKind = enum {
    ap,
    station,
};

/// OUI Kind
pub const OUI_Kind = enum {
    short,
    long,
};

/// Link Local Random MAC Nibbles
pub const ll_rand_mac_nibbles: []const u8 = &.{ 2, 6, 0xA, 0xE };

/// Find OUI Device Manufacturer
pub fn findOUI(
    oui_kind: OUI_Kind,
    device_kind: DeviceKind,
    mac: [6]u8,
) []const u8 {
    const rand_nib: u4 = @truncate(mac[0]);
    if (mem.indexOfScalar(u8, ll_rand_mac_nibbles, rand_nib) != null and device_kind == .station)
        return "[Random MAC]";
    var oui_rows_iter = mem.tokenizeScalar(u8, oui_tbl, '\n');
    while (oui_rows_iter.next()) |oui_row| {
        var oui_iter = mem.tokenizeScalar(u8, oui_row, '\t');
        const oui: [6]u8 = try address.parseMAC(oui_iter.next() orelse continue);
        if (!mem.eql(u8, mac[0..3], oui[0..3])) continue;
        const short = oui_iter.next() orelse continue;
        const long = oui_iter.next() orelse continue;
        return switch (oui_kind) {
            .short => mem.trim(u8, short, ascii.whitespace[0..]),
            .long => mem.trim(u8, long, ascii.whitespace[0..]),
        };
    }
    return "[No match found]";
}

/// Get a specific OUI from the provided `manufacturer`.
pub fn getOUI(manufacturer: []const u8) ![3]u8 {
    var man_buf: [100]u8 = .{ 0 } ** 100;
    const man = ascii.lowerString(man_buf[0..], mem.trim(u8, manufacturer, ascii.whitespace[0..]));
    var cur_man_buf: [100]u8 = .{ 0 } ** 100;
    var oui_rows_iter = mem.tokenizeScalar(u8, oui_tbl, '\n');
    var iter_idx: u16 = 0;
    while (oui_rows_iter.next()) |oui_row| : (iter_idx += 1) {
        var oui_iter = mem.tokenizeScalar(u8, oui_row, '\t');
        const cur_oui = oui_iter.next() orelse continue;
        const cur_man = ascii.lowerString(cur_man_buf[0..], mem.trim(u8, oui_iter.next() orelse continue, ascii.whitespace[0..]));
        if (mem.indexOf(u8, cur_man, man) != null) 
            return (try address.parseMAC(cur_oui))[0..3].*;
    }
    return error.ManufacturerNotFound;
}

/// Get a Random OUI
pub fn getRandomOUI() [3]u8 {
    const oui_idx: u16 = @min(60_000, crypto.random.int(u16));
    var oui_rows_iter = mem.tokenizeScalar(u8, oui_tbl, '\n');
    var iter_idx: u16 = 0;
    while (oui_rows_iter.next()) |oui_row| : (iter_idx += 1) {
        if (iter_idx != oui_idx) continue;
        var oui_iter = mem.tokenizeScalar(u8, oui_row, '\t');
        const oui: [6]u8 = address.parseMAC(oui_iter.next() orelse continue) catch .{ 0xF8, 0x63, 0xD9, 0, 0, 0 };
        return oui[0..3].*;
    }
    return .{ 0xF8, 0x63, 0xD9 };
}

