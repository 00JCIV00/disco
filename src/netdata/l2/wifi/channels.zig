//! WiFi Channels

const std = @import("std");
const Io = std.Io;

/// Invaild Channel Error
pub const Error = error {
    InvalidChannel,
};

/// Supported WiFi bands.
pub const Band = enum(u8) {
    b2 = 2,
    b5 = 5,
    b6 = 6,
};

/// Supported WiFi Cchannel Bandwidths in MHz.
pub const Bandwidth = enum(u16) {
    bw20 = 20,
    bw40 = 40,
    bw80 = 80,
    bw160 = 160,
    bw320 = 320,
};

/// Representation of a WiFi channel.
pub const Channel = extern struct {
    /// The primary 20 MHz channel number for this Channel's `band`.
    pri: u16,
    /// WiFi Channel Band
    band: Band,
    /// WiFi Channel Bandwidth
    bw: Bandwidth = .bw20,

    /// Map this Channel to its Center Frequency in MHz.
    pub fn toFreq(self: @This()) Error!usize {
        const primary_center = switch (self.band) {
            .b2 => switch (self.pri) {
                1...13 => 2407 + 5 * @as(usize, self.pri),
                14 => 2484,
                else => return error.InvalidChannel,
            },
            .b5 => 5000 + 5 * @as(usize, self.pri),
            .b6 => 5950 + 5 * @as(usize, self.pri),
        };
        const bw_mhz: usize = @intFromEnum(self.bw);
        return primary_center + ((bw_mhz / 2) - 10);
    }

    /// Convert a Center Frequency in MHz and Bandwidth to a Channel (band inferred).
    pub fn fromFreqBW(freq: usize, bw: Bandwidth) Error!@This() {
        const bw_mhz: usize = @intFromEnum(bw);
        // Base case: 20 MHz centers map directly to primary centers.
        if (bw_mhz == 20) switch (freq) {
            // 2.4 GHz
            2412...2472 => {
                const ch_2g: u16 = @intCast((freq - 2407) / 5);
                if (freq == 2407 + 5 * @as(usize, ch_2g) and ch_2g >= 1 and ch_2g <= 13) //
                    return .{ .band = .b2, .pri = ch_2g, .bw = .bw20 };
            },
            2484 => return .{ .band = .b2, .pri = 14, .bw = .bw20 },
            // 5 GHz
            5000...5895 => {
                const ch_5g: u16 = @intCast((freq - 5000) / 5);
                if (freq == 5000 + 5 * @as(usize, ch_5g) and validateChannel(ch_5g)) //
                    return .{ .band = .b5, .pri = ch_5g, .bw = .bw20 };
            },
            // 6 GHz
            5950...7125 => {
                const ch_6g: u16 = @intCast((freq - 5950) / 5);
                if (freq == 5950 + 5 * @as(usize, ch_6g) and validateChannel(ch_6g)) //
                    return .{ .band = .b6, .pri = ch_6g, .bw = .bw20 };
            },
            else => return error.InvalidChannel,
        };
        const half_bw: usize = bw_mhz / 2;
        if (half_bw <= 10 or freq <= half_bw - 10) //
            return error.InvalidChannel;
        const pri_freq = freq - (half_bw - 10);
        var ch = try fromFreqBW(pri_freq, .bw20);
        ch.bw = bw;
        return ch;
    }

    /// Construct a Channel from a Primary Channel Number.
    pub fn fromCh(ch: usize) Error!@This() {
        const pri: u16 = @intCast(ch);
        inline for ([_]Band{ .b2, .b5, .b6 }) |band| {
            inline for ([_]Bandwidth{ .bw20, .bw40, .bw80, .bw160, .bw320 }) |bw| {
                var cand = Channel{ .pri = pri, .band = band, .bw = bw };
                if (cand.validate()) //
                    return cand;
            }
        }
        return error.InvalidChannel;
    }

    /// Validate this Channel (Band, Primary, and Bandwidth).
    pub fn validate(self: @This()) bool {
        return switch (self.band) {
            .b2 => band2g: {
                if (self.bw != .bw20) //
                    break :band2g false;
                break :band2g self.pri >= 1 and self.pri <= 14;
            },
            .b5 => band5g: {
                const bw_mhz: usize = @intFromEnum(self.bw);
                const base_pri: usize = self.pri;
                if (bw_mhz == 20) {
                    const ch: u16 = self.pri;
                    break :band5g switch (ch) {
                        1...14 => false,
                        32...144, 184...196 => ch % 4 == 0 or (ch >= 135 and ch <= 138),
                        149...177 => ch % 4 == 1,
                        else => false,
                    };
                }
                const width_in_20: usize = bw_mhz / 20;
                var k: usize = 0;
                while (k < width_in_20) : (k += 1) {
                    const ch_val = base_pri + 4 * k;
                    if (ch_val > std.math.maxInt(u16)) //
                        break :band5g false;
                    const ch: u16 = @intCast(ch_val);
                    break :band5g switch (ch) {
                        1...14 => false,
                        32...144, 184...196 => ch % 4 == 0 or (ch >= 135 and ch <= 138),
                        149...177 => ch % 4 == 1,
                        else => false,
                    };
                }
                break :band5g true;
            },
            .b6 => band6g: {
                const bw_mhz: usize = @intFromEnum(self.bw);
                const base_pri: usize = self.pri;
                if (bw_mhz == 20) {
                    const ch: u16 = self.pri;
                    break :band6g ch >= 1 and ch <= 233 and (ch - 1) % 4 == 0;
                }
                const width_in_20: usize = bw_mhz / 20;
                var k: usize = 0;
                while (k < width_in_20) : (k += 1) {
                    const ch_val = base_pri + 4 * k;
                    if (ch_val > 233) //
                        break :band6g false;
                    const ch: u16 = @intCast(ch_val);
                    if (!(ch >= 1 and ch <= 233 and (ch - 1) % 4 == 0)) //
                        break :band6g false;
                }
                break :band6g true;
            },
        };
    }

    pub fn format(self: @This(), writer: *Io.Writer) Io.Writer.Error!void {
        try writer.print("{d} | {d} MHz | {d}G", .{ self.pri, @intFromEnum(self.bw), @intFromEnum(self.band) });
    }
};

/// Channels (20 MHz and Bonded) for each Band.
pub const Channels = struct {
    // 2.4 GHz
    pub const band_2G_20: []const Channel = genBand(.b2, .bw20);
    // 5 GHz
    pub const band_5G_20: []const Channel = genBand(.b5, .bw20);
    pub const band_5G_40: []const Channel = genBand(.b5, .bw40);
    pub const band_5G_80: []const Channel = genBand(.b5, .bw80);
    pub const band_5G_160: []const Channel = genBand(.b5, .bw160);
    // 6 GHz (Wi-Fi 6E & 7)
    pub const band_6G_20: []const Channel = genBand(.b6, .bw20);
    pub const band_6G_40: []const Channel = genBand(.b6, .bw40);
    pub const band_6G_80: []const Channel = genBand(.b6, .bw80);
    pub const band_6G_160: []const Channel = genBand(.b6, .bw160);
    pub const band_6G_320: []const Channel = genBand(.b6, .bw320);
    // All
    pub const all_20: []const Channel = band_2G_20 ++ band_5G_20 ++ band_6G_20;
    pub const all_5G: []const Channel = band_5G_20 ++ band_5G_40 ++ band_5G_80 ++ band_5G_160;
    pub const all_6G: []const Channel = band_6G_20 ++ band_6G_40 ++ band_6G_80 ++ band_6G_160 ++ band_6G_320;
    pub const all: []const Channel = all_20 ++ all_5G ++ all_6G;
};

/// Center Frequencies mirroring `Channels`.
pub const Frequencies = struct {
    // 2.4 GHz
    pub const band_2G_20: []const u32 = genFrequencies(Channels.band_2G_20);
    // 5 GHz
    pub const band_5G_20: []const u32 = genFrequencies(Channels.band_5G_20);
    pub const band_5G_40: []const u32 = genFrequencies(Channels.band_5G_40);
    pub const band_5G_80: []const u32 = genFrequencies(Channels.band_5G_80);
    pub const band_5G_160: []const u32 = genFrequencies(Channels.band_5G_160);
    // 6 GHz (Wi-Fi 6E & 7)
    pub const band_6G_20: []const u32 = genFrequencies(Channels.band_6G_20);
    pub const band_6G_40: []const u32 = genFrequencies(Channels.band_6G_40);
    pub const band_6G_80: []const u32 = genFrequencies(Channels.band_6G_80);
    pub const band_6G_160: []const u32 = genFrequencies(Channels.band_6G_160);
    pub const band_6G_320: []const u32 = genFrequencies(Channels.band_6G_320);
    // All
    pub const all_20: []const u32 = band_2G_20 ++ band_5G_20 ++ band_6G_20;
    pub const all_5G: []const u32 = band_5G_20 ++ band_5G_40 ++ band_5G_80 ++ band_5G_160;
    pub const all_6G: []const u32 = band_6G_20 ++ band_6G_40 ++ band_6G_80 ++ band_6G_160 ++ band_6G_320;
    pub const all: []const u32 = all_20 ++ all_5G ++ all_6G;
};

/// Generate Channels for the provided `band` and `bandwidth`.
pub fn genBand(comptime band: Band, comptime bw: Bandwidth) []const Channel {
    return switch (bw) {
        .bw20 => genBand20(band),
        else => genWideBand(band, bw),
    };
}

/// Generate the list of valid 20 MHz `Channel`s for the given `band`.
fn genBand20(comptime band: Band) []const Channel {
    return switch (band) {
        .b2 => chsB2: {
            var chs: [14]Channel = undefined;
            var idx: usize = 0;
            var ch: u16 = 1;
            while (ch <= 14) : (ch += 1) {
                const check_ch: Channel = .{ .band = band, .pri = ch, .bw = .bw20 };
                if (!check_ch.validate()) //
                    continue;
                chs[idx] = check_ch;
                idx += 1;
            }
            const chs_out = chs;
            break :chsB2 chs_out[0..idx];
        },
        .b5 => chsB5: {
            // Upper bound: there are at most 25 valid 20 MHz 5 GHz channels.
            var chs: [64]Channel = undefined;
            var idx: usize = 0;
            var ch: u16 = 1;
            while (ch <= 196) : (ch += 1) {
                const check_ch: Channel = .{ .band = band, .pri = ch, .bw = .bw20 };
                if (!check_ch.validate()) //
                    continue;
                chs[idx] = check_ch;
                idx += 1;
            }
            const chs_out = chs;
            break :chsB5 chs_out[0..idx];
        },
        .b6 => chsB6: {
            // 6 GHz: up to 59 valid 20 MHz channels in 1–233.
            var chs: [64]Channel = undefined;
            var idx: usize = 0;
            var ch: u16 = 1;
            while (ch <= 233) : (ch += 1) {
                const check_ch: Channel = .{ .band = band, .pri = ch, .bw = .bw20 };
                if (!check_ch.validate()) //
                    continue;
                chs[idx] = check_ch;
                idx += 1;
            }
            const chs_out = chs;
            break :chsB6 chs_out[0..idx];
        },
    };
}

/// Generate Bonded Channels (40/80/160/320) by sliding over the 20 MHz list.
fn genWideBand(comptime band: Band, comptime bw: Bandwidth) []const Channel {
    @setEvalBranchQuota(10_000);
    return switch (band) {
        .b2 => &.{},
        .b5, .b6 => chsB5B6: {
            const base = genBand20(band);
            const width_in_20 = @intFromEnum(bw) / 20;
            // Safe upper bound: we can never have more bonded channels than primaries.
            var chs: [64]Channel = undefined;
            var out_idx: usize = 0;
            var i: usize = 0;
            addChs: while (i + width_in_20 <= base.len) : (i += 1) {
                const first = base[i].pri;
                var j: usize = 1;
                while (j < width_in_20) : (j += 1) {
                    // 5/6 GHz 20 MHz channels are always separated by 4 in channel number
                    // when they are truly adjacent in frequency. If this breaks, the block
                    // would cross a gap between sub-bands.
                    if (base[i + j].pri != first + 4 * @as(u16, @intCast(j))) //
                        continue :addChs;
                }
                chs[out_idx] = .{ .band = band, .pri = first, .bw = bw };
                out_idx += 1;
            }
            const chs_out = chs;
            break :chsB5B6 chs_out[0..out_idx];
        },
    };
}

/// Build an array of Center Frequencies in MHz for all Channels (`chans`).
fn genFrequencies(comptime chans: []const Channel) []const u32 {
    var freqs: [chans.len]u32 = undefined;
    for (chans, freqs[0..]) |ch, *freq| //
        freq.* = ch.toFreq() catch @compileError("Unknown WiFi channel");
    const freqs_out = freqs;
    return freqs_out[0..];
}

/// Validate a frequency (`freq`) in MHz.
pub fn validateFreq(freq: usize) bool {
    _ = Channel.fromFreqBW(freq, .bw20) catch return false;
    return true;
}

/// Validate a primary `channel` number by attempting all valid band/bandwidth combinations.
/// Returns true if any Channel constructed from `channel` is valid.
pub fn validateChannel(channel: usize) bool {
    _ = Channel.fromCh(channel) catch return false;
    return true;
}

