//! Profile Information f/ DisCo

const std = @import("std");
const fmt = std.fmt;
const linux = std.os.linux;
const log = std.log;
const math = std.math;
const mem = std.mem;
const meta = std.meta;
const posix = std.posix;
const time = std.time;

const netdata = @import("../netdata.zig");
const address = netdata.address;
const MACF = address.MACFormatter;

/// Masking Information to obfuscate the host system.
pub const Mask = struct {
    /// Device OUI.
    /// If this is left `null` a Link-Local Random MAC Address will be assigned.
    oui: ?[3]u8 = null,
    /// Device Hostname
    hostname: []const u8 = "localhost",
    /// Currently unused.
    ttl: u8 = 64,
    /// User Agent String
    ua_str: ?[]const u8 = null,

    pub fn format(
        self: @This(),
        _: []const u8,
        _: fmt.FormatOptions,
        writer: anytype,
    ) !void {
        const oui = self.oui orelse [3]u8{ 0x01, 0x23, 0x45 };
        try writer.print(
            \\- OUI:        {s} ({s})
            \\- Hostname:   {s}
            \\- TTL:        {d}
            \\- User Agent: {s}
            \\
            , .{
                MACF{ .bytes = oui[0..] }, try netdata.oui.findOUI(.short, .station, oui ++ .{ 0 } ** 3),
                self.hostname,
                self.ttl,
                self.ua_str orelse "[Unknown]",
            }
        );
    }

    // TODO Fill out a few common Masks
    pub const map = std.StaticStringMap(@This()).initComptime(&.{
        .{ "google pixel 6 pro", google_pixel_6_pro },
        .{ "iphone 13 pro max", iphone_13_pro_max },
        .{ "lg v60 thingq 5g", lg_v60_thinq_5g },
        .{ "samsung galaxy s21", samsung_galaxy_s21 },
    });

    /// Google Pixel 6
    pub const google_pixel_6_pro: @This() = .{
        .oui = .{ 0xDC, 0xE5, 0x5B },
        .hostname = "Pixel 6 Pro",
        .ua_str = "Mozilla/5.0 (Linux; Android 15; Pixel 6 Pro Build/AP3A.241005.015; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/131.0.6778.22 Mobile Safari/537.36",
    };
    /// iPhone 13 Pro Max
    pub const iphone_13_pro_max: @This() = .{
        .oui = .{ 0xEC, 0xA9, 0x07 },
        .hostname = "Leila's iPhone",
        .ua_str = "Mozilla/7.0 (iPhone; CPU iPhone OS 17_0; iPhone 13 Pro Max) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/G4JUL10 Safari/604.1",
    };
    /// LG V60 ThinQ 5G
    pub const lg_v60_thinq_5g: @This() = .{
        .oui = .{ 0x30, 0xFC, 0xEB },
        .hostname = "V60 ThinQ 5G",
        .ua_str = "Mozilla/5.0 (Linux; Android 13; LM-V600 Build/TKQ1.220829.002; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/129.0.6668.97 Mobile Safari/537.36 [FB_IAB/FB4A;FBAV/485.0.0.70.77;IABMV/1;]",
    };
    /// Samsung Galaxy S21
    pub const samsung_galaxy_s21: @This() = .{
        .oui = .{ 0x8C, 0x6A, 0x3B },
        .hostname = "samsung_s21",
        .ua_str = "Mozilla/5.0 (Linux; Android 14; SM-G991N Build/UP1A.231005.007; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/114.0.0.0 Whale/1.0.0.0 Crosswalk/28.114.0.25 Mobile Safari/537.36 NAVER(inapp; search; 2000; 12.9.3)",
    };

};
