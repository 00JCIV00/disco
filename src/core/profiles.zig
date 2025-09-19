//! Profile Information f/ DisCo

const std = @import("std");
const crypto = std.crypto;
const fmt = std.fmt;
const linux = std.os.linux;
const log = std.log;
const math = std.math;
const mem = std.mem;
const meta = std.meta;
const posix = std.posix;
const time = std.time;
const Io = std.Io;
const StaticStringMap = std.StaticStringMap;

const netdata = @import("../netdata.zig");
const address = netdata.address;
const MACF = address.MACFormatter;
const utils = @import("../utils.zig");
const SlicesF = utils.SliceFormatter([]const u8, "{s}");

/// Profile for handling the Host System.
pub const Profile = struct {
    /// The Mask used to obfuscate the Host System.
    mask: ?Mask = null,
    /// Use a Random Mask if one isn't provided.
    use_random_mask: bool = true,
    /// Change the System's Hostname instead of just attempting to spoof it on each network.
    change_sys_hostname: bool = false,
    /// Conflicting Processes
    conflict_processes: []const []const u8 = &.{
        "wpa_supplicant",
        "hostapd",
        "nmcli",
        "nmtui",
        "dhcpcd",
        "dhclient",
        "angryoxide",
        "aircrack-ng",
        "airodump-ng",
        "aireplay-ng",
        "kismet",
    },
    /// Require Conflict PIDs Acknowledgement on Startup.
    require_conflicts_ack: bool = true,
};

/// Masking Information to obfuscate the Host System.
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

    pub fn format(self: @This(), writer: *Io.Writer) Io.Writer.Error!void {
        const oui = self.oui orelse [3]u8{ 0x01, 0x23, 0x45 };
        try writer.print(
            \\- OUI:        {f} ({s})
            \\- Hostname:   {s}
            \\- TTL:        {d}
            \\- User Agent: {s}
            \\
            , .{
                MACF{ .bytes = oui[0..] }, netdata.oui.findOUI(.short, oui ++ [3]u8{ 0, 0, 0 }) catch "OUI Unavailable",
                self.hostname,
                self.ttl,
                self.ua_str orelse "[Unknown]",
            }
        );
    }

    /// Get a Random Profile Mask.
    pub fn getRandom() @This() {
        const mask_idx = crypto.random.int(u16) % map.keys().len;
        const mask_key = map.keys()[mask_idx];
        return map.get(mask_key).?;
    }

    /// DisCo's built-in Masks.
    pub const map: StaticStringMap(@This()) = .initComptime(&.{
        .{ "google pixel 6 pro", google_pixel_6_pro },
        .{ "intel windows 11 pc", intel_windows_11_pc },
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
    /// Intel Windows 11 PC
    pub const intel_windows_11_pc: @This() = .{
        .oui = .{ 0x70, 0xD8, 0x23 },
        //.hostname = fmt.comptimePrint("DESKTOP-{X:7<L}", .{ crypto.random.int(u32) }),
        .hostname = "DESKTOP-L836F9W",
        .ttl = 128,
        .ua_str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
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
