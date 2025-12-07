//! Information Elements

const std = @import("std");
const mem = std.mem;
const meta = std.meta;
const ArrayList = std.ArrayList;

const nl = @import("../../netlink.zig");
const wifi = @import("wifi.zig");
const utils = @import("../../utils.zig");

/// Information Element Tag Header
pub const InformationElementHeader = extern struct {
    pub const nl_align = false;
    pub const full_len = false;

    type: u8,
    len: u8,
};

/// Information Element Tag
pub const InformationElement = struct {
    hdr: InformationElementHeader,
    data: []const u8,
};

/// Information Element Types
pub const IE = enum(u8) {
    /// Service Set Identifier (SSID)
    SSID = 0,
    /// Supported Rates
    SUPPORTED_RATES = 1,
    /// FH Parameter Set
    FH_PARAMETER_SET = 2,
    /// DS Parameter Set
    DS_PARAMETER_SET = 3,
    /// CF Parameter Set
    CF_PARAMETER_SET = 4,
    /// Traffic Indication Map (TIM)
    TIM = 5,
    /// IBSS Parameter Set
    IBSS_PARAMETER_SET = 6,
    /// Country
    COUNTRY = 7,
    /// Hopping Pattern Parameters
    HOPPING_PATTERN_PARAMS = 8,
    /// Hopping Pattern Table
    HOPPING_PATTERN_TABLE = 9,
    /// Request
    REQUEST = 10,
    /// BSS Load
    BSS_LOAD = 11,
    /// EDCA Parameter Set
    EDCA_PARAMETER_SET = 12,
    /// Traffic Specification (TSPEC)
    TSPEC = 13,
    /// Traffic Classification (TCLAS)
    TCLAS = 14,
    /// Schedule
    SCHEDULE = 15,
    /// Challenge Text (used in Shared Key authentication)
    CHALLENGE_TEXT = 16,
    /// Power Constraint
    POWER_CONSTRAINT = 32,
    /// Power Capability
    POWER_CAPABILITY = 33,
    /// Transmit Power Control (TPC) Request
    TPC_REQUEST = 34,
    /// Transmit Power Control (TPC) Report
    TPC_REPORT = 35,
    /// Supported Channels
    SUPPORTED_CHANNELS = 36,
    /// Channel Switch Announcement
    CHANNEL_SWITCH_ANNOUNCEMENT = 37,
    /// Measurement Request
    MEASUREMENT_REQUEST = 38,
    /// Measurement Report
    MEASUREMENT_REPORT = 39,
    /// Quiet
    QUIET = 40,
    /// IBSS DFS
    IBSS_DFS = 41,
    /// ERP Information
    ERP_INFORMATION = 42,
    /// HT Capabilities
    HT_CAPABILITIES = 44,
    /// HT Operation
    HT_OPERATION = 45,
    /// Secondary Channel Offset
    SECONDARY_CHANNEL_OFFSET = 46,
    /// Robust Security Network (RSN) Information
    RSN = 48,
    /// Extended Supported Rates
    EXTENDED_SUPPORTED_RATES = 50,
    /// Supported Operating Classes
    SUPPORTED_OPER_CLASSES = 59,
    /// Mesh Configuration
    MESH_CONFIGURATION = 60,
    /// Mesh ID
    MESH_ID = 61,
    /// Multi-band
    MULTI_BAND = 70,
    /// Extended Capabilities
    EXTENDED_CAPABILITIES = 127,
    /// VHT Capabilities
    VHT_CAPABILITIES = 191,
    /// VHT Operation
    VHT_OPERATION = 192,
    /// Vendor Specific
    VENDOR_SPECIFIC = 221,

    /// Unknown (Used by this library for unknown tags)
    __UNKNOWN__,
};

/// Information Elements Info
pub const InformationElements = struct {
    pub const AttrE = IE;
    pub const AttrHdrT = InformationElementHeader;

    /// SSID
    SSID: ?[]const u8 = null,
    /// Supported Rates
    SUPPORTED_RATES: ?[]const u8 = null,
    /// FH Parameter Set
    FH_PARAMETER_SET: ?[]const u8 = null,
    /// DS Parameter Set
    DS_PARAMETER_SET: ?[]const u8 = null,
    /// CF Parameter Set
    CF_PARAMETER_SET: ?[]const u8 = null,
    /// Traffic Indication Map (TIM)
    TIM: ?[]const u8 = null,
    /// IBSS Parameter Set
    IBSS_PARAMETER_SET: ?[]const u8 = null,
    /// Country
    COUNTRY: ?[]const u8 = null,
    /// Hopping Pattern Parameters
    HOPPING_PATTERN_PARAMS: ?[]const u8 = null,
    /// Hopping Pattern Table
    HOPPING_PATTERN_TABLE: ?[]const u8 = null,
    /// Request
    REQUEST: ?[]const u8 = null,
    /// BSS Load
    BSS_LOAD: ?[]const u8 = null,
    /// EDCA Parameter Set
    EDCA_PARAMETER_SET: ?[]const u8 = null,
    /// TSPEC
    TSPEC: ?[]const u8 = null,
    /// TCLAS
    TCLAS: ?[]const u8 = null,
    /// Schedule
    SCHEDULE: ?[]const u8 = null,
    /// Challenge Text
    CHALLENGE_TEXT: ?[]const u8 = null,
    /// Power Constraint
    POWER_CONSTRAINT: ?[]const u8 = null,
    /// Power Capability
    POWER_CAPABILITY: ?[]const u8 = null,
    /// TPC Request
    TPC_REQUEST: ?[]const u8 = null,
    /// TPC Report
    TPC_REPORT: ?[]const u8 = null,
    /// Supported Channels
    SUPPORTED_CHANNELS: ?[]const u8 = null,
    /// Channel Switch Announcement
    CHANNEL_SWITCH_ANNOUNCEMENT: ?[]const u8 = null,
    /// Measurement Request
    MEASUREMENT_REQUEST: ?[]const u8 = null,
    /// Measurement Report
    MEASUREMENT_REPORT: ?[]const u8 = null,
    /// Quiet
    QUIET: ?[]const u8 = null,
    /// IBSS DFS
    IBSS_DFS: ?[]const u8 = null,
    /// ERP Information
    ERP_INFORMATION: ?[]const u8 = null,
    /// HT Capabilities
    HT_CAPABILITIES: ?[]const u8 = null,
    /// HT Operation
    HT_OPERATION: ?[]const u8 = null,
    /// Secondary Channel Offset
    SECONDARY_CHANNEL_OFFSET: ?[]const u8 = null,
    /// RSN Information
    RSN: ?RobustSecurityNetwork = null,
    /// Extended Supported Rates
    EXTENDED_SUPPORTED_RATES: ?[]const u8 = null,
    /// Supported Operating Classes
    SUPPORTED_OPER_CLASSES: ?[]const u8 = null,
    /// Mesh Configuration
    MESH_CONFIGURATION: ?[]const u8 = null,
    /// Mesh ID
    MESH_ID: ?[]const u8 = null,
    /// Multi-band
    MULTI_BAND: ?[]const u8 = null,
    /// Extended Capabilities
    EXTENDED_CAPABILITIES: ?[]const u8 = null,
    /// VHT Capabilities
    VHT_CAPABILITIES: ?[]const u8 = null,
    /// VHT Operation
    VHT_OPERATION: ?[]const u8 = null,
    /// Vendor Specific
    VENDOR_SPECIFIC: ?[]const []const u8 = null,

    /// Robust Security Network (RSN)
    pub const RobustSecurityNetwork = struct {
        /// Custom Netlink Parse Function (implicitly used by `nl.parse`)
        pub fn fromBytes(alloc: mem.Allocator, bytes: []const u8) !@This() {
            var rsn: @This() = undefined;
            if (bytes.len < 8) {
                //log.err("Incomplete Type Data for RSN. Only {d}B received.", .{ bytes.len });
                return error.IncompleteTypeData;
            }
            inline for (meta.fields(@This())) |field| {
                const field_info = @typeInfo(field.type);
                if (field_info == .optional) @field(rsn, field.name) = null;
                if (field_info == .pointer and field_info.pointer.size == .Slice)
                    @field(rsn, field.name) = &.{};
            }
            rsn.VERSION = @bitCast(bytes[0..2].*);
            rsn.GROUP_CIPHER_SUITE = @bitCast(bytes[2..6].*);
            var start: usize = 6;
            var end: usize = 8;
            if (end < bytes.len) opts: {
                rsn.PAIRWISE_CIPHER_COUNT = @bitCast(bytes[6..8].*);
                if (rsn.PAIRWISE_CIPHER_COUNT.? > 0) {
                    const slice_end = end + (@sizeOf(Suite) * rsn.PAIRWISE_CIPHER_COUNT.?);
                    while (end < slice_end) {
                        start = end;
                        end += @sizeOf(Suite);
                        try nl.parse.setOptFromBytes(
                            alloc,
                            ?[]const Suite,
                            &rsn.PAIRWISE_CIPHER_SUITES,
                            bytes[start..end],
                        );
                    }
                }
                errdefer nl.parse.freeOptBytes(alloc, ?[]const Suite, rsn.PAIRWISE_CIPHER_SUITES);
                start = end;
                end += 2;
                if (end > bytes.len) break :opts;

                rsn.AKM_SUITE_COUNT = @bitCast(bytes[start..end][0..2].*);
                if (rsn.AKM_SUITE_COUNT.? > 0) {
                    const slice_end = end + (@sizeOf(Suite) * rsn.AKM_SUITE_COUNT.?);
                    while (end < slice_end) {
                        start = end;
                        end += @sizeOf(Suite);
                        try nl.parse.setOptFromBytes(
                            alloc, 
                            ?[]const Suite, 
                            &rsn.AKM_SUITES, 
                            bytes[start..end],
                        );
                    }
                }
                errdefer nl.parse.freeOptBytes(alloc, ?[]const Suite, rsn.AKM_SUITES);
                start = end;
                end += 2;
                if (end > bytes.len) break :opts;

                rsn.CAPABILITIES = @bitCast(bytes[start..end][0..2].*);
                start = end;
                end += 2;
                if (end > bytes.len) break :opts;

                rsn.PMKID_COUNT = @bitCast(bytes[start..end][0..2].*);
                if (rsn.PMKID_COUNT.? > 0) {
                    const slice_end = end + (@sizeOf(Suite) * rsn.PMKID_COUNT.?);
                    while (end < slice_end) {
                        start = end;
                        end += @sizeOf(Suite);
                        try nl.parse.setOptFromBytes(
                            alloc, 
                            ?[]const [16]u8, 
                            &rsn.PMKID_LIST, 
                            bytes[start..end],
                        );
                    }
                    errdefer nl.parse.freeOptBytes(alloc, ?[]const Suite, rsn.PMKID_LIST);
                }
                if (end > bytes.len) break :opts;

                start = end;
                end += @sizeOf(Suite);
                if (bytes.len - start < end - start)
                    return error.MalformedRSN;
                rsn.GROUP_MANAGEMENT_CIPHER_SUITE = @bitCast(bytes[start..end][0..4].*);
            }
            //{
            //    const rsn_str = try json.stringifyAlloc(alloc, rsn, .{ .whitespace = .indent_4, .emit_null_optional_fields = false });
            //    defer alloc.free(rsn_str);
            //    log.debug("RSN:\n{s}", .{ rsn_str });
            //}
            return rsn;
        }

        pub fn toBytes(self: @This(), alloc: mem.Allocator) ![]u8 {
            var buf: ArrayList(u8) = .empty;
            inline for (meta.fields(@This())) |field| {
                const field_info = @typeInfo(field.type);
                const in_field = @field(self, field.name);
                switch (field_info) {
                    .optional => |optl| optl: {
                        const _in_field = in_field orelse break :optl;
                        if (optl.child == u16 or optl.child == Suite) {
                            try buf.appendSlice(alloc, mem.toBytes(_in_field)[0..]);
                            break :optl;
                        }
                        for (_in_field[0..]) |item|
                            try buf.appendSlice(alloc, mem.toBytes(item)[0..]);
                    },
                    else => try buf.appendSlice(alloc, mem.toBytes(in_field)[0..]),
                }
            }
            return try buf.toOwnedSlice(alloc);
        }

        pub const Suite = extern struct {
            OUI: [3]u8,
            TYPE: u8,
        };

        /// Robust Security Network Types
        pub const RSN = struct {
            /// Cipher Suite Selectors
            pub const CipherSuiteSelector = enum(u8) {
                /// No encryption (useful for open networks)
                NONE = 0x00,
                /// WEP-40 encryption
                WEP40 = 0x01,
                /// TKIP (Temporal Key Integrity Protocol) encryption (used in WPA)
                TKIP = 0x02,
                /// AES-CCMP (Counter Mode Cipher Block Chaining Message Authentication Code Protocol)
                CCMP = 0x04,
                /// WEP-104 encryption
                WEP104 = 0x05,
                /// AES-GCMP (Galois/Counter Mode Protocol) encryption (used in WPA3)
                GCMP = 0x08,
                /// AES-GCMP-256 encryption (used in WPA3)
                GCMP_256 = 0x09,
            };
            /// Authentication Key Management (AKM) Suite Selectors
            pub const AKM = enum(u8) {
                /// 802.1X (Enterprise) authentication with PMKSA caching
                EAP = 0x01,
                /// WPA2 PSK (Pre-Shared Key)
                PSK = 0x02,
                /// 802.11r Fast BSS Transition (FT) with EAP
                FT_EAP = 0x03,
                /// 802.11r Fast BSS Transition (FT) with PSK
                FT_PSK = 0x04,
                /// 802.1X with SHA-256
                EAP_SHA256 = 0x05,
                /// PSK with SHA-256
                PSK_SHA256 = 0x06,
                /// Tunneled Direct Link Setup (TDLS)
                TDLS = 0x07,
                /// Simultaneous Authentication of Equals (SAE), used in WPA3-Personal
                SAE = 0x08,
                /// Fast BSS Transition (FT) over SAE
                FT_SAE = 0x09,
                /// AP-CCMP (AP PeerKey for TDLS)
                AP_PEER_KEY = 0x0A,
                /// 802.1X with Suite-B SHA-256
                EAP_SUITE_B_SHA256 = 0x0B,
                /// 802.1X with Suite-B SHA-384 (Suite-B-192)
                SUITE_B_192 = 0x0C,
                /// Fast BSS Transition (FT) over 802.1X with SHA-384
                FT_EAP_SHA384 = 0x0D,
                /// FILS with SHA-256
                FILS_SHA256 = 0x0E,
                /// FILS with SHA-384
                FILS_SHA384 = 0x0F,
                /// Fast BSS Transition (FT) over FILS with SHA-256
                FT_FILS_SHA256 = 0x10,
                /// Fast BSS Transition (FT) over FILS with SHA-384
                FT_FILS_SHA384 = 0x11,
                /// Opportunistic Wireless Encryption (OWE)
                OWE = 0x12,
            };
            /// Group Cipher Suites
            pub const GroupCipherSuites = enum(u8) {
                /// Group Cipher Suite for WPA2 (AES-CCMP)
                GROUP_CCMP = 0x04,
                /// Group Cipher Suite for WPA (TKIP)
                GROUP_TKIP = 0x02,
            };
            // WPA3 Key Management
            pub const WPA3 = enum(u8) {
                /// WPA3-Personal using Simultaneous Authentication of Equals (SAE)
                WPA3_SAE = 0x08,
                /// WPA3-Enterprise using 802.1X authentication
                WPA3_EAP = 0x0D,
            };
        };

        /// Version of the RSN (typically 1 for WPA2)
        VERSION: u16,
        /// Group Cipher Suite
        GROUP_CIPHER_SUITE: Suite,
        /// Pairwise Cipher Suite Count
        PAIRWISE_CIPHER_COUNT: ?u16 = null,
        /// Pairwise Cipher Suite(s)
        PAIRWISE_CIPHER_SUITES: ?[]const Suite = null,
        /// AKM Suite Count
        AKM_SUITE_COUNT: ?u16 = null,
        /// AKM Suite(s)
        AKM_SUITES: ?[]const Suite = null,
        /// RSN Capabilities
        CAPABILITIES: ?u16 = null,
        /// Optional fields for WPA3 and beyond
        PMKID_COUNT: ?u16 = null,
        PMKID_LIST: ?[]const [16]u8 = null,
        GROUP_MANAGEMENT_CIPHER_SUITE: ?Suite = null,
    };

    pub const OperatingClass = enum(u8) {
        // 2.4 GHz band
        /// Channels 1–13 (20 MHz, 2.4 GHz)
        Class81 = 81,
        /// Channel 14 (20 MHz, Japan)
        Class82 = 82,
        /// Channels 3-11 (40 MHz, 2.4 GHz)
        Class83 = 83,
        // 5 GHz band (20 MHz channels)
        /// Channels 36, 40, 44, 48 (20 MHz, 5 GHz)
        Class115 = 115,
        /// Channels 52, 56, 60, 64 (DFS required, 20 MHz, 5 GHz)
        Class116 = 116,
        /// Channels 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140 (DFS required, 20 MHz, 5 GHz)
        Class117 = 117,
        // 5 GHz band (40 MHz channels)
        /// Channels 38, 46 (40 MHz, 5 GHz)
        Class118 = 118,
        /// Channels 54, 62 (DFS required, 40 MHz, 5 GHz)
        Class119 = 119,
        /// Channels 102, 110, 118, 126, 134 (DFS required, 40 MHz, 5 GHz)
        Class120 = 120,
        // 5 GHz band (80 MHz channels)
        /// Channel 42 (80 MHz, 5 GHz)
        Class121 = 121,
        /// Channel 58 (DFS required, 80 MHz, 5 GHz)
        Class122 = 122,
        /// Channels 106, 122 (DFS required, 80 MHz, 5 GHz)
        Class123 = 123,
        /// Channels 138, 122 (DFS required, 80 MHz, 5 GHz)
        Class124 = 124,
        // 5 GHz band (160 MHz channels)
        /// Channel 50 (160 MHz, 5 GHz)
        Class125 = 125,
        /// Channel 114 (DFS required, 160 MHz, 5 GHz)
        Class126 = 126,
        // 6 GHz band (20, 40, 80, and 160 MHz channels)
        /// 20 MHz channels, 6 GHz band
        Class131 = 131,
        /// 40 MHz channels, 6 GHz band
        Class132 = 132,
        /// 80 MHz channels, 6 GHz band
        Class133 = 133,
        /// 160 MHz channels, 6 GHz band
        Class134 = 134,

        pub fn getClass(freq_mhz: u32, channel_width_mhz: u32) ?@This() {
            const channel = wifi.channels.channelFromFreq(freq_mhz) catch return null;
            //log.debug("Ch: {d}", .{ channel });

            // 2.4 GHz Band
            if (freq_mhz >= 2400 and freq_mhz < 2500) {
                switch (channel_width_mhz) {
                    20 => {
                        if (channel >= 1 and channel <= 13) return .Class81;
                        if (channel == 14) return .Class82;
                    },
                    40 => {
                        return switch (channel) {
                            3...11 => .Class83,
                            else => null,
                        };
                    },
                    else => return null,
                }
            }
            // 5 GHz Band
            else if (freq_mhz >= 5000 and freq_mhz < 5925) {
                switch (channel_width_mhz) {
                    20 => {
                        if (channel >= 36 and channel <= 48) return .Class115;
                        if (channel >= 52 and channel <= 64) return .Class116;
                        if (channel >= 100 and channel <= 140) return .Class117;
                    },
                    40 => {
                        if (channel == 38 or channel == 46) return .Class118;
                        if (channel == 54 or channel == 62) return .Class119;
                        if (channel >= 102 and channel <= 134) return .Class120;
                    },
                    80 => {
                        if (channel == 42) return .Class121;
                        if (channel == 58) return .Class122;
                        if (channel == 106 or channel == 122) return .Class123;
                        if (channel == 138) return .Class124;
                    },
                    160 => {
                        if (channel == 50) return .Class125;
                        if (channel == 114 or channel == 142) return .Class126;
                    },
                    else => return null,
                }
            }
            // 6 GHz Band
            else if (freq_mhz >= 5925 and freq_mhz <= 7125) {
                switch (channel_width_mhz) {
                    20 => return .Class131,
                    40 => return .Class132,
                    80 => return .Class133,
                    160 => return .Class134,
                    else => return null,
                }
            }
            return null;
        }

        /// Classes Formatter
        const ClassesF = utils.SliceFormatter(u8, "{d}");
        /// Get a slice of Operating Classes as allocated bytes from the provided `wiphy`.
        pub fn bytesFromWIPHY(alloc: mem.Allocator, wiphy: nl._80211.Wiphy) !?[]u8 {
            const bands = wiphy.WIPHY_BANDS orelse return null;
            //const ht_40: u32 = 0b0001;
            //const vht_160: u32 = 0b0010;
            var class_buf: ArrayList(u8) = .empty;
            errdefer class_buf.deinit(alloc);
            for (bands) |band| {
                const freqs = band.FREQS orelse continue;
                for (freqs) |freq| {
                    const mhz = freq.FREQ;// orelse continue;
                    var class: u8 = 0;
                    _20: {
                        //log.debug("Width: 20MHz", .{});
                        class = @intFromEnum(getClass(mhz, 20) orelse continue);
                        if (mem.indexOfScalar(u8, class_buf.items, class) != null) break :_20;
                        try class_buf.append(alloc, class);
                    }
                    HT: {
                        //if (ht & ht_40 != ht_40) break :HT;
                        //if (band.HT_CAPA & ht_40 != ht_40) break :HT;
                        class = @intFromEnum(getClass(mhz, 40) orelse break :HT);
                        if (mem.indexOfScalar(u8, class_buf.items, class) != null) break :HT;
                        try class_buf.append(alloc, class);
                    }
                    //if (band.VHT_CAPA) |vht| VHT: {
                    VHT: {
                        class = @intFromEnum(getClass(mhz, 80) orelse break :VHT);
                        if (mem.indexOfScalar(u8, class_buf.items, class) != null) break :VHT;
                        try class_buf.append(alloc, class);
                        //if (vht & vht_160 != vht_160) break :VHT;
                        class = @intFromEnum(getClass(mhz, 160) orelse break :VHT);
                        if (mem.indexOfScalar(u8, class_buf.items, class) != null) break :VHT;
                        try class_buf.append(alloc, class);
                    }
                }
            }
            if (class_buf.items.len == 0) return null;
            //log.debug("Op Classes: {f}", .{ ClassesF{ .slice = class_buf.items } });
            return try class_buf.toOwnedSlice(alloc);
        }
    };
};
