//! WiFi Data

pub const channels = @import("wifi/channels.zig");
pub const radiotap = @import("wifi/radiotap.zig");
pub const suites = @import("wifi/suites.zig");


/// WiFi Frame Header
/// [IETF - RFC 5416](https://www.rfc-editor.org/rfc/rfc5416)
/// [Cisco - WiFi Knowledge](https://community.cisco.com/t5/wireless-mobility-knowledge-base/802-11-frames-a-starter-guide-to-learn-wireless-sniffer-traces/ta-p/3110019)
pub const Header = struct {
    frame_control: FrameControl,
    duration: u16,
    addr_1: ?[6]u8 = null,
    addr_2: ?[6]u8 = null,
    addr_3: ?[6]u8 = null,
    seq_control: ?u16 = null,
    addr_4: ?[6]u8 = null,
    qos_control: ?u16 = null,

    /// Prefix
    /// Stable ABI portion of the WiFi Header
    pub const Prefix = extern struct {
        frame_control: u16,
        duration: u16,
    };

    /// Frame Control Data
    pub const FrameControl = packed struct(u16) {
        proto_version: u2,
        frame_type: FrameType,
        frame_subtype: FrameSubtype,
        to_DS: bool,
        from_DS: bool,
        more_frag: bool,
        retry: bool,
        pwr_mgmt: bool,
        more_data: bool,
        protected: bool,
        ordered: bool,
    };

    /// IEEE 802.11 Frame Control: Type (bits 3–2)
    pub const FrameType = enum(u2) {
        management,
        control,
        data,
        extension,
    };

    /// Union over Frame Control Subtypes (bits 7-4)
    const FrameSubtype = packed union {
        management: ManagementSubtype,
        control: ControlSubtype,
        data: DataSubtype,
        extension: ExtensionSubtype,
    };

    /// IEEE 802.11 Management frame subtypes (bits 7–4)
    pub const ManagementSubtype = enum(u4) {
        association_request,
        association_response,
        reassociation_request,
        reassociation_response,
        probe_request,
        probe_response,
        timing_advertisement,
        reserved_7,
        beacon,
        atim,
        disassociation,
        authentication,
        deauthentication,
        action,
        action_no_ack,
        reserved_15,
    };

    /// Management Frame Fixed Parameters
    /// These come after the 802.11 header and before tagged parameters
    pub const ManagementFixed = union(ManagementSubtype) {
        association_request: AssocRequest,
        association_response: AssocResponse,
        reassociation_request: ReassocRequest,
        reassociation_response: ReassocResponse,
        probe_request,
        probe_response: Beacon,
        timing_advertisement,
        reserved_7,
        beacon: Beacon,
        atim,
        disassociation: Disassoc,
        authentication: Auth,
        deauthentication: Deauth,
        action,
        action_no_ack,
        reserved_15,

        /// Beacon Frame Fixed Parameters
        /// Also used for Probe Response
        pub const Beacon = extern struct {
            timestamp: u64 align(1),
            beacon_interval: u16 align(1),
            capability_info: u16 align(1),
        };

        /// Association Request Fixed Parameters
        pub const AssocRequest = extern struct {
            capability_info: u16 align(1),
            listen_interval: u16 align(1),
        };

        /// Reassociation Request Fixed Parameters
        pub const ReassocRequest = extern struct {
            capability_info: u16 align(1),
            listen_interval: u16 align(1),
            current_ap: [6]u8 align(1),
        };

        /// Association Response Fixed Parameters
        pub const AssocResponse = extern struct {
            capability_info: u16 align(1),
            status_code: u16 align(1),
            association_id: u16 align(1),
        };

        /// Reassociation Response Fixed Parameters
        pub const ReassocResponse = extern struct {
            capability_info: u16 align(1),
            status_code: u16 align(1),
            association_id: u16 align(1),
        };

        /// Disassociation Fixed Parameters
        pub const Disassoc = extern struct {
            reason_code: u16 align(1),
        };

        /// Authentication Fixed Parameters
        pub const Auth = extern struct {
            auth_algorithm: u16 align(1),
            auth_seq: u16 align(1),
            status_code: u16 align(1),
        };

        /// Deauthentication Fixed Parameters
        pub const Deauth = extern struct {
            reason_code: u16 align(1),
        };
    };

    /// IEEE 802.11 Control frame subtypes (bits 7–4)
    pub const ControlSubtype = enum(u4) {
        reserved_0,
        reserved_1,
        trigger,
        tack,
        beamforming_report_poll,
        vht_he_ndp_announcement,
        control_frame_extension,
        control_wrapper,
        block_ack_request,
        block_ack,
        ps_poll,
        rts,
        cts,
        ack,
        cf_end,
        cf_end_cf_ack,
    };

    /// IEEE 802.11 Data frame subtypes (bits 7–4)
    pub const DataSubtype = enum(u4) {
        data,
        reserved_1,
        reserved_2,
        reserved_3,
        null,
        reserved_5,
        reserved_6,
        reserved_7,
        qos_data,
        qos_data_cf_ack,
        qos_data_cf_poll,
        qos_data_cf_ack_cf_poll,
        qos_null,
        reserved_13,
        qos_cf_poll,
        qos_cf_ack_cf_poll,
    };

    /// IEEE 802.11 Extension frame subtypes (bits 7–4)
    pub const ExtensionSubtype = enum(u4) {
        dmg_beacon,
        s1g_beacon,
        reserved_2,
        reserved_3,
        reserved_4,
        reserved_5,
        reserved_6,
        reserved_7,
        reserved_8,
        reserved_9,
        reserved_10,
        reserved_11,
        reserved_12,
        reserved_13,
        reserved_14,
        reserved_15,
    };
};

///// Wifi Footer
//pub const Footer = packed struct(u32) {
//    wifi_frame_check_seq: u32 = 0,
//    
//    /// Calculate the Cyclic Redundancy Check (CRC) and set it as the Frame Check Sequence (FCS) of this Wifi Frame Footer.
//    pub fn calcCRC(self: *@This(), alloc: mem.Allocator, frame_bytes: []u8) !void {
//        _ = self;
//        _ = alloc;
//        _ = frame_bytes;
//        // TODO
//    }
//};

/// Security Types
pub const SecurityType = enum {
    open,
    wep,
    wpa1,
    wpa2,
    wpa3t,
    wpa3,
};

/// Authentication Types
pub const AuthType = enum {
    open,
    /// Pre-shared key
    psk,
    /// Enterprise (802.1X)
    eap,
    // Simultaneous Authentication of Equals (WPA3)
    sae,
};

/// Security Info
pub const SecurityInfo = struct {
    type: SecurityType,
    auth: AuthType,
};
