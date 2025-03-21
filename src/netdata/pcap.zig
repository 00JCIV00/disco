//! Packet Capture (pcap-ng) Headers and Functions
/// [RFC PCAP-NG](https://www.ietf.org/archive/id/draft-tuexen-opsawg-pcapng-05.html)

/// Option Header
pub const OptionHeader = packed struct {
    code: u16,
    len: u16,
};

/// Section Header Block (SHB)
pub const SectionHeaderBlock = extern struct {
    block_type: u32 = 0x0A0D0D0A,
    block_total_len: u32,
    byte_order_magic: u32 = 0x1A2B3C4D,
    major_ver: u16 = 1,
    minor_ver: u16 = 0,
    section_len: u64,

    /// Section Header Option Codes
    pub const OptionCode = enum(u16) {
        hardware = 2,
        os = 3,
        userappl = 4,
    };
};

/// Interface Description Block (IDB)
pub const InterfaceDescriptionBlock = extern struct {
    block_type: u32 = 0x01,
    block_total_len: u32,
    link_type: u16,
    _reserved: u16 = 0,
    snap_len: u32,

    /// Interface Description Option Codes
    pub const OptionCode = enum(u16) {
        name = 2,
        description = 3,
        ipv4_addr = 4,
        ipv6_addr = 5,
        mac_addr = 6,
        eui_addr = 7,
        speed = 8,
        ts_resol = 9,
        t_zone = 10,
        filter = 11,
        os = 12,
        fcs_len = 13,
        ts_offset = 14,
        hardware = 15,
        tx_speed = 16,
        rx_speed = 17,
    };
};

/// Enhanced Packet Block (EPB)
pub const EnhancedPacketBlock = extern struct {
    block_type: u32 = 0x06,
    block_total_len: u32,
    interface_id: u32,
    ts_high: u32,
    ts_low: u32,
    cap_packet_len: u32,
    og_packet_len: u32,

    pub const OptionCode = enum(u16) {
        flags = 2,
        hash = 3,
        dropcount = 4,
        packetid = 5,
        queue = 6,
        verdict = 7,
    };
};

