//! RadioTap
//! [radiotap.org](https://www.radiotap.org/)

/// RadioTap Header
pub const Header = extern struct {
    /// Indicates which major version of the radiotap header is in use.
    /// Currently, this is always 0.
    it_version: u8 = 0,
    it_pad: u8,
    /// The entire length of the radiotap data, including the radiotap header.
    it_len: u16,
    /// A bitmask of the radiotap data fields that follows the radiotap header.
    /// Provided bit 31 of the it_present field is not set, the data for fields specified in the it_present bitmask immediately follow the radiotap header.
    /// If it is set, then more it_present words follow and the radiotap data follows after the it_present word that has bit 31 unset.
    /// Multiple namespaces may be present.
    it_present: u32,
};

/// RadioTap Defined Fields
/// These values serve as bitshift masks to be applied to `Header.it_present`.
pub const DefinedFields = enum(u8) {
    TSFT = 0,
    Flags = 1,
    Rate = 2,
    Channel = 3,
    FHSS = 4,
    AntSignal = 5,
    AntNoise = 6,
    LockQuality = 7,
    TxAttenuation = 8,
    TxAttenuation_dB = 9,
    TxPower_dB = 10,
    Ant = 11,
    AntSignal_dB = 12,
    AntNoise_dB = 13,
    RxFlags = 14,
    TxFlags = 15,
    MCS = 19,
    AMPDUStatus = 20,
    VHT = 21,
    Timestamp = 22,
    HE = 23,
    HEMU = 24,
    HEMUOtherUser = 25,
    PSDU0Length = 26,
    LSIG = 27,
    TLVFields = 28,
    RadiotapNamespace = 29,
    VendorNamespace = 30,
    EXT = 31,
    S1G = 32,
    USIG = 33,
    EHT = 34,
};

/// RadioTap Data Fields
pub const Data = struct {
    TSFT: ?TSFT = null,
    Flags: ?Flags = null,
    Rate: ?Rate = null,
    Channel: ?Channel = null,
    FHSS: ?FHSS = null,
    AntSignal: ?i8 = null,
    AntNoise: ?i8 = null,
    LockQuality: ?u16 = null,
    TxAttenuation: ?u16 = null,
    TxAttenuation_dB: ?u16 = null,
    TxPower_dB: ?u16 = null,
    Ant: ?u8 = null,
    AntSignal_dB: ?u8 = null,
    AntNoise_dB: ?u8 = null,
    RxFlags: ?u16 = null,
    TxFlags: ?u16 = null,
    MCS: ?MCS = null,
    AMPDUStatus: ?AMPDU = null,
    VHT: ?VHT = null,
    Timestamp: ?Timestamp = null,
    HE: ?HE = null,
    HEMU: ?HEMU = null,
    HEMUOtherUser: ?HEMUOtherUser = null,
    PSDU0Length: ?u8 = null,
    LSIG: ?LSIG = null,
    TLVFields: ?TLVFields = null,
    //RadiotapNamespace: ?RadiotapNamespace = null,
    VendorNamespace: ?VendorNamespace = null,
    S1G: ?S1G = null,
    USIG: ?USIG = null,
    EHT: ?EHT = null,
};

/// Time Synchronization Function Timer
pub const TSFT = extern struct {
    /// Timestamp in milliseconds
    ts_ms: u64 align(8),
};

/// Properties of transmitted and received frames.
pub const Flags = extern struct {
    flags: u8,

    pub const Mask = enum(u8) {
        cfp = 0x01,
        short_preamble = 0x02,
        wep_encryption = 0x04,
        fragmentation = 0x08,
        fcs = 0x10,
        frame_padding = 0x20,
        failed_fcs = 0x40,
        short_guard_interval = 0x80,
    };
};

/// Tx/Rx Rate
pub const Rate = extern struct {
    /// Rate in increments of 500 Kbps
    rate: u8,
};

/// Channel
pub const Channel = extern struct {
    /// Frequency in MHz
    freq: u16 align(2),
    /// Flags
    flags: u16 align(2),

    pub const Mask = enum(u16) {
        s1g_700 = 0x01,
        s1g_800 = 0x02,
        s1g_900 = 0x04,
        turbo = 0x10,
        cck = 0x20,
        ofdm = 0x40,
        spectrum_2g = 0x80,
        spectrum_5g = 0x100,
        passive_scan = 0x200,
        dynamic_cck_ofdm = 0x400,
        gfsk = 0x800,
    };
};

/// Frequency Hopping Spread Spectrum
pub const FHSS = extern struct {
    hop_set: u8 align(1),
    hop_pattern: u8 align(1),
};

/// Antenna RF Signal power in dBm.
pub const AntSignal = extern struct {
    /// Power in mW
    power: i8,
};

/// Antenna RF Noise power.
pub const AntNoise = extern struct {
    /// Power in mW
    power: i8,
};

/// Quality of Barker code lock
pub const LockQuality = extern struct {
    /// Lock Quality
    quality: u16 align(2),
};

/// Transmit power expressed as unitless distance from max power set at factory calibration.
pub const TxAttenuation = extern struct {
    /// Attenuation
    tx_atten: u16 align(2),
};

/// Transmit power expressed as decibel distance from max power set at factory calibration.
pub const TxAttenuation_dB = extern struct {
    /// Attenuation in dB
    tx_atten: u16 align(2),
};

/// Transmit power expressed as dBm (decibels from a 1 milliwatt reference).
pub const TxPower = extern struct {
    /// Transmit Power
    tx_power: u16 align(2),
};

/// Antenna Index
pub const Ant = extern struct {
    /// Index
    index: u8,
};

/// Antenna Signal dB
pub const AntSignal_dB = extern struct {
    power: u8,
};

/// Antenna Noise dB
pub const AntNoise_dB = extern struct {
    power: u8,
};

/// Rx Flags
pub const RxFlags = extern struct {
    flags: u16 align(2),

    pub const Mask = enum(u16) {
        reserved_0x01 = 0x01,
        plcp_crc_failed = 0x02,
        reserved_0xfffc = 0xfffc,
    };
};

/// Tx Flags
pub const TxFlags = extern struct {
    flags: u16 align(2),

    pub const Mask = enum(u16) {
        excessive_retries = 0x01,
        cts_to_self = 0x02,
        rts_cts_handshake = 0x04,
        no_ack = 0x08,
        pre_config_seq_num = 0x10,
        no_reorder = 0x20,
    };
};

/// Modulation & Coding Schemes
pub const MCS = extern struct {
    /// Known Information
    known: u8 align(1),
    /// Flags
    flags: u8 align(1),
    /// MCS Rate Index
    mcs: u8 align(1),

    /// Known Mask
    pub const KnownMask = enum(u8) {
        bandwidth = 0x01,
        index_known = 0x02,
        guard_interval = 0x04,
        ht_format = 0x08,
        fec_type = 0x10,
        stbc_known = 0x20,
        ness_known = 0x40,
        ness_data = 0x80,
    };

    /// Flags Mask
    pub const FlagsMask = enum(u8) {
        bandwidth = 0x03,
        guard_interval = 0x04,
        ht_format = 0x08,
        fec_type = 0x10,
        stbc_known = 0x20,
        stbc_streams = 0x60,
        ness = 0x80,
    };
};

/// A-MPDU
pub const AMPDU = extern struct {
    ref_num: u32 align(4),
    flags: u16 align(2),
    delim_crc: u8 align(1),
    reserved: u8 align(1) = 0,

    /// Mask
    pub const Mask = enum(u16) {
        sub_frames_0len = 0x01,
        frames_0len = 0x02,
        last_subframe_known = 0x04,
        last_subframe = 0x08,
        delim_crc_error = 0x10,
        delim_crc_known = 0x20,
        eof_value = 0x40,
        eof_value_known = 0x80,
        reserved = 0xff00,
    };
};

/// Very High Throughput
pub const VHT = extern struct {
    known: u16 align(2),
    flags: u8 align(1),
    bandwidth: u8 align(1),
    mcs_nss: [4]u8 align(1),
    coding: u8 align(1),
    group_id: u8 align(1),
    partial_aid: u16 align(2),

    /// Known Mask
    pub const KnownMask = enum(u16) {
        stbc_known = 0x01,
        txop_ps_not_allowed = 0x02,
        guard_interval = 0x04,
        short_gi_nsym_da_known = 0x08,
        lpdc_ofdm_sym_known = 0x10,
        beamform_known = 0x20,
        bandwidth_known = 0x40,
        group_id = 0x80,
        partial_aid_known = 0x100,
    };

    /// Flags Mask
    pub const FlagsMask = enum(u16) {
        stbc = 0x01,
        txop_ps_not_allowed = 0x02,
        guard_interval = 0x04,
        short_gi_nsym_da = 0x08,
        lpdc_ofdm_sym = 0x10,
        beamform = 0x20,
        unused = 0xc0,
    };
};

/// Timestamp
pub const Timestamp = extern struct {
    timestamp: u64 align(8),
    accuracy: u16 align(2),
    unit_position: u8 align(1),
    flags: u8 align(1),
    reserved: u32 align(4),

    pub const Mask = enum(u8) {
        counter_32bit = 0x01,
        accuracy_known = 0x02,
        reserved = 0xfc,
    };
};

/// High Efficiency (802.11ax) information
pub const HE = extern struct {
    /// HE Data 1
    data1: u16 align(2),
    /// HE Data 2
    data2: u16 align(2),
    /// HE Data 3
    data3: u16 align(2),
    /// HE Data 4
    data4: u16 align(2),
    /// HE Data 5
    data5: u16 align(2),
    /// HE Data 6
    data6: u16 align(2),

    /// Data1 bit mask
    pub const Data1Mask = enum(u16) {
        /// HE PPDU Format: 0=HE_SU, 1=HE_EXT_SU, 2=HE_MU, 3=HE_TRIG
        he_ppdu_format = 0x0003,
        /// BSS Color value known
        bss_color_known = 0x0004,
        /// Beam Change known
        beam_change_known = 0x0008,
        /// UL/DL (uplink/downlink) known
        ul_dl_known = 0x0010,
        /// Data MCS known
        data_mcs_known = 0x0020,
        /// Data DCM known
        data_dcm_known = 0x0040,
        /// Coding (BCC/LDPC) known
        coding_known = 0x0080,
        /// LDPC extra symbol segment known
        ldpc_extra_symbol_segment_known = 0x0100,
        /// STBC known
        stbc_known = 0x0200,
        /// Spatial Reuse (or SR1) known
        spatial_reuse_known = 0x0400,
        /// Spatial Reuse 2 known (HE_TRIG) / STA-ID known (HE_MU)
        spatial_reuse2_or_sta_id_known = 0x0800,
        /// Spatial Reuse 3 known (HE_TRIG)
        spatial_reuse3_known = 0x1000,
        /// Spatial Reuse 4 known (HE_TRIG)
        spatial_reuse4_known = 0x2000,
        /// Data Bandwidth/RU allocation known
        data_bw_ru_allocation_known = 0x4000,
        /// Doppler value known
        doppler_known = 0x8000,
    };

    /// Data2 bit mask
    pub const Data2Mask = enum(u16) {
        /// pri/sec 80 MHz known
        pri_sec_80mhz_known = 0x0001,
        /// GI known
        gi_known = 0x0002,
        /// Number of LTF symbols known
        ltf_symbols_known = 0x0004,
        /// Pre-FEC Padding Factor known
        pre_fec_padding_factor_known = 0x0008,
        /// Tx Beamforming known
        txbf_known = 0x0010,
        /// PE Disambiguity known
        pe_disambiguity_known = 0x0020,
        /// TXOP known
        txop_known = 0x0040,
        /// Midamble periodicity known
        midamble_periodicity_known = 0x0080,
        /// RU allocation offset
        ru_allocation_offset = 0x3f00,
        /// RU allocation offset known
        ru_allocation_offset_known = 0x4000,
        /// pri/sec 80 MHz (primary=0, secondary=1)
        pri_sec_80mhz = 0x8000,
    };

    /// Data3 bit mask
    pub const Data3Mask = enum(u16) {
        /// BSS Color value
        bss_color = 0x003f,
        /// Beam Change flag
        beam_change = 0x0040,
        /// UL/DL flag
        ul_dl = 0x0080,
        /// Data MCS (not SIG-B MCS)
        data_mcs = 0x0f00,
        /// Data DCM
        data_dcm = 0x1000,
        /// Coding (0=BCC, 1=LDPC)
        coding = 0x2000,
        /// LDPC extra symbol segment
        ldpc_extra_symbol_segment = 0x4000,
        /// STBC enabled
        stbc = 0x8000,
    };

    /// Data4 bit mask
    pub const Data4Mask = enum(u16) {
        /// Spatial Reuse (HE_SU / HE_EXT_SU / HE_MU formats)
        spatial_reuse = 0x000f,
        /// STA-ID of captured user (HE_MU format)
        sta_id = 0x7ff0,
        /// Reserved bits
        reserved = 0x8000,
    };

    /// Data5 bit mask
    pub const Data5Mask = enum(u16) {
        /// Data Bandwidth / RU allocation
        /// 0=20, 1=40, 2=80, 3=160/80+80, 4=26-tone RU, 5=52-tone RU,
        /// 6=106-tone RU, 7=242-tone RU, 8=484-tone RU, 9=996-tone RU,
        /// 10=2x996-tone RU
        data_bw_ru_allocation = 0x000f,
        /// GI (0=0.8us, 1=1.6us, 2=3.2us, 3=reserved)
        gi = 0x0030,
        /// LTF symbol size (0=unknown, 1=1x, 2=2x, 3=4x)
        ltf_symbol_size = 0x00c0,
        /// Number of LTF symbols (0=1, 1=2, 2=4, 3=6, 4=8, 5–7=reserved)
        ltf_symbols = 0x0700,
        /// Reserved
        reserved_0x0800 = 0x0800,
        /// Pre-FEC Padding Factor
        pre_fec_padding_factor = 0x3000,
        /// Tx Beamforming
        txbf = 0x4000,
        /// PE Disambiguity
        pe_disambiguity = 0x8000,
    };

    /// Data6 bit mask
    pub const Data6Mask = enum(u16) {
        /// NSTS (number of space-time streams; 0=unknown, 1=1, ...)
        nsts = 0x000f,
        /// Doppler value
        doppler = 0x0010,
        /// Reserved
        reserved_0x00e0 = 0x00e0,
        /// TXOP value
        txop_value = 0x7f00,
        /// Midamble periodicity (0=10, 1=20)
        midamble_periodicity = 0x8000,
    };
};

/// HE-MU common information
pub const HEMU = extern struct {
    /// Flags 1
    flags1: u16 align(2),
    /// Flags 2
    flags2: u16 align(2),
    /// RU allocation indices for channel 1
    ru_channel1: [4]u8 align(1),
    /// RU allocation indices for channel 2
    ru_channel2: [4]u8 align(1),

    /// Flags1 bit mask
    pub const Flags1Mask = enum(u16) {
        /// SIG-B MCS (from SIG-A)
        sig_b_mcs = 0x000f,
        /// SIG-B MCS known
        sig_b_mcs_known = 0x0010,
        /// SIG-B DCM (from SIG-A)
        sig_b_dcm = 0x0020,
        /// SIG-B DCM known
        sig_b_dcm_known = 0x0040,
        /// Channel 2 Center 26-tone RU bit known
        ch2_center_26tone_known = 0x0080,
        /// Channel 1 RUs known (depends on bandwidth)
        ch1_ru_known = 0x0100,
        /// Channel 2 RUs known (depends on bandwidth)
        ch2_ru_known = 0x0200,
        /// Reserved
        reserved_0x0c00 = 0x0c00,
        /// Channel 1 Center 26-tone RU bit known
        ch1_center_26tone_known = 0x1000,
        /// Channel 1 Center 26-tone RU value
        ch1_center_26tone_value = 0x2000,
        /// SIG-B compression known
        sig_b_compression_known = 0x4000,
        /// # HE-SIG-B symbols / MU-MIMO users known
        num_sigb_syms_or_mu_mimo_users_known = 0x8000,
    };

    /// Flags2 bit mask
    pub const Flags2Mask = enum(u16) {
        /// Bandwidth from Bandwidth field in HE-SIG-A (0=20,1=40,2=80,3=160/80+80)
        bandwidth = 0x0003,
        /// Bandwidth known
        bandwidth_known = 0x0004,
        /// SIG-B compression from SIG-A
        sig_b_compression = 0x0008,
        /// # HE-SIG-B Symbols - 1 / # MU-MIMO Users - 1
        num_sigb_syms_or_mu_mimo_users_minus1 = 0x00f0,
        /// Preamble puncturing from Bandwidth field in HE-SIG-A
        preamble_puncturing = 0x0300,
        /// Preamble puncturing known
        preamble_puncturing_known = 0x0400,
        /// Channel 2 Center 26-tone RU value
        ch2_center_26tone_value = 0x0800,
        /// Reserved
        reserved_0xf000 = 0xf000,
    };
};

/// HE-MU per-user information for additional users
pub const HEMUOtherUser = extern struct {
    /// HE-SIG-B user field bits 0–14
    per_user_1: u16 align(2),
    /// HE-SIG-B user field bits 15–20
    per_user_2: u16 align(2),
    /// Position of this user field (starting at 0)
    per_user_position: u8 align(1),
    /// Which per-user fields are known
    per_user_known: u8 align(1),

    pub const PerUser1Mask = enum(u16) {
        /// Bits B0–B14 of HE-SIG-B user field
        user_bits_0_14 = 0x7fff,
        /// Reserved
        reserved_0x8000 = 0x8000,
    };

    pub const PerUser2Mask = enum(u16) {
        /// Bits B15–B20 of HE-SIG-B user field
        user_bits_15_20 = 0x003f,
        /// Reserved
        reserved_0xffc0 = 0xffc0,
    };

    pub const PerUserKnownMask = enum(u8) {
        /// User field position known
        position_known = 0x01,
        /// STA-ID known (B0–10)
        sta_id_known = 0x02,
        /// NSTS known (B11–13, non-MU-MIMO)
        nsts_known = 0x04,
        /// Tx Beamforming known (B14, non-MU-MIMO)
        tx_beamforming_known = 0x08,
        /// Spatial Configuration known (B11–14, MU-MIMO)
        spatial_configuration_known = 0x10,
        /// MCS known (B15–18)
        mcs_known = 0x20,
        /// DCM known (B19)
        dcm_known = 0x40,
        /// Coding known (B20)
        coding_known = 0x80,
    };
};

/// 0-length PSDU indicator
pub const PSDU0Length = extern struct {
    /// Type of PPDU without PSDU
    typ: u8 align(1),

    pub const Type = enum(u8) {
        /// Sounding PPDU
        sounding_ppdu = 0,
        /// Data not captured (e.g. multi-user PPDU)
        data_not_captured = 1,
        /// Vendor-specific
        vendor_specific = 0xff,
        _,
    };
};

/// Legacy L-SIG contents
pub const LSIG = extern struct {
    /// Known bits for rate/length
    data1: u16 align(2),
    /// Encoded rate and length
    data2: u16 align(2),

    pub const Data1Mask = enum(u16) {
        /// Rate known
        rate_known = 0x0001,
        /// Length known
        length_known = 0x0002,
        /// Reserved
        reserved_0xfffc = 0xfffc,
    };

    pub const Data2Mask = enum(u16) {
        /// Rate
        rate = 0x000f,
        /// Length
        length = 0xfff0,
    };
};

/// TLV-based radiotap fields (bit 28)
/// Represents a single TLV item within the TLV field.
pub const TLVFields = extern struct {
    /// TLV type (radiotap field number or special)
    typ: u16 align(2),
    /// Length of the following value in bytes
    length: u16 align(2),

    /// Header for a vendor TLV (type 30 inside TLVs)
    pub const VendorHeader = extern struct {
        /// Organizationally Unique Identifier
        oui: [3]u8 align(1),
        /// Vendor-specific subtype
        subtype: u8 align(1),
        /// Presence type (index of overridden presence bit)
        presence_type: u16 align(2),
        /// Reserved / padding for 4-byte alignment of vendor data
        reserved: u16 align(2),
    };
};

/// Radiotap namespace reset (bit 29)
/// No payload; presence resets to the default radiotap namespace.
pub const RadiotapNamespace = extern struct {};

/// Vendor namespace selector (bit 30)
pub const VendorNamespace = extern struct {
    /// Vendor OUI
    oui: [3]u8 align(1),
    /// Vendor-specific sub-namespace selector
    sub_namespace: u8 align(1),
    /// Number of bytes belonging to this vendor namespace after this field
    skip_length: u16 align(2),
};

/// Sub-1 GHz (S1G) PHY information (TLV type 32)
pub const S1G = extern struct {
    /// Which S1G parameters are known
    known: u16 align(2),
    /// S1G parameter word 1
    data1: u16 align(2),
    /// S1G parameter word 2
    data2: u16 align(2),

    pub const KnownMask = enum(u16) {
        s1g_ppdu_format_known = 0x0001,
        response_indication_known = 0x0002,
        guard_interval_known = 0x0004,
        nss_known = 0x0008,
        bandwidth_known = 0x0010,
        mcs_known = 0x0020,
        color_known = 0x0040,
        uplink_indication_known = 0x0080,
        reserved_0xff00 = 0xff00,
    };

    pub const Data1Mask = enum(u16) {
        /// S1G PPDU Format: 0=S1G_1M, 1=S1G_SHORT, 2=S1G_LONG
        s1g_ppdu_format = 0x0003,
        /// Response indication: 0=NO_RESPONSE, 1=NDP_RESPONSE,
        /// 2=NORMAL_RESPONSE, 3=LONG_RESPONSE
        response_indication = 0x000c,
        /// Reserved
        reserved_0x0010 = 0x0010,
        /// Guard interval: 0=Long GI, 1=Short GI
        guard_interval = 0x0020,
        /// Number of spatial streams (0=1, 1=2, 2=3, 3=4)
        num_spatial_streams = 0x00c0,
        /// Bandwidth: 0=1MHz, 1=2MHz, 2=4MHz, 3=8MHz, 4=16MHz
        bandwidth = 0x0f00,
        /// MCS (0–10)
        mcs = 0xf000,
    };

    pub const Data2Mask = enum(u16) {
        /// Color (0–7)
        color = 0x0007,
        /// Uplink indication
        uplink_indication = 0x0008,
        /// Reserved
        reserved_0x00f0 = 0x00f0,
        /// RSSI
        rssi = 0xff00,
    };
};

/// U-SIG contents (EHT / 11be)
pub const USIG = extern struct {
    /// Common part of U-SIG
    common: u32 align(4),
    /// Value bits
    value: u32 align(4),
    /// Mask of valid bits in `value`
    mask: u32 align(4),
};

/// Extremely High Throughput (EHT / 802.11be) information
pub const EHT = extern struct {
    /// Which EHT fields are known
    known: u32 align(4),
    /// EHT data words 0–8
    data: [9]u32 align(4),
    // User information entries follow in the capture (variable length)
    // and must be parsed based on the remaining radiotap length.

    pub const KnownMask = enum(u32) {
        spatial_reuse_known = 0x00000002,
        gi_known = 0x00000004,
        num_ltf_symbols_known = 0x00000010,
        ldpc_extra_symbol_segment_known = 0x00000020,
        pre_fec_padding_factor_known = 0x00000040,
        pe_disambiguity_known = 0x00000080,
        disregard_known = 0x00000100,
        disregard2_known = 0x00000200,
        crc1_known = 0x00002000,
        tail1_known = 0x00004000,
        crc2_known = 0x00008000,
        tail2_known = 0x00010000,
        nss_known = 0x00020000,
        beamformed_known = 0x00040000,
        num_non_ofdma_users_known = 0x00080000,
        user_encoding_block_crc_known = 0x00100000,
        user_encoding_block_tail_known = 0x00200000,
        ru_mru_size_known = 0x00400000,
        ru_mru_index_known = 0x00800000,
        ru_allocation_tb_format_known = 0x01000000,
        primary_80mhz_channel_position_known = 0x02000000,
        reserved_0xfc000000 = 0xfc000000,
    };

    /// Bit layout for data[0]
    pub const Data0Mask = enum(u32) {
        reserved_0x00000007 = 0x00000007,
        spatial_reuse = 0x00000078,
        gi = 0x00000180,
        ltf_symbol_size = 0x00000600,
        ltf_symbols = 0x00003800,
        ldpc_extra_symbol_segment = 0x00004000,
        pre_fec_padding_factor = 0x00018000,
        pe_disambiguity = 0x00020000,
        disregard_eht_sounding = 0x000c0000,
        disregard_non_eht_sounding = 0x003c0000,
        crc1 = 0x03c00000,
        tail1 = 0xfc000000,
    };

    /// Bit layout for data[1]
    pub const Data1Mask = enum(u32) {
        /// RU/MRU Size (0:26, 1:52, 2:106, 3:242, 4:484, 5:996, 6:2x996, 7:4x996, ...)
        ru_mru_size = 0x0000001f,
        /// RU/MRU Index
        ru_mru_index = 0x00001fe0,
        /// RU Allocation 1
        ru_allocation1 = 0x003fe000,
        /// RU Allocation 1 known
        ru_allocation1_known = 0x00400000,
        /// Reserved
        reserved_0x3f800000 = 0x3f800000,
        /// Primary 80 MHz Channel Position (0–3)
        primary_80mhz_channel_position = 0xc0000000,
    };

    /// Bit layout for data[2]–data[6] (RU Allocation X/+1/+2)
    pub const DataXMask = enum(u32) {
        ru_allocation_x = 0x000001ff,
        ru_allocation_x_known = 0x00000200,
        ru_allocation_x_plus1 = 0x0007fc00,
        ru_allocation_x_plus1_known = 0x00080000,
        ru_allocation_x_plus2 = 0x1ff00000,
        ru_allocation_x_plus2_known = 0x20000000,
        reserved_0xc0000000 = 0xc0000000,
    };

    /// Bit layout for data[7]
    pub const Data7Mask = enum(u32) {
        crc2 = 0x0000000f,
        tail2 = 0x000003f0,
        reserved_0x00000c00 = 0x00000c00,
        nss_eht_sounding = 0x0000f000,
        beamformed_eht_sounding = 0x00010000,
        num_non_ofdma_users = 0x000e0000,
        user_encoding_block_crc = 0x00f00000,
        user_encoding_block_tail = 0x3f000000,
        reserved_0xc0000000 = 0xc0000000,
    };

    /// Bit layout for data[8]
    pub const Data8Mask = enum(u32) {
        ru_allocation_tb_ps160 = 0x00000001,
        ru_allocation_tb_b0 = 0x00000002,
        ru_allocation_tb_b7_b1 = 0x000001fc,
        reserved_0xfffffe00 = 0xfffffe00,
    };

    /// Bit layout for each user_info entry
    pub const UserInfoMask = enum(u32) {
        sta_id_known = 0x00000001,
        mcs_known = 0x00000002,
        coding_known = 0x00000004,
        reserved_known = 0x00000008,
        nss_known = 0x00000010,
        beamforming_known = 0x00000020,
        spatial_configuration_known = 0x00000040,
        data_captured_for_user = 0x00000080,
        sta_id = 0x0007ff00,
        coding = 0x00080000,
        mcs = 0x00f00000,
        nss = 0x0f000000,
        reserved_0x10000000 = 0x10000000,
        beamforming = 0x20000000,
        spatial_configuration = 0x3f000000,
        reserved_0xc0000000 = 0xc0000000,
    };
};

