//! 802.11 Suites


pub const AKM = enum(u32) {
    /// WPA2-PSK (Pre-Shared Key)
    PSK = 0x000FAC02,
    /// 802.1X (used in WPA2/WPA3 Enterprise)
    EAP = 0x000FAC01,
    /// Fast BSS Transition (802.11r) with PSK
    FT_PSK = 0x000FAC03,
    /// Fast BSS Transition (802.11r) with EAP
    FT_EAP = 0x000FAC04,
    /// Simultaneous Authentication of Equals (SAE), used in WPA3-Personal
    SAE = 0x000FAC08,
    /// Suite B-192, used in WPA3-Enterprise for high-security environments
    SUITE_B_192 = 0x000FAC0C,
    /// Opportunistic Wireless Encryption (OWE), used for open networks with encryption
    OWE = 0x000FAC12,
    /// DPP (Device Provisioning Protocol), used in WPA3 for easy device onboarding
    DPP = 0x000FAC14,
};

pub const CIPHER = enum(u32) {
    /// No encryption (open network)
    NONE = 0x00000000,
    /// WEP-40 encryption (insecure, deprecated)
    WEP40 = 0x000FAC01,
    /// TKIP (Temporal Key Integrity Protocol), used in WPA (insecure)
    TKIP = 0x000FAC02,
    /// AES-CCMP (Counter Mode with Cipher Block Chaining Message Authentication Code Protocol), used in WPA2/WPA3
    CCMP = 0x000FAC04,
    /// WEP-104 encryption (insecure, deprecated)
    WEP104 = 0x000FAC05,
    /// AES-GCMP (Galois/Counter Mode Protocol) encryption, used in WPA3
    GCMP_128 = 0x000FAC08,
    /// AES-GCMP-256 encryption, used in WPA3 for enhanced security
    GCMP_256 = 0x000FAC09,
    ///// Group addressed traffic using AES-CCMP (Group Cipher Suite)
    //GROUP_CCMP = 0x000FAC04,
    ///// Group addressed traffic using TKIP (Group Cipher Suite)
    //GROUP_TKIP = 0x000FAC02,
    /// BIP-GMAC-128, used for Management Frame Protection (MFP) in WPA3
    BIP_GMAC_128 = 0x000FAC0B,
    /// BIP-GMAC-256, used for Management Frame Protection (MFP) in WPA3
    BIP_GMAC_256 = 0x000FAC0C,
    /// BIP-CMAC-256, another option for Management Frame Protection (MFP)
    BIP_CMAC_256 = 0x000FAC0D,
};
