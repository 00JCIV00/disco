//! WiFi Data

pub const channels = @import("wifi/channels.zig");
pub const radiotap = @import("wifi/radiotap.zig");
pub const suites = @import("wifi/suites.zig");


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
