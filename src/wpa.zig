//! WEP/WPA Security Protocol function for DisCo.

const std = @import("std");
const crypto = std.crypto;

pub const Protocol = enum {
    open,
    wep,
    wpa2,
};

/// Function to calculate the WPA key using PBKDF2 with HMAC-SHA1
pub fn genKey(ssid: []const u8, passphrase: []const u8, protocol: Protocol) ![32]u8 {
    var key: [32]u8 = undefined;

    switch (protocol) {
        .wpa2 => {
            // Use the crypto module to perform PBKDF2 HMAC-SHA1 key derivation
            try crypto.pwhash.pbkdf2(
                key[0..],
                passphrase,
                ssid,
                4096,
                crypto.auth.hmac.HmacSha1,
            );
        },
        else => return error.UnsupportedProtocol,
    }
    return key;
}
