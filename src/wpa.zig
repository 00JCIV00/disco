//! WEP/WPA Security Protocol function for DisCo.

const std = @import("std");
const crypto = std.crypto;

pub const Protocol = enum {
    open,
    wep,
    wpa2,
};

/// Calculate a WEP or WPA Key using MD5 or PBKDF2 with HMAC-SHA1.
pub fn genKey(protocol: Protocol, ssid: []const u8, passphrase: []const u8) ![32]u8 {
    var key: [32]u8 = undefined;

    switch (protocol) {
        .wpa2 => {
            // PBKDF2 HMAC-SHA1 Key Derivation
            try crypto.pwhash.pbkdf2(
                key[0..],
                passphrase,
                ssid,
                4096,
                crypto.auth.hmac.HmacSha1,
            );
        },
        .wep => {
            // MD5 Sum Key
            var md5 = crypto.hash.Md5.init(.{});
            md5.update(passphrase);
            md5.final(key[0..16]);
        },
        else => return error.UnsupportedProtocol,
    }
    return key;
}
