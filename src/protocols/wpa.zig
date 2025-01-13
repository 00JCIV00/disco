//! WEP/WPA Security Protocol functions for DisCo.

const std = @import("std");
const bpf = std.os.linux.BPF;
const crypto = std.crypto;
const fmt = std.fmt;
const json = std.json;
const log = std.log.scoped(.wpa);
const mem = std.mem;
const posix = std.posix;

const Md5 = crypto.hash.Md5;
const Sha1 = crypto.hash.Sha1;

const nl = @import("../netlink.zig");
const netdata = @import("../netdata.zig");
const utils = @import("../utils.zig");

const c = utils.toStruct;
const l2 = netdata.l2;

/// Calculate a WEP Key or WPA Pre-Shared Key (PSK) using MD5 or PBKDF2 with HMAC-SHA1.
pub fn genKey(protocol: nl._80211.SecurityType, ssid: []const u8, passphrase: []const u8) ![32]u8 {
    var key: [32]u8 = .{ 0 } ** 32;
    switch (protocol) {
        .wpa2, .wpa3t => {
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
            var md5 = Md5.init(.{});
            md5.update(passphrase);
            md5.final(key[0..16]);
        },
        else => return error.UnsupportedProtocol,
    }
    return key;
}

/// Calculate the Pairwise Transient Key from the given inputs.
/// `pmk` is the 32-byte Pairwise Master Key
/// `anonce` and `snonce` are the 32-byte Authenticator and Supplicant nonces
/// `addr1` and `addr2` are 6-byte MAC addresses
pub fn genPTK(
    pmk: [32]u8,
    anonce: [32]u8,
    snonce: [32]u8,
    addr1: [6]u8,
    addr2: [6]u8,
) [48]u8 {
    const mac_len = 6;
    const nonce_len = 32;
    const data_len = 2 * mac_len + 2 * nonce_len;
    const label = "Pairwise key expansion";
    var ptk: [48]u8 = .{ 0 } ** 48;
    var data: [data_len]u8 = .{ 0 } ** data_len;
    // Order addresses using memcmp logic
    const macs_ordered = mem.order(u8, addr1[0..], addr2[0..]);
    const first_addr = if (macs_ordered == .lt) addr1[0..] else addr2[0..];
    const second_addr = if (macs_ordered == .lt) addr2[0..] else addr1[0..];
    // Order nonces using memcmp logic
    const nonces_ordered = mem.order(u8, anonce[0..], snonce[0..]);
    const first_nonce = if (nonces_ordered == .lt) anonce[0..] else snonce[0..];
    const second_nonce = if (nonces_ordered == .lt) snonce[0..] else anonce[0..];
    // Copy data in hostapd order
    const mac_pair_len = 2 * mac_len;
    @memcpy(data[0..mac_len], first_addr);
    @memcpy(data[mac_len..mac_pair_len], second_addr);
    @memcpy(data[mac_pair_len..mac_pair_len + nonce_len], first_nonce);
    @memcpy(data[mac_pair_len + nonce_len..], second_nonce);
    _ = sha1PRF(pmk[0..], label, data[0..], ptk[0..]);
    return ptk;
}

/// HMAC-SHA1 implementation that processes multiple data chunks.
/// Takes `key` for HMAC operations and arrays of data chunks (`addr`) and their lengths (`len`)
fn hmacSHA1(key: []const u8, message: []const u8) [Sha1.digest_length]u8 {
    const block_len = 64;
    var k_pad: [block_len]u8 = .{ 0 } ** block_len;
    var tk: [Sha1.digest_length]u8 = .{ 0 } ** Sha1.digest_length;
    // If key is longer than 64 bytes reset it to key = SHA1(key)
    const use_key = if (key.len > block_len) blk: {
        Sha1.hash(key, &tk, .{});
        break :blk tk[0..];
    } else key;
    // Start out by storing key in pad
    @memcpy(k_pad[0..use_key.len], use_key);
    // Create inner pad
    for (&k_pad) |*byte| byte.* ^= 0x36;
    // Perform inner SHA1
    var inner = Sha1.init(.{});
    inner.update(k_pad[0..]);
    inner.update(message);
    var inner_hash: [Sha1.digest_length]u8 = .{ 0 } ** Sha1.digest_length;
    inner.final(&inner_hash);
    // Reset k_pad and create outer pad
    @memset(&k_pad, 0);
    @memcpy(k_pad[0..use_key.len], use_key);
    for (&k_pad) |*byte| byte.* ^= 0x5c;
    // Perform outer SHA1
    var outer = Sha1.init(.{});
    outer.update(k_pad[0..]);
    outer.update(&inner_hash);
    var result: [Sha1.digest_length]u8 = .{ 0 } ** Sha1.digest_length;
    outer.final(&result);
    return result;
}

/// SHA1-based Pseudo-Random Function (PRF) as defined in IEEE 802.11i-2004
/// Used to derive cryptographically separate keys from `key`
fn sha1PRF(key: []const u8, label: []const u8, data: []const u8, buf: []u8) void {
    var counter: u8 = 0;
    var pos: usize = 0;
    // Include null terminator in label length
    const label_len = label.len + 1;
    while (pos < buf.len) {
        // Construct the input buffer for this round
        const round_input_len = label_len + data.len + 1;
        var round_input: [256]u8 = .{ 0 } ** 256;
        @memcpy(round_input[0..label.len], label);
        @memcpy(round_input[label.len + 1 .. label.len + 1 + data.len], data);
        round_input[round_input_len - 1] = counter;
        const hash = hmacSHA1(key, round_input[0..round_input_len]);
        const copy_len = @min(Sha1.digest_length, buf.len - pos);
        @memcpy(buf[pos .. pos + copy_len], hash[0..copy_len]);
        pos += copy_len;
        counter += 1;
    }
}

/// Unwrap key with AES Key Wrap Algorithm (RFC3394)
/// `kek` is the Key Encryption Key
/// `cipher` is the wrapped key data
/// `out` is the buffer to write the unwrapped data to
/// Returns the number of bytes written
pub fn aesKeyUnwrap(kek: []const u8, cipher: []const u8, out: []u8) !usize {
    // Check input lengths
    if (cipher.len < 16 or cipher.len % 8 != 0) return error.InvalidCiphertextLength;
    if (out.len < cipher.len - 8) {
        log.err(
            \\Output Buffer Too Small:
            \\- Received: {d}B
            \\- Expected: {d}B
            , .{
                out.len,
                cipher.len,
            },
        );
        return error.OutputBufferTooSmall;
    }
    const n = (cipher.len / 8) - 1;
    // Initial variable setup
    var a: [8]u8 = .{ 0 } ** 8;
    @memcpy(a[0..], cipher[0..8]);
    @memcpy(out[0..n * 8], cipher[8..]);
    // Compute intermediate values
    var b: [16]u8 = .{ 0 } ** 16;
    var j: usize = 5;
    while (true) : (j -= 1) {
        var i: usize = n;
        while (true) : (i -= 1) {
            const r_index = (i - 1) * 8;
            const r = out[r_index..];
            // Copy A to first half of B
            @memcpy(b[0..8], &a);
            // XOR counter t into A
            const t = n * j + i;
            b[7] ^= @as(u8, @intCast(t));
            b[6] ^= @as(u8, @intCast(t >> 8));
            b[5] ^= @as(u8, @intCast(t >> 16));
            b[4] ^= @as(u8, @intCast(t >> 24));
            // Copy R[i] to second half of B
            @memcpy(b[8..], r[0..8]);
            // Decrypt block based on key length
            switch (kek.len) {
                16 => crypto.core.aes.Aes128.initDec(kek[0..16].*).decrypt(b[0..], b[0..]),
                32 => crypto.core.aes.Aes256.initDec(kek[0..32].*).decrypt(b[0..], b[0..]),
                else => return error.InvalidKeyLength,
            }
            @memcpy(a[0..], b[0..8]);
            @memcpy(r[0..8], b[8..16]);
            if (i == 1) break;
        }
        if (j == 0) break;
    }
    // Verify integrity check value
    for (a) |byte| {
        if (byte == 0xa6) continue;
        log.err(
            \\
            \\Invalid AES Integrity Check
            \\- Derived:  {X:0>2}
            \\- Expected: {X:0>2}
            , .{ a, @as([8]u8, .{ 0xA6 } ** 8) },
        );
        return error.UnwrapFailed;
    }
    return n * 8;
}

/// An IEEE 802.11i GTK KDE (Key Data Encapsulation) structure
const GTK_KDE = packed struct {
    /// Must be 0xdd to indicate vendor specific
    type: u8,
    /// Length of remaining fields
    length: u8,
    /// Must be 0x000fac (00:0F:AC in bytes)
    oui: u24,
    /// Must be 0x01 to indicate GTK payload
    data_type: u8,
    /// Reserved
    _reserved: u16,
    /// Key (128 bits = 16B)
    key: u128,
    /// Padding
    _padding: u16
};

/// 4-Way Handshake State
const HandshakeState = enum {
    start,
    m1,
    m2,
    m3,
    m4,
};

/// Handle a 4-Way Handshake
pub fn handle4WHS(if_index: i32, pmk: [32]u8, m2_data: []const u8) !struct{ [48]u8, [16]u8 } {
    var state: HandshakeState = .start;
    log.debug("Starting 4WHS...", .{});
    defer {
        log.debug("{s}", .{
            switch (state) {
                .start => "Failed 4WHS before M1.",
                .m1 => "Failed 4WHS after M1.",
                .m2 => "Failed 4WHS after M2.",
                .m3 => "Failed 4WHS after M3.",
                .m4 => "Finshed 4WHS!",
            }
        });
    }
    const hs_sock = try posix.socket(nl.AF.PACKET, posix.SOCK.RAW, mem.nativeToBig(u16, c(l2.Eth.ETH_P).PAE));
    defer posix.close(hs_sock);
    const sock_addr = posix.sockaddr.ll{
        .ifindex = if_index,
        .protocol = mem.nativeToBig(u16, c(l2.Eth.ETH_P).PAE),
        .hatype = 0,
        .pkttype = 0,
        .halen = 6,
        .addr = .{ 0 } ** 8,
    };
    try posix.setsockopt(
        hs_sock,
        posix.SOL.SOCKET,
        posix.SO.RCVTIMEO,
        mem.toBytes(posix.timeval{ .tv_sec = 3, .tv_usec = 0 })[0..],
    );
    try posix.setsockopt(
        hs_sock,
        posix.SOL.SOCKET,
        posix.SO.RCVBUF,
        mem.toBytes(@as(usize, 1_000_000))[0..],
    );
    try posix.bind(hs_sock, @ptrCast(&sock_addr), @sizeOf(posix.sockaddr.ll));
    // Process 4-Way Handshake
    const eth_hdr_len = @sizeOf(l2.Eth.Header);
    const eap_hdr_len = @sizeOf(l2.EAPOL.Header);
    const kf_hdr_len = @bitSizeOf(l2.EAPOL.KeyFrame) / 8;
    const hdrs_len = eth_hdr_len + eap_hdr_len + kf_hdr_len;
    const KeyInfo = l2.EAPOL.KeyFrame.KeyInfo;
    const ptk_flags = mem.nativeToBig(u16, c(KeyInfo).Version2 | c(KeyInfo).KeyTypePairwise | c(KeyInfo).Ack);
    const mic_flags = mem.nativeToBig(u16, c(KeyInfo).Version2 | c(KeyInfo).KeyTypePairwise | c(KeyInfo).MIC);
    const gtk_flags = mem.nativeToBig(u16, c(KeyInfo).Version2 | c(KeyInfo).KeyTypePairwise | c(KeyInfo).Install | c(KeyInfo).Ack | c(KeyInfo).MIC | c(KeyInfo).Secure);
    const fin_flags = mem.nativeToBig(u16, c(KeyInfo).Version2 | c(KeyInfo).KeyTypePairwise | c(KeyInfo).MIC | c(KeyInfo).Secure);
    log.debug(
        \\
        \\ETH Len = {d}B
        \\EAP Len = {d}B
        \\KF Hdr = {d}B
        \\Hdrs Len = {d}B
        \\
        , .{
            eth_hdr_len,
            eap_hdr_len,
            kf_hdr_len,
            hdrs_len,
        }
    );
    while (true) {
        state = .start;
        const snonce: [32]u8 = snonce: {
            var bytes: [32]u8 = .{ 0 } ** 32;
            crypto.random.bytes(bytes[0..]);
            //mem.reverse(u8, bytes[0..]);
            break :snonce bytes;
        };
        var recv_buf: [1600]u8 = .{ 0 } ** 1600;
        // Message 1
        const m1_len = try posix.recv(hs_sock, recv_buf[0..], 0);
        const m1_buf = recv_buf[0..m1_len];
        var start: usize = 0;
        var end: usize = eth_hdr_len;
        log.debug("Start: {d}B, End: {d}B", .{ start, end });
        const m1_eth_hdr: *const l2.Eth.Header = @alignCast(@ptrCast(m1_buf[start..end]));
        if (mem.bigToNative(u16, m1_eth_hdr.ether_type) != c(l2.Eth.ETH_P).PAE) {
            log.warn("Non-EAPOL: {X}", .{ mem.bigToNative(u16, m1_eth_hdr.ether_type) });
            continue;
        }
        start = end;
        end += eap_hdr_len;
        //log.debug("Start: {d}B, End: {d}B", .{ start, end });
        //const m1_eap_hdr: *const frames.EAPOL.Header = @alignCast(@ptrCast(m1_buf[start..end]));
        const m1_eap_hdr = mem.bytesAsValue(l2.EAPOL.Header, m1_buf[start..end]);
        const eap_packet_type = mem.bigToNative(u8, m1_eap_hdr.packet_type);
        if (eap_packet_type != c(l2.EAPOL.EAP).KEY) {
            log.warn("EAPOL Type: {s}", .{ @tagName(@as(l2.EAPOL.EAP, @enumFromInt(eap_packet_type))) });
            continue;
        }
        start = end;
        end += kf_hdr_len;
        //log.debug("Start: {d}B, End: {d}B", .{ start, end });
        //log.debug("KeyFrame Header Len: {d}B", .{ kf_hdr_len });
        const m1_kf_hdr = mem.bytesAsValue(l2.EAPOL.KeyFrame, m1_buf[start..end]);
        log.debug(
            \\
            \\-------------------------------------
            \\M1:
            \\  - Key Info:  0x{X:0>4}
            \\  - PTK Flags: 0x{X:0>4}
            \\  - Replay Counter: {d}
            \\
            , .{ 
                mem.bigToNative(u16, m1_kf_hdr.key_info),
                mem.bigToNative(u16, ptk_flags),
                mem.bigToNative(u64, m1_kf_hdr.replay_counter),
            },
        );
        if (m1_kf_hdr.key_info & ptk_flags != ptk_flags) return error.ExpectedPTK;
        if (m1_kf_hdr.key_info & c(KeyInfo).MIC == c(KeyInfo).MIC) return error.UnexpectedMIC;
        const ap_mac = m1_eth_hdr.src_mac_addr;
        const client_mac = m1_eth_hdr.dst_mac_addr;
        const anonce = mem.toBytes(m1_kf_hdr.key_nonce);
        const m1_rc = mem.bigToNative(u64, m1_kf_hdr.replay_counter);
        // Gen PTK, KCK, & KEK
        const ptk = genPTK(
            pmk,
            anonce,
            snonce,
            client_mac,
            ap_mac,
        );
        const kck = ptk[0..16];
        const kek = ptk[16..32];
        state = .m1;
        // Message 2
        const m2_eth_hdr: l2.Eth.Header = .{
            .dst_mac_addr = ap_mac,
            .src_mac_addr = client_mac,
            .ether_type = m1_eth_hdr.ether_type,
        };
        const m2_eap_hdr: l2.EAPOL.Header = .{
            .protocol_version = m1_eap_hdr.protocol_version,
            .packet_type = m1_eap_hdr.packet_type,
            .packet_length = mem.nativeToBig(u16, kf_hdr_len + @as(u16, @intCast(m2_data.len))),
        };
        var m2_kf_hdr = m1_kf_hdr.*;
        m2_kf_hdr.key_info = mic_flags;
        m2_kf_hdr.key_len = 0;
        m2_kf_hdr.key_nonce = @bitCast(snonce);
        m2_kf_hdr.key_mic = 0;
        m2_kf_hdr.key_data_len = mem.nativeToBig(u16, @intCast(m2_data.len));
        // - Gen M2 MIC
        var m2_mic_buf: [1600]u8 = .{ 0 } ** 1600;
        start = 0;
        end = eap_hdr_len;
        @memcpy(m2_mic_buf[start..end], mem.toBytes(m2_eap_hdr)[0..]);
        start = end;
        end += kf_hdr_len;
        @memcpy(m2_mic_buf[start..end], mem.toBytes(m2_kf_hdr)[0..kf_hdr_len]);
        start = end;
        end += m2_data.len;
        @memcpy(m2_mic_buf[start..end], m2_data);
        const m2_mic = hmacSHA1(kck, m2_mic_buf[0..end])[0..16];
        m2_kf_hdr.key_mic = mem.bytesToValue(u128, m2_mic); //[0..16].*;
        // - Send M2
        var m2_buf: [1600]u8 = .{ 0 } ** 1600;
        start = 0;
        end = eth_hdr_len;
        @memcpy(m2_buf[start..end], mem.toBytes(m2_eth_hdr)[0..]);
        start = end;
        end += eap_hdr_len;
        @memcpy(m2_buf[start..end], mem.toBytes(m2_eap_hdr)[0..]);
        start = end;
        end += kf_hdr_len;
        @memcpy(m2_buf[start..end], mem.toBytes(m2_kf_hdr)[0..kf_hdr_len]);
        start = end;
        end += m2_data.len;
        @memcpy(m2_buf[start..end], m2_data);
        _ = try posix.send(hs_sock, m2_buf[0..end], 0);
        log.debug(
            \\
            \\-------------------------------------
            \\M2:
            \\- A1: {X:0>2}
            \\- A2: {X:0>2}
            \\- PMK: {X:0>2}
            \\- ANonce: {X:0>2}
            \\- SNonce: {X:0>2}
            \\- PTK: {X:0>2}
            \\  - KCK: {X:0>2}
            \\  - KEK: {X:0>2}
            \\- MIC: {X:0>2}
            \\
            , .{
                if (mem.order(u8, client_mac[0..], ap_mac[0..]) == .lt) client_mac else ap_mac,
                if (mem.order(u8, client_mac[0..], ap_mac[0..]) == .gt) client_mac else ap_mac,
                pmk,
                anonce,
                snonce,
                ptk,
                kck,
                kek,
                m2_mic,
            },
        );
        state = .m2;
        // Message 3
        recv_buf = .{ 0 } ** 1600;
        const m3_len = try posix.recv(hs_sock, recv_buf[0..], 0);
        const m3_buf = recv_buf[0..m3_len];
        start = 0;
        end = eth_hdr_len;
        const m3_eth_hdr: *const l2.Eth.Header = @alignCast(@ptrCast(m3_buf[start..end]));
        if (mem.bigToNative(u16, m3_eth_hdr.ether_type) != c(l2.Eth.ETH_P).PAE) {
            log.warn("Non-EAPOL: {X}", .{ mem.bigToNative(u16, m3_eth_hdr.ether_type) });
            continue;
        }
        //log.debug("Start: {d}B, End: {d}B", .{ start, end });
        start = end;
        end += eap_hdr_len;
        const m3_eap_hdr = mem.bytesAsValue(l2.EAPOL.Header, m3_buf[start..end]);
        start = end;
        end += kf_hdr_len;
        const m3_kf_hdr = mem.bytesToValue(l2.EAPOL.KeyFrame, m3_buf[start..end]);
        start = end;
        end += mem.bigToNative(u16, m3_kf_hdr.key_data_len);
        const m3_key_data = m3_buf[start..end];
        log.debug(
            \\
            \\-------------------------------------
            \\M3:
            \\- EAP Header:
            \\  - Src:  0x{X:0>2}
            \\  - Type: 0x{X:0>2}
            \\  - Len:  {d}B
            \\- Replay Counter: {d}
            \\- Key Info:  0x{X:0>4}
            \\- GTK Flags: 0x{X:0>4}
            \\- Key Len:   {d}B
            \\- Key Data:  {X:0>2}
            , .{
                m3_eap_hdr.protocol_version,
                m3_eap_hdr.packet_type,
                mem.bigToNative(u16, m3_eap_hdr.packet_length),
                mem.bigToNative(u64, m3_kf_hdr.replay_counter),
                mem.bigToNative(u16, m3_kf_hdr.key_info),
                mem.bigToNative(u16, gtk_flags),
                mem.bigToNative(u16, m3_kf_hdr.key_data_len),
                m3_key_data,
            },
        );
        // - Validate M3
        // -- Unexpected Flags
        const m3_info = m3_kf_hdr.key_info;
        if (m3_kf_hdr.key_info & gtk_flags != gtk_flags) {
            log.err(
                \\Unexpected Flags:
                \\- Received: 0x{X:0>4}
                \\- Expected: 0x{X:0>4}
                , .{
                    mem.bigToNative(u16, m3_info) & gtk_flags,
                    gtk_flags,
                }
            );
            //continue;
            return error.UnexpectedFlags;
        }
        // -- Key Length Mismatch
        if (mem.bigToNative(u16, m3_kf_hdr.key_len) != 16) {
            log.err(
                \\Key Length Mismatch: 
                \\- Received: {d}B
                \\- Expected: 16B
                , .{ mem.bigToNative(u16, m3_kf_hdr.key_len) }
            );
            return error.KeyLengthMismatch;
        }
        // -- Replay Counter Mismatch
        if (mem.bigToNative(u64, m3_kf_hdr.replay_counter) != m1_rc + 1) {
            log.err(
                \\Replay Counter Mismatch:
                \\- Received: {d}
                \\- Expected: {d}
                , .{
                    mem.bigToNative(u64, m3_kf_hdr.replay_counter),
                    m1_rc + 1,
                },
            );
            return error.ReplayCounterMismatch;
        }
        // -- M3 MIC Mismatch
        const m3_mic_actual = m3_kf_hdr.key_mic;
        var m3_mic_buf = m3_buf[eth_hdr_len..];
        const mic_offset = eap_hdr_len + kf_hdr_len - 18;
        @memset(m3_mic_buf[(mic_offset)..(mic_offset + 16)], 0);
        end -= eth_hdr_len;
        const m3_mic_valid = hmacSHA1(kck, m3_mic_buf[0..end])[0..16];
        if (!mem.eql(u8, mem.toBytes(m3_mic_actual)[0..], m3_mic_valid[0..])) {
            log.err(
                \\MIC Mismatch:
                \\- Received: {X:0>2}
                \\- Expected: {X:0>2}
                , .{
                    mem.toBytes(m3_mic_actual)[0..],
                    m3_mic_valid[0..],
                },
            );
            //continue;
            return error.Message3MICMismatch;
        }
        // - Handle Key Data
        var m3_uw_buf: [500]u8 = .{ 0 } ** 500;
        const m3_uw_data = uwKeyData: {
            //log.debug(
            //    \\Encrypted M3 Data:
            //    \\- Info: 0b{b:0>16}
            //    \\- Bool: 0b{b:0>16}
            //    \\- Flag: 0b{b:0>16}
            //    , .{
            //        mem.bigToNative(u16, m3_info),
            //        mem.bigToNative(u16, m3_info) & c(KeyInfo).EncryptedData,
            //        c(KeyInfo).EncryptedData,
            //    },
            //);
            if (mem.bigToNative(u16, m3_info) & c(KeyInfo).EncryptedData == c(KeyInfo).EncryptedData) {
                const uw_len = try aesKeyUnwrap(kek, m3_key_data, m3_uw_buf[0..]);
                break :uwKeyData m3_uw_buf[0..uw_len];
            }
            else break :uwKeyData m3_key_data;
        };
        //log.debug("Decrypted Key Data:\n{X:0>2}", .{ m3_uw_data });
        start = m3_uw_data[1] + 2;
        end = start + (m3_uw_data[start + 1]) + 2;
        const m3_gtk_kde = mem.bytesAsValue(GTK_KDE, m3_uw_data[start..end]);
        //log.debug("GTK: {X:0>2}", .{ mem.toBytes(m3_gtk_kde.key)[0..] });
        const gtk: [16]u8 = mem.toBytes(m3_gtk_kde.key);
        state = .m3;
        // Message 4
        const m4_eth_hdr = m2_eth_hdr;
        var m4_eap_hdr = m2_eap_hdr;
        var m4_kf_hdr = m2_kf_hdr;
        m4_eap_hdr.packet_length = mem.nativeToBig(u16, kf_hdr_len);
        m4_kf_hdr.replay_counter = m3_kf_hdr.replay_counter;
        m4_kf_hdr.key_info = fin_flags;
        m4_kf_hdr.key_mic = 0;
        m4_kf_hdr.key_nonce = 0;
        m4_kf_hdr.key_data_len = 0;
        var m4_mic_buf: [hdrs_len]u8 = .{ 0 } ** hdrs_len;
        start = 0;
        end = eap_hdr_len;
        @memcpy(m4_mic_buf[start..end], mem.toBytes(m4_eap_hdr)[0..]);
        start = end;
        end += kf_hdr_len;
        @memcpy(m4_mic_buf[start..end], mem.toBytes(m4_kf_hdr)[0..kf_hdr_len]);
        const m4_mic = hmacSHA1(kck, m4_mic_buf[0..end])[0..16];
        m4_kf_hdr.key_mic = mem.bytesToValue(u128, m4_mic);
        // - Send M4
        var m4_buf: [hdrs_len]u8 = .{ 0 } ** hdrs_len;
        start = 0;
        end = eth_hdr_len;
        @memcpy(m4_buf[start..end], mem.toBytes(m4_eth_hdr)[0..]);
        start = end;
        end += eap_hdr_len;
        @memcpy(m4_buf[start..end], mem.toBytes(m4_eap_hdr)[0..]);
        start = end;
        end += kf_hdr_len;
        @memcpy(m4_buf[start..end], mem.toBytes(m4_kf_hdr)[0..kf_hdr_len]);
        _ = try posix.send(hs_sock, m4_buf[0..], 0);
        log.debug(
            \\
            \\-------------------------------------
            \\M4:
            \\- A1: {X:0>2}
            \\- A2: {X:0>2}
            \\- PMK: {X:0>2}
            \\- ANonce: {X:0>2}
            \\- SNonce: {X:0>2}
            \\- PTK: {X:0>2}
            \\  - KCK: {X:0>2}
            \\  - KEK: {X:0>2}
            \\- MIC: {X:0>2}
            \\
            , .{
                if (mem.order(u8, client_mac[0..], ap_mac[0..]) == .lt) client_mac else ap_mac,
                if (mem.order(u8, client_mac[0..], ap_mac[0..]) == .gt) client_mac else ap_mac,
                pmk,
                anonce,
                snonce,
                ptk,
                kck,
                kek,
                m4_mic,
            },
        );
        state = .m4;

        return .{ ptk, gtk };
    }
}
