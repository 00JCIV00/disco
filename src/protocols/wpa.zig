//! WEP/WPA Security Protocol functions for DisCo.

const std = @import("std");
const bpf = std.os.linux.BPF;
const crypto = std.crypto;
const fmt = std.fmt;
const json = std.json;
const log = std.log.scoped(.wpa);
const mem = std.mem;
const posix = std.posix;
const testing = std.testing;

const CmacAes128 = crypto.auth.cmac.CmacAes128;
const hkdf = crypto.kdf.hkdf;
const hmac = crypto.auth.hmac;
const Md5 = crypto.hash.Md5;

const nl = @import("../netlink.zig");
const netdata = @import("../netdata.zig");
const utils = @import("../utils.zig");
const HexF = utils.HexFormatter;
const InHexF = utils.SliceFormatter(u8, "{X:0>2}");
const DecF = utils.SliceFormatter(u8, "{d}");

const c = utils.toStruct;
const l2 = netdata.l2;
const MACF = netdata.address.MACFormatter;

/// Calculate a WEP Key or WPA Pre-Shared Key (PSK) using MD5 or PBKDF2 with HMAC-SHA1.
pub fn genKey(protocol: nl._80211.SecurityType, ssid: []const u8, passphrase: []const u8) ![32]u8 {
    var key: [32]u8 = @splat(0);
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
    security: nl._80211.SecurityType,
) [48]u8 {
    const label = "Pairwise key expansion";
    const mac_len = 6;
    const nonce_len = 32;
    const data_len = 2 * mac_len + 2 * nonce_len;
    //const data_len = label.len + 2 * mac_len + 2 * nonce_len;
    var data: [data_len]u8 = undefined;
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
    @memcpy(data[mac_pair_len..(mac_pair_len + nonce_len)], first_nonce);
    @memcpy(data[mac_pair_len + nonce_len..], second_nonce);
    var ptk_buf: [48]u8 = undefined;
    //_ = sha1PRF(pmk[0..], label, data[0..], ptk[0..]);
    switch (security) {
        .wpa2 => {
            log.debug("Using PRF(SHA1)", .{});
            prf(
                hmac.HmacSha1,
                pmk[0..],
                label,
                data[0..],
                ptk_buf[0..],
            );
        },
        else => {
            log.debug("Using PRF(SHA256)", .{});
            prfSha256(
                pmk[0..],
                label,
                data[0..],
                ptk_buf[0..],
            );
        },
    }
    return ptk_buf[0..48].*;
}

/// Generic PRF using the provided `Hmac`
fn prf(
    Hmac: type,
    key: []const u8,
    label: []const u8,
    data: []const u8,
    buf: []u8,
) void {
    var counter: u8 = 0;
    var pos: usize = 0;
    var ln_buf: [256]u8 = undefined;
    const label_null = labelNull: {
        @memcpy(ln_buf[0..label.len], label[0..]);
        ln_buf[label.len] = 0;
        break :labelNull ln_buf[0..label.len + 1];
    };
    while (pos < buf.len) : (counter += 1) {
        const round_input_len = label_null.len + data.len + 1;
        var round_input: [512]u8 = undefined;
        @memcpy(round_input[0..label_null.len], label_null);
        @memcpy(round_input[(label_null.len)..][0..data.len], data);
        round_input[round_input_len - 1] = counter;
        var hash_buf: [Hmac.mac_length]u8 = undefined;
        Hmac.create(hash_buf[0..], round_input[0..round_input_len], key);
        const copy_len = @min(Hmac.mac_length, buf.len - pos);
        @memcpy(buf[pos..(pos + copy_len)], hash_buf[0..copy_len]);
        pos += copy_len;
    }
}

/// PRF using HMAC-SHA256 f/ WPA3
pub fn prfSha256(
    key: []const u8,
    label: []const u8,
    data: []const u8,
    out: []u8,
) void {
    const hmac256 = hmac.sha2.HmacSha256;
    const output_bits: u16 = @truncate(out.len * 8);
    log.debug("Output Bits: {d}", .{ output_bits });
    const out_len = @divTrunc(output_bits + 7, 8);
    var hash_buf: [hmac256.mac_length]u8 = undefined;
    var pos: usize = 0;
    var counter: u16 = 1;
    var counter_bytes: [2]u8 = undefined;
    var length_bytes: [2]u8 = undefined;
    //mem.writeInt(u16, length_bytes[0..], output_bits, .little);
    length_bytes = mem.toBytes(output_bits);
    while (pos < out_len) : (counter += 1) {
        //mem.writeInt(u16, counter_bytes[0..], counter, .little);
        counter_bytes = mem.toBytes(counter);
        var vec: [512]u8 = undefined;
        var off: usize = 0;
        @memcpy(vec[off..][0..2], counter_bytes[0..]);
        off += 2;
        @memcpy(vec[off..][0..label.len], label[0..]);
        off += label.len;
        @memcpy(vec[off..][0..data.len], data[0..]);
        off += data.len;
        @memcpy(vec[off..][0..2], length_bytes[0..]);
        off += 2;
        hmac256.create(hash_buf[0..], vec[0..off], key);
        const copy_len = @min(hmac256.mac_length, out_len - pos);
        @memcpy(out[pos..][0..copy_len], hash_buf[0..copy_len]);
        pos += copy_len;
    }
    if (output_bits % 8 != 0) {
        const mask: u8 = @as(u8, 0xff) << @as(u3, @intCast(8 - (output_bits % 8)));
        out[out.len - 1] &= mask;
    }
    @memset(hash_buf[0..], 0);
}

/// Derives a key using IEEE 802.11 PRF (not HKDF).
/// 
/// `key` – The base key for the PRF (e.g., PMK).  
/// `label` – Purpose-specific ASCII string.  
/// `data` – Context-specific data (e.g., nonces, MAC addresses).  
/// `output_bits` – Desired output length in **bits**.
///
/// Writes output to `out`, returns error if PRF fails.
pub fn sha256PRFBits(
    key: []const u8,
    label: []const u8,
    data: []const u8,
    output_bits: u16,
    out: []u8,
) !void {
    const hmac256 = hmac.sha2.HmacSha256;
    var counter: u16 = 1;
    const output_len = (output_bits + 7) / 8;
    if (out.len < output_len) return error.OutputBufferTooSmall;
    var pos: usize = 0;
    var hash: [hmac256.mac_length]u8 = undefined;
    var length_bytes: [2]u8 = undefined;
    var counter_bytes: [2]u8 = undefined;
    mem.writeInt(u16, length_bytes[0..], output_bits, .little);
    while (pos < output_len) {
        const remaining = output_len - pos;
        mem.writeInt(u16, counter_bytes[0..], counter, .little);
        var vec_array: [256]u8 = undefined;
        var vec_counter: usize = 0;
        inline for (&.{
            counter_bytes[0..],
            label,
            data,
            length_bytes[0..],
        }) |vec_bytes| {
            @memcpy(vec_array[vec_counter..(vec_counter + vec_bytes.len)], vec_bytes);
            vec_counter += vec_bytes.len;
        }
        const vec = vec_array[0..vec_counter];
        if (remaining >= hmac256.mac_length) {
            hmac256.create(out[pos..(pos + hmac256.mac_length)][0..hmac256.mac_length], vec, key);
            pos += hmac256.mac_length;
        }
        else {
            hmac256.create(hash[0..hmac256.mac_length], vec, key);
            @memcpy(out[pos..(pos + remaining)], hash[0..remaining]);
            pos += remaining;
            break;
        }
        counter += 1;
    }
    // Mask final bits if output_bits isn't byte-aligned
    //if (output_bits % 8 != 0) {
    //    const mask: u8 = 0xff << (8 - (output_bits % 8));
    //    out[output_len - 1] &= mask;
    //}
    // Clear sensitive material
    @memset(hash[0..], 0);
}

// Maybe make a `crypto.zig` f/ this and other functions?
fn prfBits(
    comptime Hmac: type,
    key: []const u8,
    label: []const u8,
    data: []const u8,
    output_bits: u16,
    buf: []u8,
) !void {
    const mac_len = Hmac.mac_length;
    const output_len = (output_bits + 7) / 8;
    if (buf.len < output_len) return error.OutputBufferTooSmall;
    var counter: u16 = 1;
    var pos: usize = 0;
    var hash: [mac_len]u8 = undefined;
    var length_bytes: [2]u8 = undefined;
    var counter_bytes: [2]u8 = undefined;
    mem.writeInt(u16, length_bytes[0..], output_bits, .little);
    while (pos < output_len) : (counter += 1) {
        mem.writeInt(u16, counter_bytes[0..], counter, .little);
        var vec_array: [512]u8 = undefined;
        var vec_counter: usize = 0;
        inline for (&.{
            counter_bytes[0..],
            label,
            data,
            length_bytes[0..],
        }) |vec_bytes| {
            @memcpy(vec_array[vec_counter..(vec_counter + vec_bytes.len)], vec_bytes);
            vec_counter += vec_bytes.len;
        }
        const vec = vec_array[0..vec_counter];
        const remaining = output_len - pos;
        if (remaining >= mac_len) {
            var hmac_buf: [Hmac.mac_length]u8 = undefined;
            Hmac.create(hmac_buf[0..], vec, key);
            @memcpy(buf[pos..(pos + mac_len)], hmac_buf[0..]);
            pos += mac_len;
        } else {
            Hmac.create(hash[0..], vec, key);
            @memcpy(buf[pos..(pos + remaining)], hash[0..remaining]);
            pos += remaining;
            break;
        }
    }
}

test "PRF(SHA1)" {
    testing.log_level = .debug;
    log.info("=== PRF(SHA1) ===", .{});
    const key = "Jefe";
    const label = "prefix-2";
    const data = "what do ya want for nothing?";
    const sha1_result = [_]u8{ 
        0x47, 0xc4, 0x90, 0x8e, 0x30, 0xc9, 0x47, 0x52, 
        0x1a, 0xd2, 0x0b, 0xe9, 0x05, 0x34, 0x50, 0xec, 
        0xbe, 0xa2, 0x3d, 0x3a, 0xa6, 0x04, 0xb7, 0x73, 
        0x26, 0xd8, 0xb3, 0x82, 0x5f, 0xf7, 0x47, 0x5c, 
    };
    var prf_sha1_buf: [32]u8 = undefined;
    prf(
        hmac.HmacSha1,
        key,
        label,
        data,
        prf_sha1_buf[0..],
    );
    log.debug(
        \\
        \\ prf(sha-1)
        \\ - Calc'ed:  {f}
        \\ - Expected: {f}
        \\
        , .{
            HexF{ .bytes = prf_sha1_buf[0..] },
            HexF{ .bytes = sha1_result[0..] },
        },
    );
    try testing.expect(mem.eql(u8, prf_sha1_buf[0..], sha1_result[0..]));
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
    var a: [8]u8 = @splat(0);
    @memcpy(a[0..], cipher[0..8]);
    @memcpy(out[0..n * 8], cipher[8..]);
    // Compute intermediate values
    var b: [16]u8 = @splat(0);
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
            \\- Derived:  {f}
            \\- Expected: {f}
            , .{ InHexF{ .slice = a[0..] }, InHexF{ .slice = @as([8]u8, @splat(0xA6))[0..] } },
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
pub fn handle4WHS(
    if_index: i32,
    pmk: [32]u8,
    m2_data: []const u8,
    security: nl._80211.SecurityType,
) !nl._80211.EAPoLKeys {
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
        .addr = @splat(0),
    };
    try posix.setsockopt(
        hs_sock,
        posix.SOL.SOCKET,
        posix.SO.RCVTIMEO,
        mem.toBytes(posix.timeval{ .sec = 1, .usec = 0 })[0..],
    );
    try posix.setsockopt(
        hs_sock,
        posix.SOL.SOCKET,
        posix.SO.RCVBUF,
        mem.toBytes(@as(usize, 10_000))[0..],
    );
    try posix.bind(hs_sock, @ptrCast(&sock_addr), @sizeOf(posix.sockaddr.ll));
    // Process 4-Way Handshake
    const eth_hdr_len = @sizeOf(l2.Eth.Header);
    const eap_hdr_len = @sizeOf(l2.EAPOL.Header);
    const kf_hdr_len = @bitSizeOf(l2.EAPOL.KeyFrame) / 8;
    const hdrs_len = eth_hdr_len + eap_hdr_len + kf_hdr_len;
    const KeyInfo = l2.EAPOL.KeyFrame.KeyInfo;
    const desc_info = switch(security) {
        .wpa2 => c(KeyInfo).Version2,
        else => 0,
    };
    const ptk_flags = mem.nativeToBig(u16, desc_info | c(KeyInfo).KeyTypePairwise | c(KeyInfo).Ack);
    const mic_flags = mem.nativeToBig(u16, desc_info | c(KeyInfo).KeyTypePairwise | c(KeyInfo).MIC);
    const gtk_flags = mem.nativeToBig(u16, desc_info | c(KeyInfo).KeyTypePairwise | c(KeyInfo).Install | c(KeyInfo).Ack | c(KeyInfo).MIC | c(KeyInfo).Secure);
    const fin_flags = mem.nativeToBig(u16, desc_info | c(KeyInfo).KeyTypePairwise | c(KeyInfo).MIC | c(KeyInfo).Secure);
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
            var bytes: [32]u8 = undefined;
            crypto.random.bytes(bytes[0..]);
            break :snonce bytes;
        };
        var recv_buf: [1600]u8 = undefined;
        // Message 1
        const m1_len = try posix.recv(hs_sock, recv_buf[0..], 0);
        const m1_buf = recv_buf[0..m1_len];
        var start: usize = 0;
        var end: usize = eth_hdr_len;
        log.debug("Start: {d}B, End: {d}B", .{ start, end });
        const m1_eth_hdr = mem.bytesAsValue(l2.Eth.Header, m1_buf[start..end]);
        if (mem.bigToNative(u16, m1_eth_hdr.ether_type) != c(l2.Eth.ETH_P).PAE) {
            log.warn("Non-EAPOL: {X}", .{ mem.bigToNative(u16, m1_eth_hdr.ether_type) });
            continue;
        }
        start = end;
        end += eap_hdr_len;
        //log.debug("Start: {d}B, End: {d}B", .{ start, end });
        const m1_eap_hdr = mem.bytesAsValue(l2.EAPOL.Header, m1_buf[start..end]);
        const eap_packet_type = mem.bigToNative(u8, m1_eap_hdr.packet_type);
        if (eap_packet_type != c(l2.EAPOL.EAP).KEY) {
            log.warn("EAPOL Type: {t}", .{ @as(l2.EAPOL.EAP, @enumFromInt(eap_packet_type)) });
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
        if ( //
            m1_kf_hdr.key_info & ptk_flags != ptk_flags and ( //
                (security == .wpa3t or security == .wpa3) and //
                m1_kf_hdr.key_info != (ptk_flags) //
            )
        ) return error.ExpectedPTK;
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
            security,
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
        var m2_mic_buf: [1600]u8 = undefined;
        start = 0;
        end = eap_hdr_len;
        @memcpy(m2_mic_buf[start..end], mem.toBytes(m2_eap_hdr)[0..]);
        start = end;
        end += kf_hdr_len;
        @memcpy(m2_mic_buf[start..end], mem.toBytes(m2_kf_hdr)[0..kf_hdr_len]);
        start = end;
        end += m2_data.len;
        @memcpy(m2_mic_buf[start..end], m2_data);
        const m2_mic: [16]u8 = switch (security) {
            .wpa3t, .wpa3 => cmacAes128: {
                var m2_mic: [16]u8 = undefined;
                CmacAes128.create(m2_mic[0..], m2_mic_buf[0..end], kck);
                break :cmacAes128 m2_mic;
            },
            else => hmacSha1: {
                var m2_mic: [20]u8 = undefined;
                hmac.HmacSha1.create(m2_mic[0..], m2_mic_buf[0..end], kck);
                break :hmacSha1 m2_mic[0..16].*;
            },
        };
        m2_kf_hdr.key_mic = mem.bytesToValue(u128, m2_mic[0..]);
        // - Send M2
        var m2_buf: [1600]u8 = undefined;
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
            \\- A1: {f}
            \\- A2: {f}
            \\- PMK: {f}
            \\- ANonce: {f}
            \\- SNonce: {f}
            \\- PTK: {f}
            \\  - KCK: {f}
            \\  - KEK: {f}
            \\- MIC: {f}
            \\
            , .{
                MACF{ .bytes = if (mem.order(u8, client_mac[0..], ap_mac[0..]) == .lt) client_mac[0..] else ap_mac[0..] },
                MACF{ .bytes = if (mem.order(u8, client_mac[0..], ap_mac[0..]) == .gt) client_mac[0..] else ap_mac[0..] },
                InHexF{ .slice = pmk[0..] },
                InHexF{ .slice = anonce[0..] },
                InHexF{ .slice = snonce[0..] },
                InHexF{ .slice = ptk[0..] },
                InHexF{ .slice = kck[0..] },
                InHexF{ .slice = kek[0..] },
                InHexF{ .slice = m2_mic[0..] },
            },
        );
        state = .m2;
        // Message 3
        recv_buf = @splat(0);
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
            \\- Key Data:  {f}
            , .{
                m3_eap_hdr.protocol_version,
                m3_eap_hdr.packet_type,
                mem.bigToNative(u16, m3_eap_hdr.packet_length),
                mem.bigToNative(u64, m3_kf_hdr.replay_counter),
                mem.bigToNative(u16, m3_kf_hdr.key_info),
                mem.bigToNative(u16, gtk_flags),
                mem.bigToNative(u16, m3_kf_hdr.key_data_len),
                InHexF{ .slice = m3_key_data[0..] },
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
        const m3_mic_valid: [16]u8 = switch (security) {
            .wpa3t, .wpa3 => cmacAes128: {
                var m3_mic_valid: [16]u8 = undefined;
                CmacAes128.create(m3_mic_valid[0..], m3_mic_buf[0..end], kck);
                break :cmacAes128 m3_mic_valid;
            },
            else => hmacSha1: {
                var m3_mic_valid: [20]u8 = undefined;
                hmac.HmacSha1.create(m3_mic_valid[0..], m3_mic_buf[0..end], kck);
                break :hmacSha1 m3_mic_valid[0..16].*;
            },
        };
        if (!mem.eql(u8, mem.toBytes(m3_mic_actual)[0..], m3_mic_valid[0..])) {
            log.err(
                \\MIC Mismatch:
                \\- Received: {f}
                \\- Expected: {f}
                , .{
                    InHexF{ .slice = mem.toBytes(m3_mic_actual)[0..] },
                    InHexF{ .slice = m3_mic_valid[0..] },
                },
            );
            //continue;
            return error.Message3MICMismatch;
        }
        // - Handle Key Data
        var m3_uw_buf: [500]u8 = undefined;
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
        var m4_mic_buf: [hdrs_len]u8 = @splat(0);
        start = 0;
        end = eap_hdr_len;
        @memcpy(m4_mic_buf[start..end], mem.toBytes(m4_eap_hdr)[0..]);
        start = end;
        end += kf_hdr_len;
        @memcpy(m4_mic_buf[start..end], mem.toBytes(m4_kf_hdr)[0..kf_hdr_len]);
        //const m4_mic: [16]u8 = hmacSha1: {
        //    var m4_mic: [20] u8 = undefined;
        //    hmac.HmacSha1.create(m4_mic[0..], m4_mic_buf[0..end], kck);
        //    break :hmacSha1 m4_mic[0..16].*;
        //};
        const m4_mic: [16]u8 = switch (security) {
            .wpa3t, .wpa3 => cmacAes128: {
                var m4_mic: [16]u8 = undefined;
                CmacAes128.create(m4_mic[0..], m4_mic_buf[0..end], kck);
                break :cmacAes128 m4_mic;
            },
            else => hmacSha1: {
                var m4_mic: [20]u8 = undefined;
                hmac.HmacSha1.create(m4_mic[0..], m4_mic_buf[0..end], kck);
                break :hmacSha1 m4_mic[0..16].*;
            },
        };
        m4_kf_hdr.key_mic = mem.bytesToValue(u128, m4_mic[0..]);
        // - Send M4
        var m4_buf: [hdrs_len]u8 = @splat(0);
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
            \\- A1: {f}
            \\- A2: {f}
            \\- PMK: {f}
            \\- ANonce: {f}
            \\- SNonce: {f}
            \\- PTK: {f}
            \\  - KCK: {f}
            \\  - KEK: {f}
            \\- MIC: {f}
            \\
            , .{
                MACF{ .bytes = if (mem.order(u8, client_mac[0..], ap_mac[0..]) == .lt) client_mac[0..] else ap_mac[0..] },
                MACF{ .bytes = if (mem.order(u8, client_mac[0..], ap_mac[0..]) == .gt) client_mac[0..] else ap_mac[0..] },
                InHexF{ .slice = pmk[0..] },
                InHexF{ .slice = anonce[0..] },
                InHexF{ .slice = snonce[0..] },
                InHexF{ .slice = ptk[0..] },
                InHexF{ .slice = kck[0..] },
                InHexF{ .slice = kek[0..] },
                InHexF{ .slice = m4_mic[0..] },
            },
        );
        state = .m4;
        return .{ .ptk = ptk, .gtk = gtk };
    }
}
