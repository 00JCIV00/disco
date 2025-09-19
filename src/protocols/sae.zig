//! Simultaneous Authentication of Equals (SAE) and Elliptic Curve Diffie Helman (ECDH) functions for DisCo.

const std = @import("std");
const crypto = std.crypto;
const Ed25519 = crypto.ecc.Edwards25519;
const hmac256 = crypto.auth.hmac.sha2.HmacSha256;
//const pbkdf2 = crypto.pwhash.pbkdf2;
const hkdf = crypto.kdf.hkdf.HkdfSha256;
const P256 = crypto.ecc.P256;
const math = std.math;
const mem = std.mem;
const log = std.log.scoped(.sae);
const netdata = @import("../netdata.zig");
const address = netdata.address;
const MACF = address.MACFormatter;
const utils = @import("../utils.zig");
const HexF = utils.HexFormatter;

/// SAE Errors
pub const SAEError = error{
    InvalidElement,
    InvalidScalar,
    LoopCountExceeded,
    HashToElementFailed,
    CommitTokenMismatch,
    ConfirmTokenMismatch,
};

/// SAE Context
pub const Context = struct {
    private: [32]u8,
    pwe: P256,
    commit: Commit,
    send_confirm: [2]u8 = sendConfirm: {
        var buf: [2]u8 = undefined;
        mem.writeInt(u16, buf[0..], 1, .big);
        break :sendConfirm buf;
    },
    confirm: ?[32]u8 = null,
    kck: ?[32]u8 = null,
    pmk: ?[32]u8 = null,
};

/// Result of SAE Commit Generation.
pub const Commit = struct {
    scalar: [32]u8,
    element: P256,
};

/// P256 Order
const p256_order: u256 = mem.readInt(
    u256,
    &[_]u8{
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
        0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
    },
    .big,
);

/// Generate SAE Commit Message Data within overall SAE Context.
pub fn genCommit(password: []const u8, addr1: [6]u8, addr2: [6]u8) !Context {
    log.debug("Generating SAE Commit...", .{});
    // Generate random private and mask values
    const private: [32]u8 = P256.scalar.random(.big);
    var mask: [32]u8 = P256.scalar.random(.big);
    defer @memset(mask[0..], 0);
    // Calculate commit-scalar = (private + mask) mod r
    const scalar: [32]u8 = scalar: {
        const priv_int: u512 = mem.readInt(u256, private[0..], .big);
        const mask_int: u512 = mem.readInt(u256, mask[0..], .big);
        const scalar_int: u256 = @truncate((priv_int + mask_int) % p256_order);
        if (scalar_int < 2 or scalar_int >= p256_order) {
            log.err("Scalar is invalid: {d}", .{ scalar_int });
            return error.InvalidScalar;
        }
        break :scalar mem.toBytes(mem.nativeTo(u256, scalar_int, .big));
    };
    // Calculate password element through hunting-and-pecking
    const pe = try hashToElement(password, addr1, addr2);
    // Calculate commit-element = inverse(scalar-op(mask, PE))
    const ce: P256 = ce: {
        const masked_pe = maskedPE: {
            const raw = try pe.mul(mask, .big);
            log.debug(
                "Raw Masked CE:\n- X:{f}\n- Y:{f}"
                , .{
                    HexF{ .bytes = raw.x.toBytes(.big)[0..] },
                    HexF{ .bytes = raw.y.toBytes(.big)[0..] },
                },
            );
            break :maskedPE try P256.fromAffineCoordinates(raw.affineCoordinates());
        };
        log.debug(
            "Affine Masked PE:\n- X:{f}\n- Y:{f}"
            , .{
                HexF{ .bytes = masked_pe.x.toBytes(.big)[0..] },
                HexF{ .bytes = masked_pe.y.toBytes(.big)[0..] },
            },
        );
        //const masked_pe = try pe.mul(mask, .big);
        masked_pe.rejectIdentity() catch |err| {
            log.err("Masked PE Identity Rejected.", .{});
            return err;
        };
        break :ce try P256.fromAffineCoordinates(.{
            .x = masked_pe.x,
            .y = masked_pe.y.neg(),
        });
    };
    log.debug(
        \\Generated SAE Commit.
        \\ - PE X:   {f}
        \\ - PE Y:   {f}
        \\ - Scalar: {f}
        \\ - CE X:   {f}
        \\ - CE Y:   {f}
        , .{
            HexF{ .bytes = pe.x.toBytes(.big)[0..] },
            HexF{ .bytes = pe.y.toBytes(.big)[0..] },
            HexF{ .bytes = scalar[0..] },
            HexF{ .bytes = ce.x.toBytes(.big)[0..] },
            HexF{ .bytes = ce.y.toBytes(.big)[0..] },
        },
    );
    return .{
        .private = private,
        .pwe = pe,
        .commit = .{
            .scalar = scalar,
            .element = ce,
        },
    };
}

pub fn genScalarRand() ![32]u8 {
    while (true) {
        var buf: [32]u8 = P256.scalar.random(.big);
        const s: u256 = mem.readInt(u256, buf[0..], .big);
        if (s > 1 and s < p256_order)
            return buf;
    }
}

/// Hash Password to Element for ECC Group 19 (P-256 NIST)
pub fn hashToElement(password: []const u8, addr1: [6]u8, addr2: [6]u8) !P256 {
    log.debug("Generating Password Element Hash...", .{});
    const prime: [32]u8 = [_]u8{
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    };
    var counter: u8 = 1;
    const max_tries = 40;
    const max_addr, const min_addr =
        if (mem.lessThan(u8, addr1[0..], addr2[0..])) .{ addr2, addr1 } 
        else .{ addr1, addr2 };
    const addrs: [12]u8 = max_addr ++ min_addr;
    log.debug("- max addr (1): {f}, min addr (2): {f}", .{ MACF{ .bytes = max_addr[0..] }, MACF{ .bytes = min_addr[0..] } });
    var found_point: ?P256 = null;
    var found_iter: ?u8 = null;
    var x_coord: [32]u8 = undefined;
    while (counter <= max_tries) : (counter += 1) {
        var pwd_seed: [32]u8 = undefined;
        var h = hmac256.init(addrs[0..]);
        h.update(password);
        h.update(&[_]u8{ counter });
        h.final(pwd_seed[0..]);
        try sha256PRFBits(
            pwd_seed[0..],
            "SAE Hunting and Pecking",
            prime[0..],
            256,
            x_coord[0..],
        );
        const x_valid = mem.lessThan(u8, x_coord[0..], prime[0..]);
        if (x_valid and found_point == null) findPoint: {
            const x_candidate = P256.Fe.fromBytes(x_coord, .big) catch break :findPoint;
            const is_odd = @as(u1, @truncate(pwd_seed[pwd_seed.len - 1])) == 1;
            const y_coord = P256.recoverY(x_candidate, is_odd) catch break :findPoint;
            found_point = P256.fromAffineCoordinates(.{ .x = x_candidate, .y = y_coord }) catch break :findPoint;
            found_iter = counter;
        }
        //log.debug(
        //    \\- Counter {d:0>2}:
        //    \\  - Valid: {any}
        //    \\  - Found: {any}
        //    \\  - Seed:  {f}
        //    \\  - Value: {f}
        //    \\
        //, .{
        //    counter,
        //    x_valid,
        //    found_point != null,
        //    InHexF{ .slice = pwd_seed[0..] },
        //    InHexF{ .slice = x_coord[0..] },
        //});
    }
    if (found_point) |point| {
        log.debug(
            "Generated Password Element Hash on Iteration {?d}.\nX: {f}\nY: {f}", 
            .{ 
                found_iter,
                HexF{ .bytes = point.x.toBytes(.big)[0..] },
                HexF{ .bytes = point.y.toBytes(.big)[0..] },
            },
        );
        return point;
    }
    return SAEError.HashToElementFailed;
}

/// Generate SAE Confirm Message Data.
pub fn genConfirm(ctx: *Context, peer: Commit) !void {
    log.debug("Generating SAE Confirm...", .{});
    log.debug(
        \\Peer Commit:
        \\ - scalar: {f}
        \\ - x:      {f}
        \\ - y:      {f}
        \\
        , .{
            HexF{ .bytes = peer.scalar[0..] },
            HexF{ .bytes = peer.element.x.toBytes(.big)[0..] },
            HexF{ .bytes = peer.element.y.toBytes(.big)[0..] },
        },
    ); 
    // Check for basic Reflection Attack
    if (
        mem.eql(u8, ctx.commit.scalar[0..], peer.scalar[0..]) and
        ctx.commit.element.equivalent(peer.element)
    ) return error.PeerIsReflected;
    // Derive Shared Secret (k = F(K))
    const k: [32]u8 = K: {
        const pwe_mul = try ctx.pwe.mul(peer.scalar, .big);
        const peer_add = pwe_mul.add(peer.element);
        const private_mul = try peer_add.mul(ctx.private, .big);
        try private_mul.rejectIdentity();
        const shared_pt = private_mul.affineCoordinates();
        break :K shared_pt.x.toBytes(.big);
    };
    // Derive Keyseed
    const keyseed: [32]u8 = keyseed: {
        const ks_salt: [32]u8 = @splat(0);
        var ks_h = hmac256.init(ks_salt[0..]);
        ks_h.update(k[0..]);
        var ks_buf: [32]u8 = undefined;
        ks_h.final(ks_buf[0..]);
        break :keyseed ks_buf;
    };
    // Derive KCK & PMK Context / PMKID
    const pk_ctx: [32]u8 = pkCtx: {
        const commit_scalar_int: u512 = mem.readInt(u256, ctx.commit.scalar[0..], .big);
        const peer_scalar_int: u512 = mem.readInt(u256, peer.scalar[0..], .big);
        const context_int: u256 = @truncate((commit_scalar_int + peer_scalar_int) % p256_order);
        break :pkCtx mem.toBytes(mem.nativeTo(u256, context_int, .big));
    };
    const pmkid: [16]u8 = pk_ctx[0..16].*;
    // Derive KCK & PMK
    var kck_pmk: [64]u8 = undefined;
    try sha256PRFBits(
        keyseed[0..],
        "SAE KCK and PMK",
        pk_ctx[0..],
        512,
        kck_pmk[0..],
    );
    ctx.kck = kck_pmk[0..32].*;
    ctx.pmk = kck_pmk[32..64].*;
    // Generate confirm token
    ctx.confirm = makeConfirm(peer, ctx.*);
    log.debug(
        \\Confirm Data:
        \\ - Secret (k): {f}
        \\ - Keyseed:    {f}
        \\ - PMKID:      {f}
        \\ - KCK:        {f}
        \\ - PMK:        {f}
        \\ - Confirm:    {f}
        , .{
            HexF{ .bytes = k[0..] },
            HexF{ .bytes = keyseed[0..] },
            HexF{ .bytes = pmkid[0..] },
            HexF{ .bytes = ctx.kck.?[0..] },
            HexF{ .bytes = ctx.pmk.?[0..] },
            HexF{ .bytes = ctx.confirm.?[0..] },
        }
    );
    log.debug("Generated SAE Confirm.", .{});
}

/// Make the Confirm Token.
fn makeConfirm(peer: Commit, ctx: Context) [32]u8 {
    var confirm: [32]u8 = undefined;
    var h = hmac256.init(ctx.kck.?[0..]);
    h.update(ctx.send_confirm[0..]);
    h.update(ctx.commit.scalar[0..]);
    h.update(ctx.commit.element.x.toBytes(.big)[0..]);
    h.update(ctx.commit.element.y.toBytes(.big)[0..]);
    h.update(peer.scalar[0..]);
    h.update(peer.element.x.toBytes(.big)[0..]);
    h.update(peer.element.y.toBytes(.big)[0..]);
    h.final(confirm[0..]);
    return confirm;
}

/// Check if a Peer's Confirm is Valid.
pub fn checkConfirm(received: [32]u8, peer: Commit, ctx: Context) !void {
    const expected = makeConfirm(peer, ctx);
    if (!std.mem.eql(u8, expected[0..], received[0..])) {
        log.warn(
            \\Confirm Mismatch:
            \\- Expected: {f}
            \\- Received: {f}
            \\
            , .{
                HexF{ .bytes = expected[0..] },
                HexF{ .bytes = received[0..] },
            }
        );
        return error.ConfirmMismatch;
    }
}

test "commit & confirm" {
    std.testing.log_level = .debug;
    log.info("=== SAE Commit & Confirm ===", .{});
    const mac1: [6]u8 = .{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
    const mac2: [6]u8 = .{ 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
    const password: []const u8 = "test passw0rd!";
    var client_ctx: Context = try genCommit(password, mac1, mac2);
    var router_ctx: Context = try genCommit(password, mac2, mac1);
    try genConfirm(&client_ctx, router_ctx.commit);
    try genConfirm(&router_ctx, client_ctx.commit);
    log.info(
        \\Confirm
        \\- Client: {f}
        \\- Router: {f}
        \\
        , .{
            HexF{ .bytes = client_ctx.confirm.?[0..] },
            HexF{ .bytes = router_ctx.confirm.?[0..] },
        },
    );
    try checkConfirm(client_ctx.confirm.?, router_ctx.commit, client_ctx);
    try checkConfirm(router_ctx.confirm.?, client_ctx.commit, router_ctx);
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
    const sha256_mac_len = 32;
    var counter: u16 = 1;
    const output_len = (output_bits + 7) / 8;
    if (out.len < output_len) return error.OutputBufferTooSmall;
    var pos: usize = 0;
    var hash: [sha256_mac_len]u8 = undefined;
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
        if (remaining >= sha256_mac_len) {
            hmac256.create(out[pos..(pos + sha256_mac_len)][0..sha256_mac_len], vec, key);
            pos += sha256_mac_len;
        }
        else {
            hmac256.create(hash[0..sha256_mac_len], vec, key);
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

