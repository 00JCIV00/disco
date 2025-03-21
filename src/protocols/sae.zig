//! Simultaneous Authentication of Equals (SAE) and Elliptic Curve Diffie Helman (ECDH) functions for DisCo.

const std = @import("std");
const crypto = std.crypto;
const Ed25519 = crypto.ecc.Edwards25519;
const hmac256 = crypto.auth.hmac.sha2.HmacSha256;
const pbkdf2 = crypto.pwhash.pbkdf2;
const math = std.math;
const mem = std.mem;
const log = std.log.scoped(.sae);

const netdata = @import("../netdata.zig");
const address = netdata.address;
const MACF = address.MACFormatter;

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
    password_element: Ed25519,
    commit: Commit,
};

/// Result of SAE Commit Generation.
pub const Commit = struct {
    scalar: [32]u8,
    element: Ed25519,
};

/// Generate SAE Commit Message Data within overall SAE Context.
pub fn genCommit(password: []const u8, addr1: [6]u8, addr2: [6]u8) !Context {
    log.debug("Generating SAE Commit...", .{});
    // Generate random mask and private values
    var mask: [32]u8 = undefined;
    var private: [32]u8 = undefined;
    crypto.random.bytes(mask[0..]);
    crypto.random.bytes(private[0..]);
    // Calculate password element through hunting-and-pecking
    const pe = try hashToElement(password, addr1, addr2);
    // Calculate commit-scalar = (private + mask) mod r
    var scalar: [32]u8 = undefined;
    const kp1 = Ed25519.scalar.mul(Ed25519.basePoint.toBytes(), private);
    const kp2 = Ed25519.scalar.mul(Ed25519.basePoint.toBytes(), mask);
    for (scalar[0..], 0..) |*s, i| 
        s.* = kp1[i] +% kp2[i];
    // Calculate commit-element = inverse(scalar-op(mask, PE))
    const element = try Ed25519.fromBytes(Ed25519.scalar.mul(pe.toBytes(), mask));
    log.debug("Generated SAE Commit.", .{});
    return .{
        .private = private,
        .password_element = pe,
        .commit = .{
            .scalar = scalar,
            .element = element,
        },
    };
}

/// Generate SAE Confirm Message Data.
pub fn genConfirm(ctx: Context, peer: Commit) ![32]u8 {
    log.debug("Generating SAE Confirm...", .{});
    // Calculate k
    const k = try deriveK(ctx, peer);
    // Generate confirm token
    var confirm: [32]u8 = undefined;
    var h = crypto.hash.sha2.Sha256.init(.{});
    h.update(k[0..]);
    h.update(ctx.commit.scalar[0..]);
    h.update(peer.scalar[0..]);
    h.update(ctx.commit.element.toBytes()[0..]);
    h.update(peer.element.toBytes()[0..]);
    h.final(confirm[0..]);
    log.debug("Generated SAE Confirm.", .{});
    return confirm;
}

///// Hash Password to Element (Hunting-and-Pecking Technique; 256-bit Hashing f/ ECC Group 19)
//pub fn hashToElement(password: []const u8, addr1: [6]u8, addr2: [6]u8) !Ed25519 {
//    log.debug("Generating Password Element Hash...", .{});
//    var counter: u8 = 1;
//    const max_tries = 40;
//    var found: bool = false;
//    const max_addr, const min_addr =
//        if (mem.lessThan(u8, addr1[0..], addr2[0..])) .{ addr2, addr1 }
//        else .{ addr1, addr2 };
//    log.debug("- max addr (1): {s}, min addr (2): {s}", .{ MACF{ .bytes = max_addr[0..] }, MACF{ .bytes = min_addr[0..] } });
//    while (counter <= max_tries or !found) : (counter += 1) {
//        // Generate pwd-seed = H(max(addrs) || min(addrs) || password || counter)
//        var pwd_seed: [32]u8 = undefined;
//        var h = crypto.hash.sha2.Sha256.init(.{});
//        h.update(max_addr[0..]);
//        h.update(min_addr[0..]);
//        h.update(password);
//        h.update(&[_]u8{ counter });
//        h.final(pwd_seed[0..]);
//        // Generate pwd-value = KDF-z(pwd-seed, "SAE Hunting and Pecking", p)
//        var pwd_value: [32]u8 = undefined;
//        h = crypto.hash.sha2.Sha256.init(.{});
//        h.update("SAE Hunting and Pecking");
//        h.update(pwd_seed[0..]);
//        h.final(pwd_value[0..]);
//        // Check if pwd-value < p (prime)
//        const prime = [_]u8{ 0x7f } ++ [_]u8{ 0xff } ** 30 ++ [_]u8{ 0xed };
//        const in_range = mem.lessThan(u8, pwd_value[0..], prime[0..]);
//        const point = if (in_range) Ed25519.fromBytes(pwd_value) catch null else null;
//        found = point != null;
//        log.debug(
//            \\- Counter {d}:
//            \\  - Found = {}
//            \\  - Result = {X:0<2}
//            \\  - Seed = {X:0<2}
//            \\
//            , .{ 
//                counter,
//                found,
//                pwd_value[0..],
//                pwd_seed[0..],
//            }
//        );
//        if (found and counter >= 40) {
//            log.debug("Generated Password Element Hash in {d} Iterations.", .{ counter });
//            return point.?;
//        }
//    }
//    return SAEError.HashToElementFailed;
//}

/// Edwards25519 curve constant: d = -(121665/121666) mod p
const CURVE_D = [32]u8{
    0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75,
    0xab, 0xd8, 0x41, 0x41, 0x4d, 0x0a, 0x70, 0x00,
    0x98, 0xe8, 0x79, 0x77, 0x79, 0x40, 0xc7, 0x8c,
    0x73, 0xfe, 0x6f, 0x2b, 0xee, 0x6c, 0x03, 0x52,
};

/// Calculate Y coordinate from X using curve equation: -x^2 + y^2 = 1 + dx^2y^2
fn solveForY(x: [32]u8) ?[32]u8 {
    // 1. Calculate x^2
    const x_fe = Ed25519.Fe.fromBytes(x);
    const x2 = x_fe.sq();
    // 2. Calculate u = 1 + dx^2
    const d_fe = Ed25519.Fe.fromBytes(CURVE_D);
    const dx2 = d_fe.mul(x2);
    const u = Ed25519.Fe.one.add(dx2);
    // 3. Calculate v = 1 - x^2
    const v = Ed25519.Fe.one.sub(x2);
    // 4. Calculate y = sqrt(u/v) if it exists
    // y^2 = u/v, so y = sqrt(u * v^-1)
    const v_inv = v.invert();
    const uv = u.mul(v_inv);
    // Check if uv is a square
    if (!uv.isSquare()) return null;
    // Get square root
    const y_fe = uv.sqrt() catch return null;
    const y = y_fe.toBytes();
    return y;
}

/// Create point from X,Y coordinates in compressed Ed25519 format
fn pointFromCoordinates(x: [32]u8, y: [32]u8) !Ed25519 {
    var point_bytes = y;  // Start with Y coordinate
    // Set the sign bit (highest bit of last byte) based on sign of X
    const x_negative = (x[31] & 0x80) != 0;
    point_bytes[31] &= 0x7f;  // Clear top bit
    point_bytes[31] |= @as(u8, @intFromBool(x_negative)) << 7;  // Set based on X sign
    return Ed25519.fromBytes(point_bytes) catch return error.InvalidPoint;
}

/// Hash Password to Element for ECC Group 19 (Curve25519)
pub fn hashToElement(password: []const u8, addr1: [6]u8, addr2: [6]u8) !Ed25519 {
    log.debug("Generating Password Element Hash...", .{});
    var counter: u8 = 1;
    const max_tries = 40;
    const max_addr, const min_addr =
        if (mem.lessThan(u8, addr1[0..], addr2[0..])) .{ addr2, addr1 }
        else .{ addr1, addr2 };
    const addrs: [12]u8 = max_addr ++ min_addr;
    log.debug("- max addr (1): {s}, min addr (2): {s}", .{ MACF{ .bytes = max_addr[0..] }, MACF{ .bytes = min_addr[0..] } });
    var found_point: ?Ed25519 = null;
    var found_iter: ?u8 = null;
    var x_coord: [32]u8 = undefined;
    while (counter <= max_tries) : (counter += 1) {
        var pwd_seed: [32]u8 = undefined;
        var h = hmac256.init(addrs[0..]);
        h.update(password);
        h.update(&[_]u8{ counter });
        h.final(pwd_seed[0..]);
        var pwd_value: [32]u8 = undefined;
        try pbkdf2(
            pwd_value[0..],
            pwd_seed[0..],
            "SAE Hunting and Pecking",
            96,
            hmac256,
        );
        x_coord = pwd_value;
        const prime = [_]u8{0x7f} ++ [_]u8{0xff} ** 30 ++ [_]u8{0xed};
        const x_valid = mem.lessThan(u8, x_coord[0..], prime[0..]);
        const y_coord = if (x_valid) solveForY(x_coord) else null;
        log.debug(
            \\- Counter {d:0>2}:
            \\  - Found: {}
            \\  - Seed:  {X:0>2}
            \\  - Value: {X:0>2}
            \\
            , .{
                counter,
                y_coord != null,
                pwd_seed[0..],
                x_coord[0..],
            }
        );
        if (y_coord != null and found_point == null) {
            found_point = pointFromCoordinates(x_coord, y_coord.?) catch continue;
            found_iter = counter;
        }
    }
    if (found_point) |point| {
        log.debug("Generated Password Element Hash on Iteration {?d}.", .{ found_iter });
        return point;
    }
    return SAEError.HashToElementFailed;
}

/// Derive Shared Key `k`.
fn deriveK(ctx: Context, peer: Commit) ![32]u8 {
    log.debug("Deriving K...", .{});
    // Calculate: k = F(scalar-op(private, element-op(peer-element, scalar-op(peer-scalar, PE))))
    const t1 = Ed25519.scalar.mul(ctx.password_element.toBytes(), peer.scalar);
    const t2 = Ed25519.scalar.mul(peer.element.toBytes(), t1);
    const k = Ed25519.scalar.mul(t2, ctx.private);
    log.debug("Derived K.", .{});
    return k;
}
