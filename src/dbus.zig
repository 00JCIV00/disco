//! D-Bus Structs & Functions f/ DisCo

const std = @import("std");
const fmt = std.fmt;
const fs = std.fs;
const log = std.log.scoped(.dbus);
const mem = std.mem;
const net = std.net;
const posix = std.posix;
const os = std.os;

const utils = @import("utils.zig");
const HexF = utils.HexFormatter;
const sys = @import("sys.zig");


///// Possible D-Bus Errors
//pub const DBusError = error {
//    ConnectionFailed,
//    AuthenticationFailed,
//    MessageError,
//    ServiceNotAvailable,
//    InvalidResponse,
//    OutOfMemory,
//    InterfaceNotFound,
//};

/// D-Bus Header Field
pub const HeaderField = struct {
    code: u8,
    variant_type: []const u8,
    value: []const u8,
};

/// D-Bus Connection Context
pub const Context = struct {
    sock: net.Stream,
    uuid: []const u8,
};

/// Create a Connection to System D-Bus.
pub fn connectSysBus(uuid_buf: []u8) !Context {
    //log.debug("Creating DBus Socket.", .{});
    // Default system bus address
    const bus_path: []const u8 = "/run/dbus/system_bus_socket";
    // Create Unix domain socket
    const sock = try net.connectUnixSocket(bus_path);
    errdefer sock.close();
    // Perform SASL authentication
    try authenticateDBus(sock);
    const uuid = try helloDBus(sock, uuid_buf);
    return .{ .sock = sock, .uuid = uuid };
}

/// Authenticate a D-Bus Connection.
pub fn authenticateDBus(sock: net.Stream) !void {
    //log.debug("Authenticating DBus Socket...", .{});
    // Send initial null byte
    try sock.writeAll(&[_]u8{ 0 });
    // Get UID string
    var uid_buf: [1024]u8 = @splat(0);
    const uid_str = try fmt.bufPrint(uid_buf[0..], "{d}", .{ try sys.getUID() });
    //log.debug("UID: {s}", .{ uid_str });
    // Convert UID to hex
    var uid_hex_buf: [1024]u8 = undefined;
    for (uid_str, 0..) |b, i| //
        @memcpy(uid_hex_buf[(i * 2)..((i + 1) * 2)], fmt.hex(b)[0..]);
    const uid_hex = uid_hex_buf[0..(uid_str.len * 2)];
    //const uid_hex = try fmt.bufPrint(uid_hex_buf[0..], "{s}", .{ fmt.fmtSliceHexLower(uid_str) });
    // Create authentication message
    var auth_buf: [1024]u8 = undefined;
    const auth_msg = try fmt.bufPrint(
        auth_buf[0..],
        "AUTH EXTERNAL {s}\r\n",
        .{ uid_hex },
    );
    //log.debug("Auth Message:\n{s}", .{ auth_msg });
    // Send authentication message
    try sock.writeAll(auth_msg);
    // Read response
    //log.debug("Reading Auth Response", .{});
    var response_buf: [4096]u8 = undefined;
    const auth_read = try sock.read(response_buf[0..]);
    //log.debug("Auth Response:\n{s}", .{ response_buf[0..auth_read] });
    if (!mem.startsWith(u8, response_buf[0..auth_read], "OK "))
        return error.AuthenticationFailed;
    // Negotiate Unix FD
    //log.debug("Negotiating Unix FD", .{});
    try sock.writeAll("NEGOTIATE_UNIX_FD\r\n");
    const neg_read = try sock.read(response_buf[0..]);
    //log.debug("Negotiation Response:\n{s}", .{ response_buf[0..neg_read] });
    if (!mem.startsWith(u8, response_buf[0..neg_read], "AGREE"))
        return error.NegotiationFailed;
    // Send BEGIN
    try sock.writeAll("BEGIN\r\n");
    //log.debug("Wrote DBus: 'BEGIN\\r\\n'", .{});
}

/// Send a `hello` message to get a Unique Name (UUID).
pub fn helloDBus(sock: net.Stream, uuid_buf: []u8) ![]const u8 {
    //log.debug("Getting Unique Name f/ DBus Socket...", .{});
    // Set up Headers
    const header_fields = [_]HeaderField{
        .{
            .code = 1,
            .variant_type = "o",
            .value = "/org/freedesktop/DBus",
        },
        .{
            .code = 6,
            .variant_type = "s",
            .value = "org.freedesktop.DBus",
        },
        .{
            .code = 2,
            .variant_type = "s",
            .value = "org.freedesktop.DBus",
        },
        .{
            .code = 3,
            .variant_type = "s",
            .value = "Hello",
        },
    };
    // Set up Buffer
    var msg_buf: [4096]u8 = undefined;
    // Send Hello
    try sendMsg(
        msg_buf[0..],
        sock,
        header_fields[0..],
        &.{},
    );
    // Verify Response
    var response_buf: [4096]u8 = undefined;
    const read = try sock.read(response_buf[0..]);
    if (read == 0) return error.DBusReadError;
    //log.debug("Hello Response:\n{s}\n---\n{f}", .{ response_buf[0..read], HexF{ .bytes = response_buf[0..read] } });
    try verifyResponse(response_buf[0..read]);
    // Parse the UUID
    const start = 8 + (mem.indexOf(u8, response_buf[0..read], &.{ 0x06, 0x01, 0x73, 0x00 }) orelse return error.InvalidStartOfUUID);
    const end = start + (mem.indexOf(u8, response_buf[start..read], &.{ 0 }) orelse return error.InvalidEndOfUUID);
    const uuid_len = end - start;
    @memcpy(uuid_buf[0..uuid_len], response_buf[start..end]);
    const uuid = uuid_buf[0..uuid_len];
    //log.debug("Unique Name: ({d}-{d} | {d}B)\n{s}\n---\n{f}", .{ start, end, uuid_len, uuid, HexF{ .bytes = uuid } });
    //log.debug("Unique Name:\n{s}\n", .{ uuid });
    return uuid;
}

/// Send a D-Bus Message.
pub fn sendMsg(
    msg_buf: []u8,
    sock: net.Stream,
    header_fields: []const HeaderField,
    data: []const u8
) !void {
    var offset: usize = 4;
    // Basic Header
    // - 'l' Little Endian
    // - 1   Method Call
    // - 0   No Flags
    // - 1   Protocol Version
    @memcpy(msg_buf[0..offset], &[_]u8{ 'l', 1, 0, 1 });
    // Body Length
    const body_len_offset = offset;
    offset += 4;
    // Serial Number
    mem.writeInt(
        u32,
        msg_buf[offset..][0..4],
        1,
        .little,
    );
    offset += 4;
    const array_size_offset = offset;
    offset += 4;
    const array_start = offset;
    // Write each Header Field
    for (header_fields) |field| {
        while (offset % 8 != 0) {
            msg_buf[offset] = 0;
            offset += 1;
        }
        msg_buf[offset] = field.code;
        offset += 1;
        // Variant Signature
        msg_buf[offset] = @intCast(field.variant_type.len);
        offset += 1;
        @memcpy(msg_buf[offset..][0..field.variant_type.len], field.variant_type);
        offset += field.variant_type.len;
        msg_buf[offset] = 0;
        offset += 1;
        // Variant Value
        const value_len: u32 = @intCast(field.value.len);
        // - Signature Field
        if (mem.eql(u8, field.variant_type, "g")) {
            mem.writeInt(
                u8,
                msg_buf[offset..][0..1],
                @truncate(value_len),
                .little,
            );
            offset += 1;
        }
        // - Other Fields
        else {
            mem.writeInt(
                u32,
                msg_buf[offset..][0..4],
                value_len,
                .little,
            );
            offset += 4;
        }
        @memcpy(msg_buf[offset..][0..value_len], field.value);
        offset += value_len;
        msg_buf[offset] = 0;
        offset += 1;
    }
    // Write Header Array Length 
    const array_size = offset - array_start;
    mem.writeInt(
        u32,
        msg_buf[array_size_offset..][0..4],
        @intCast(array_size),
        .little,
    );
    // Alignment
    while (offset % 8 != 0) {
        msg_buf[offset] = 0;
        offset += 1;
    }
    // Add Data
    @memcpy(msg_buf[offset..(offset + data.len)], data[0..]);
    offset += data.len;
    // Write Body Length
    mem.writeInt(
        u32,
        msg_buf[body_len_offset..][0..4],
        @intCast(data.len),
        .little,
    );
    // Send Message
    //log.debug(
    //    \\Sending Message: (Total: {d}B | Headers: {d}B | Body: {d}B)
    //    \\{s}
    //    \\---
    //    \\{f}
    //    \\
    //    , .{ 
    //        offset,
    //        array_size,
    //        data.len,
    //        msg_buf[0..offset],
    //        HexF{ .bytes = msg_buf[0..offset] } 
    //    },
    //);
    try sock.writeAll(msg_buf[0..offset]);
}

/// Verify a DBus Response.
pub fn verifyResponse(response: []const u8) !void {
    if (response.len < 16) return error.InvalidResponse;
    const msg_type = response[1];
    // ERROR
    if (msg_type == 3)
        return error.MessageError;
    // METHOD_RETURN
    if (msg_type != 2)
        return error.InvalidResponse;
}
