//! D-Bus Structs & Functions f/ DisCo

const std = @import("std");
const fmt = std.fmt;
const fs = std.fs;
const log = std.log.scoped(.dbus);
const mem = std.mem;
const net = std.net;
const posix = std.posix;
const os = std.os;
const Io = std.Io;

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
pub const Connection = struct {
    sock: net.Stream,
    reader: net.Stream.Reader,
    writer: net.Stream.Writer,
    uuid: []const u8,

    /// Initialize a Connection to System D-Bus.
    pub fn init(alloc: mem.Allocator) !@This() {
        //log.debug("Creating DBus Socket.", .{});
        // Default system bus address
        const bus_path: []const u8 = "/run/dbus/system_bus_socket";
        // Create Unix domain socket
        const sock = try net.connectUnixSocket(bus_path);
        errdefer sock.close();
        const r_buf = try alloc.alloc(u8, 4096);
        errdefer alloc.free(r_buf);
        const w_buf = try alloc.alloc(u8, 4096);
        var self: @This() = .{
            .sock = sock,
            .reader = sock.reader(r_buf),
            .writer = sock.writer(w_buf),
            .uuid = undefined,
        };
        // Perform SASL authentication
        try self.authenticate();
        self.uuid = try self.hello(alloc);
        return self;
    }

    /// Deinitialize this Connection to System D-Bus.
    pub fn deinit(self: *@This(), alloc: mem.Allocator) void {
        self.sock.close();
        alloc.free(self.uuid);
        alloc.free(self.reader.interface().buffer);
        alloc.free(self.writer.interface.buffer);
    }

    /// Authenticate a D-Bus Connection.
    pub fn authenticate(self: *@This()) !void {
        //log.debug("Authenticating DBus Socket...", .{});
        var sock_w = &self.writer.interface;
        var sock_r = self.reader.interface();
        // Send initial null byte
        try sock_w.writeByte(0);
        try sock_w.flush();
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
        try sock_w.print(
            "AUTH EXTERNAL {s}\r\n",
            .{ uid_hex },
        );
        //log.debug("Auth Message:\n{s}", .{ self.buffered() });
        // Send authentication message
        try sock_w.flush();
        // Read response
        try sock_r.fillMore();
        //log.debug("Reading Auth Response", .{});
        //log.debug("Auth Response:\n{s}", .{ response_buf[0..auth_read] });
        if (!mem.startsWith(u8, sock_r.buffered(), "OK "))
            return error.AuthenticationFailed;
        // Negotiate Unix FD
        //log.debug("Negotiating Unix FD", .{});
        try sock_w.writeAll("NEGOTIATE_UNIX_FD\r\n");
        try sock_w.flush();
        sock_r.tossBuffered();
        sock_r.seek = 0;
        sock_r.end = 0;
        try sock_r.fillMore();
        //log.debug("Negotiation Response:\n{s}", .{ response_buf[0..neg_read] });
        if (!mem.startsWith(u8, sock_r.buffered(), "AGREE"))
            return error.NegotiationFailed;
        // Send BEGIN
        try sock_w.writeAll("BEGIN\r\n");
        try sock_w.flush();
        //log.debug("Wrote DBus: 'BEGIN\\r\\n'", .{});
    }

    /// Send a `hello` message from this Connection to get a Unique Name (UUID).
    pub fn hello(self: *@This(), alloc: mem.Allocator) ![]const u8 {
        var sock_r = self.reader.interface();
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
        // Send Hello
        try self.sendMsg(header_fields[0..], &.{});
        // Verify Response
        sock_r.tossBuffered();
        sock_r.seek = 0;
        sock_r.end = 0;
        try sock_r.fillMore();
        if (sock_r.end == 0) //
            return error.DBusReadError;
        //log.debug("Hello Response:\n{s}\n---\n{f}", .{ response_buf[0..read], HexF{ .bytes = response_buf[0..read] } });
        try verifyResponse(sock_r.buffered());
        // Parse the UUID
        const start = 8 + (mem.indexOf(u8, sock_r.buffered(), &.{ 0x06, 0x01, 0x73, 0x00 }) orelse return error.InvalidStartOfUUID);
        const end = start + (mem.indexOf(u8, sock_r.buffered(), &.{ 0 }) orelse return error.InvalidEndOfUUID);
        return try alloc.dupe(u8, sock_r.buffered()[start..end]);
        //log.debug("Unique Name: ({d}-{d} | {d}B)\n{s}\n---\n{f}", .{ start, end, uuid_len, uuid, HexF{ .bytes = uuid } });
        //log.debug("Unique Name:\n{s}\n", .{ uuid });
    }

    /// Send a D-Bus Message.
    pub fn sendMsg(
        self: *@This(),
        header_fields: []const HeaderField,
        data: []const u8
    ) !void {
        var sock_w = &self.writer.interface;
        sock_w.end = 0;
        // Basic Header
        // - 'l' Little Endian
        // - 1   Method Call
        // - 0   No Flags
        // - 1   Protocol Version
        try sock_w.writeAll(&[_]u8{ 'l', 1, 0, 1 });
        // Body Length
        try sock_w.writeInt(u32, @truncate(data.len), .little);
        // Serial Number
        try sock_w.writeInt(u32, 1, .little);
        const array_size_offset = sock_w.end;
        sock_w.end += 4;
        const array_start = sock_w.end;
        // Write each Header Field
        for (header_fields) |field| {
            // Alignment
            while (sock_w.end % 8 != 0) //
                try sock_w.writeByte(0);
            try sock_w.writeByte(field.code);
            // Variant Signature
            try sock_w.writeByte(@intCast(field.variant_type.len));
            try sock_w.writeAll(field.variant_type);
            try sock_w.writeByte(0);
            // Variant Value
            const value_len: u32 = @intCast(field.value.len);
            // - Signature Field
            if (mem.eql(u8, field.variant_type, "g")) //
                try sock_w.writeByte(@truncate(value_len))
            // - Other Fields
            else //
                try sock_w.writeInt(u32, value_len, .little);
            try sock_w.writeAll(field.value);
            try sock_w.writeByte(0);
        }
        // Write Header Array Length 
        const cur_end = sock_w.end;
        const array_size = sock_w.end - array_start;
        sock_w.end = array_size_offset;
        try sock_w.writeInt(u32, @intCast(array_size), .little);
        sock_w.end = cur_end;
        // Alignment
        while (sock_w.end % 8 != 0) //
            try sock_w.writeByte(0);
        // Add Data
        try sock_w.writeAll(data[0..]);
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
        try sock_w.flush();
    }
};

/// Verify a DBus Response.
pub fn verifyResponse(response: []const u8) !void {
    if (response.len < 16) //
        return error.InvalidResponse;
    const msg_type = response[1];
    // ERROR
    if (msg_type == 3) //
        return error.MessageError;
    // METHOD_RETURN
    if (msg_type != 2) //
        return error.InvalidResponse;
}
