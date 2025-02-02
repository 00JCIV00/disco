//! DNS Functions f/ DisCo.

const std = @import("std");
const fmt = std.fmt;
const fs = std.fs;
const log = std.log.scoped(.dns);
const mem = std.mem;
const net = std.net;
const posix = std.posix;
const os = std.os;

const dbus = @import("../dbus.zig");
const netdata = @import("../netdata.zig");
const address = netdata.address;
const IPF = address.IPFormatter;
const utils = @import("../utils.zig");
const HexF = utils.HexFormatter;
const sys = @import("../sys.zig");

/// Configuration for DNS settings
pub const DNSConfig = struct {
    /// Interface index to update. If null, applies to all interfaces.
    if_index: ?i32 = null,
    /// List of DNS servers. If empty, clears all DNS servers for the interface.
    servers: []const [4]u8,
    /// Set or Unset the Interface as the Default Route for DNS Queries.
    set_route: bool = true,
};

/// Updates DNS Settings using DBus w/ `resolv.conf` as a failover.
pub fn updateDNS(config: DNSConfig) !void {
    log.debug("Updating DNS via DBus...", .{});
    updateDNSDBus(config) catch |err| {
        log.debug("DBus Failed ({s}). Updating DNS via `resolv.conf`...", .{ @errorName(err) });
        //try updateDNSResConf(config);
        return err;
    };
    try setDefaultRouteDNS(config.if_index orelse return, config.set_route);
}

/// Updates DNS Settings using `resolv.conf`.
pub fn updateDNSResConf(config: DNSConfig) !void {
    const cwd = fs.cwd();
    var res_conf_file = try cwd.openFile("/etc/resolv.conf", .{ .mode = .read_write });
    var res_conf_buf: [16_000]u8 = .{ 0 } ** 16_000;
    const start = try res_conf_file.readAll(res_conf_buf[0..]);
    _ = start;
    const res_conf_writer = res_conf_file.writer();
    try res_conf_writer.print("\n# DisCo Adds:", .{});
    for (config.servers) |server| {
        log.debug("- Adding DNS: {s}", .{ IPF{ .bytes = server[0..] } });
        try res_conf_writer.print(
            "\nnameserver '{s}'",
            IPF{ .bytes = server[0..] },
        );
    }
    try res_conf_writer.print("\n# End DisCo Adds\n", .{});
}

/// Updates DNS settings using systemd-resolved via DBus.
pub fn updateDNSDBus(config: DNSConfig) !void {
    //log.debug("Using `systemd-resolved`", .{});
    // Connect to system DBus
    var uuid_buf: [286]u8 = .{ 0 } ** 286;
    const dbus_ctx = try dbus.connectSysBus(uuid_buf[0..]);
    // Array of header fields
    const header_fields = [_]dbus.HeaderField{
        // PATH
        .{
            .code = 1,
            .variant_type = "o",
            .value = "/org/freedesktop/resolve1",
        },
        // INTERFACE
        .{
            .code = 2,
            .variant_type = "s",
            .value = "org.freedesktop.resolve1.Manager",
        },
        // MEMBER
        .{
            .code = 3,
            .variant_type = "s",
            .value = "SetLinkDNS",
        },
        // DESTINATION
        .{
            .code = 6,
            .variant_type = "s",
            .value = ":1.0",
        },
        // SENDER
        .{
            .code = 7,
            .variant_type = "s",
            .value = dbus_ctx.uuid,
        },
        // SIGNATURE
        .{
            .code = 8,
            .variant_type = "g",
            .value = "ia(iay)",
        },
    };
    defer dbus_ctx.sock.close();
    // Construct the DBus message to update DNS settings
    //log.debug("Building DBus DNS Message.", .{});
    var data_buf: [2048]u8 = .{ 0 } ** 2048;
    const dns_msg = try buildSetDNSData(data_buf[0..], config);
    //log.debug("DBus DNS Message:\n{s}\n---\n{s}", .{ dns_msg, HexF{ .bytes = dns_msg } });
    // Send the message
    //log.debug("Sending DBus DNS Message.", .{});
    var msg_buf: [4096]u8 = .{ 0 } ** 4096;
    //try sock.writeAll(dns_msg);
    try dbus.sendMsg(
        msg_buf[0..],
        dbus_ctx.sock,
        header_fields[0..],
        dns_msg,
    );
    // Read and Verify response
    var response_buf: [4096]u8 = .{ 0 } ** 4096;
    //log.debug("Reading DBus DNS Response.", .{});
    //const read = try posix.read(sock, response_buf[0..]);
    const read = try dbus_ctx.sock.read(response_buf[0..]);
    if (read == 0) return error.MessageError;
    //log.debug("Verifying DBus DNS Response.", .{});
    try dbus.verifyResponse(response_buf[0..read]);
}

/// Build a Set DNS Message.
fn buildSetDNSData(buf: []u8, config: DNSConfig) ![]const u8 {
    // Offset
    var offset: usize = 0;
    // Body: Method arguments
    // Interface index
    const if_index = config.if_index orelse 0;
    mem.writeInt(i32, buf[offset..][0..4], if_index, .little);
    offset += 4;
    // Array of DNS servers
    // Reserve space for array length
    const dns_array_size_offset = offset;
    offset += 4;
    // Align to 8-byte boundary for array of structs
    while (offset % 8 != 0) {
        buf[offset] = 0;
        offset += 1;
    }
    const dns_array_start = offset;
    // Write each DNS server
    for (config.servers) |server| {
        // Write family (AF_INET = 2)
        mem.writeInt(i32, buf[offset..][0..4], 2, .little);
        offset += 4;
        // Length of IPv4 address
        mem.writeInt(u32, buf[offset..][0..4], 4, .little); 
        // Write address as byte array
        offset += 4;
        @memcpy(buf[offset..][0..4], server[0..]);
        offset += 4;
    }
    // Write DNS array size
    const dns_array_size = offset - dns_array_start;
    mem.writeInt(u32, buf[dns_array_size_offset..][0..4], @intCast(dns_array_size), .little);
    return buf[0..offset];
}

/// Set or Unset the provided Interface (`if_index`) as the Default Route for DNS Queries.
pub fn setDefaultRouteDNS(if_index: i32, set: bool) !void {
    // Connect to system DBus
    var uuid_buf: [286]u8 = .{ 0 } ** 286;
    const dbus_ctx = try dbus.connectSysBus(uuid_buf[0..]);
    // Array of header fields
    const header_fields = [_]dbus.HeaderField{
        // PATH
        .{
            .code = 1,
            .variant_type = "o",
            .value = "/org/freedesktop/resolve1",
        },
        // INTERFACE
        .{
            .code = 2,
            .variant_type = "s",
            .value = "org.freedesktop.resolve1.Manager",
        },
        // MEMBER
        .{
            .code = 3,
            .variant_type = "s",
            .value = "SetLinkDefaultRoute",
        },
        // DESTINATION
        .{
            .code = 6,
            .variant_type = "s",
            .value = ":1.0",
        },
        // SENDER
        .{
            .code = 7,
            .variant_type = "s",
            .value = dbus_ctx.uuid,
        },
        // SIGNATURE
        .{
            .code = 8,
            .variant_type = "g",
            .value = "ib",
        },
    };
    defer dbus_ctx.sock.close();
    // Construct the DBus message to update DNS settings
    //log.debug("Building DBus DNS Message.", .{});
    var dns_msg: [8]u8 = .{ 0 } ** 8;
    mem.writeInt(
        i32,
        dns_msg[0..4],
        if_index,
        .little
    );
    mem.writeInt(
        i32,
        dns_msg[4..8],
        if (set) 1 else 0,
        .little
    );
    //log.debug("DBus DNS Message:\n{s}\n---\n{s}", .{ dns_msg, HexF{ .bytes = dns_msg } });
    // Send the message
    //log.debug("Sending DBus DNS Message.", .{});
    var msg_buf: [4096]u8 = .{ 0 } ** 4096;
    //try sock.writeAll(dns_msg);
    try dbus.sendMsg(
        msg_buf[0..],
        dbus_ctx.sock,
        header_fields[0..],
        dns_msg[0..],
    );
    // Read and Verify response
    var response_buf: [4096]u8 = .{ 0 } ** 4096;
    //log.debug("Reading DBus DNS Response.", .{});
    //const read = try posix.read(sock, response_buf[0..]);
    const read = try dbus_ctx.sock.read(response_buf[0..]);
    if (read == 0) return error.MessageError;
    //log.debug("Verifying DBus DNS Response.", .{});
    try dbus.verifyResponse(response_buf[0..read]);
}
