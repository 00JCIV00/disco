//! DNS Functions f/ DisCo.

const std = @import("std");
const fmt = std.fmt;
const fs = std.fs;
const log = std.log.scoped(.dns);
const mem = std.mem;
const net = std.net;
const posix = std.posix;
const os = std.os;
const time = std.time;
const Io = std.Io;

const dbus = @import("../dbus.zig");
const netdata = @import("../netdata.zig");
const address = netdata.address;
const IPF = address.IPFormatter;
const utils = @import("../utils.zig");
const HexF = utils.HexFormatter;
const sys = @import("../sys.zig");
const SockReader = utils.SocketReader;

/// DNS Protocol Setting
pub const ProtoSetting = enum {
    yes,
    no,
    inherit,
    resolve,

    pub fn format(self: @This(), writer: *Io.Writer) Io.Writer.Error!void {
        switch (self) {
            .inherit => return,
            else => try writer.print("{t}", .{ self }),
        }
    }
};

/// Configuration for DNS settings
pub const Config = struct {
    /// Interface index to update. If null, applies to all interfaces.
    if_index: ?i32 = null,
    /// List of DNS servers. If empty, clears all DNS servers for the interface.
    servers: []const [4]u8 = &.{},
    /// Set or Unset the Interface as the Default Route for DNS Queries.
    set_route: bool = true,
    /// Allow Multicast DNS (mDNS). Note, if the Global Policy in `/etc/systemd/resolved.conf` is set to `no`, this can't override it.
    allow_mdns: ProtoSetting = .no,
    /// Allow Link-Local Multicast Name Resolution (LLMNR). Note, if the Global Policy in `/etc/systemd/resolved.conf` is set to `no`, this can't override it.
    allow_llmnr: ProtoSetting = .no,
};

/// Current State of DNS Setting
pub const State = enum {
    update_dns,
    verify_dns,
    update_route,
    verify_route,
    update_mdns,
    verify_mdns,
    update_llmnr,
    verify_llmnr,
    done,
};

/// Handler for DNS Settings
pub const Handler = struct {
    state: State = .update_dns,
    dbus_conn: *dbus.Connection,
    reader: SockReader,
    config: Config,
    timer: time.Timer,
    timeout: u64,

    /// Initialize a new DNS Handler for DNS Servers, mDNS, and LLMNR.
    pub fn init(
        alloc: mem.Allocator,
        dbus_conn: *dbus.Connection,
        timeout: u64,
        config: Config,
    ) !@This() {
        const r_buf = try alloc.alloc(u8, 4096);
        const reader: SockReader = .init(dbus_conn.sock.handle, r_buf, posix.MSG.DONTWAIT);
        return .{
            .dbus_conn = dbus_conn,
            .reader = reader,
            .config = config,
            .timer = try .start(),
            .timeout = timeout,
        };
    }

    /// Deinitialize this DNS Handler.
    pub fn deinit(self: *@This(), alloc: mem.Allocator) void {
        alloc.free(self.reader.io_reader.buffer[0..]);
    }

    /// Step through setting DNS Servers, mDNS, and LLMNR.
    pub fn step(self: *@This()) !void {
        if (self.timer.read() >= self.timeout * time.ns_per_ms) //
            return error.Timeout;
        state: switch (self.state) {
            .update_dns => {
                try self.updateServers();
                self.state = .verify_dns;
                continue :state self.state;
            },
            .verify_dns => {
                try self.verifyResponse();
                self.state = .update_route;
            },
            .update_route => {
                if (self.config.if_index == null) {
                    self.state = .verify_route;
                    continue :state self.state;
                }
                try self.updateRoute(self.config.set_route);
                self.state = .verify_route;
                continue :state self.state;
            },
            .verify_route => {
                try self.verifyResponse();
                self.state = .update_mdns;
            },
            .update_mdns => {
                try self.updateMDNS(self.config.allow_mdns);
                self.state = .verify_mdns;
                continue :state self.state;
            },
            .verify_mdns => {
                try self.verifyResponse();
                self.state = .update_llmnr;
            },
            .update_llmnr => {
                try self.updateLLMNR(self.config.allow_llmnr);
                self.state = .verify_llmnr;
                continue :state self.state;
            },
            .verify_llmnr => {
                try self.verifyResponse();
                self.state = .done;
            },
            .done => {},
        }
    }

    /// Update the DNS Servers of the Interfaces provided in `self.config`.
    fn updateServers(self: *@This()) !void {
        log.debug("Setting DNS Servers", .{});
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
                .value = "org.freedesktop.resolve1",
            },
            // SENDER
            .{
                .code = 7,
                .variant_type = "s",
                .value = self.dbus_conn.uuid,
            },
            // SIGNATURE
            .{
                .code = 8,
                .variant_type = "g",
                .value = "ia(iay)",
            },
        };
        // Construct the DBus message to update DNS settings
        //log.debug("Building DBus DNS Message.", .{});
        var msg_buf: [2048]u8 = undefined;
        var sock_w: Io.Writer = .fixed(msg_buf[0..]);
        // Body: Method arguments
        // Interface index
        const if_index = self.config.if_index orelse 0;
        try sock_w.writeInt(i32, if_index, .little);
        // Array of DNS servers
        // Reserve space for array length
        const dns_array_size_offset = sock_w.end;
        sock_w.end += 4;
        // Align to 8-byte boundary for array of structs
        try utils.writePad(&sock_w, .{ .alignment = 8 });
        const dns_array_start = sock_w.end;
        // Write each DNS server
        for (self.config.servers) |server| {
            // Write family (AF_INET = 2)
            try sock_w.writeInt(i32, 2, .little);
            // Length of IPv4 address
            try sock_w.writeInt(u32, 4, .little);
            // Write address as byte array
            try sock_w.writeAll(server[0..]);
        }
        // Write DNS array size
        const dns_array_size = sock_w.end - dns_array_start;
        const cur_end = sock_w.end;
        sock_w.end = dns_array_size_offset;
        try sock_w.writeInt(u32, @intCast(dns_array_size), .little);
        sock_w.end = cur_end;
        //log.debug("DBus DNS Message:\n{s}\n---\n{s}", .{ dns_msg, HexF{ .bytes = dns_msg } });
        // Send the message
        //log.debug("Sending DBus DNS Message.", .{});
        try self.dbus_conn.sendMsg(header_fields[0..], sock_w.buffered());
    }

    /// Set or Unset the provided Interface (`if_index`) as the Default Route for DNS Queries.
    fn updateRoute(self: *@This(), set: bool) !void {
        log.debug("Setting DNS Route", .{});
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
                .value = "org.freedesktop.resolve1",
            },
            // SENDER
            .{
                .code = 7,
                .variant_type = "s",
                .value = self.dbus_conn.uuid,
            },
            // SIGNATURE
            .{
                .code = 8,
                .variant_type = "g",
                .value = "ib",
            },
        };
        // Construct the DBus Route message to update DNS settings
        //log.debug("Building DBus DNS Route Message.", .{});
        var msg_buf: [2048]u8 = undefined;
        var sock_w: Io.Writer = .fixed(msg_buf[0..]);
        try sock_w.writeInt(i32, self.config.if_index.?, .little);
        try sock_w.writeInt(
            i32,
            if (set) 1 else 0,
            .little,
        );
        //log.debug("DBus DNS Route Message:\n{s}\n---\n{s}", .{ dns_msg, HexF{ .bytes = dns_msg } });
        // Send the message
        //log.debug("Sending DBus DNS Message.", .{});
        try self.dbus_conn.sendMsg(header_fields[0..], sock_w.buffered());
    }

    /// Enable/Disable mDNS
    fn updateMDNS(self: *@This(), setting: ProtoSetting) !void {
        log.debug("Setting mDNS", .{});
        const header_fields = [_]dbus.HeaderField{
            .{ .code = 1, .variant_type = "o", .value = "/org/freedesktop/resolve1" },
            .{ .code = 2, .variant_type = "s", .value = "org.freedesktop.resolve1.Manager" },
            .{ .code = 3, .variant_type = "s", .value = "SetLinkMulticastDNS" },
            .{ .code = 6, .variant_type = "s", .value = "org.freedesktop.resolve1" },
            .{ .code = 7, .variant_type = "s", .value = self.dbus_conn.uuid },
            .{ .code = 8, .variant_type = "g", .value = "is" },
        };
        var msg_buf: [256]u8 = undefined;
        var sock_w: Io.Writer = .fixed(msg_buf[0..]);
        const if_index = self.config.if_index orelse 0;
        try sock_w.writeInt(i32, if_index, .little);
        const setting_len: i32 = if (setting == .inherit) 0 else @intCast(@tagName(setting).len);
        try sock_w.writeInt(i32, setting_len, .little);
        try sock_w.print("{f}\u{0}", .{ setting });
        try self.dbus_conn.sendMsg(header_fields[0..], sock_w.buffered());
    }

    /// Enable/Disable LLMNR
    fn updateLLMNR(self: *@This(), setting: ProtoSetting) !void {
        log.debug("Setting LLMNR", .{});
        const header_fields = [_]dbus.HeaderField{
            .{ .code = 1, .variant_type = "o", .value = "/org/freedesktop/resolve1" },
            .{ .code = 2, .variant_type = "s", .value = "org.freedesktop.resolve1.Manager" },
            .{ .code = 3, .variant_type = "s", .value = "SetLinkLLMNR" },
            .{ .code = 6, .variant_type = "s", .value = "org.freedesktop.resolve1" },
            .{ .code = 7, .variant_type = "s", .value = self.dbus_conn.uuid },
            .{ .code = 8, .variant_type = "g", .value = "is" },
        };
        var msg_buf: [256]u8 = undefined;
        var sock_w: Io.Writer = .fixed(msg_buf[0..]);
        const if_index = self.config.if_index orelse 0;
        try sock_w.writeInt(i32, if_index, .little);
        const setting_len: i32 = if (setting == .inherit) 0 else @intCast(@tagName(setting).len);
        try sock_w.writeInt(i32, setting_len, .little);
        try sock_w.print("{f}\u{0}", .{ setting });
        try self.dbus_conn.sendMsg(header_fields[0..], sock_w.buffered());
    }

    /// Verify that D-Bus accepted the provided DNS Request.
    fn verifyResponse(self: *@This()) !void {
        // Read and Verify response
        var sock_r = &self.reader.io_reader;
        //log.debug("Reading DBus DNS Response.", .{});
        sock_r.tossBuffered();
        sock_r.end = 0;
        sock_r.seek = 0;
        try sock_r.fillMore();
        if (sock_r.end == 0) //
            //return error.EmptyResponse;
            return error.ReadFailed;
        //log.debug("Verifying DBus DNS Response.", .{});
        try dbus.verifyResponse(sock_r.buffered());
    }
};

/// Updates DNS Settings using D-Bus.
pub fn updateDNS(config: Config) !void {
    var buf: [16_000]u8 = undefined;
    var fba: std.heap.FixedBufferAllocator = .init(buf[0..]);
    var dbus_conn: dbus.Connection = try .init(fba.allocator());
    //log.debug("Updating DNS via DBus...", .{});
    updateDNSDBus(&dbus_conn, config) catch |err| {
        //log.debug("DBus Failed ({s}). Updating DNS via `resolv.conf`...", .{ @errorName(err) });
        //try updateDNSResConf(config);
        return err;
    };
    //try setDefaultRouteDNS(config.if_index orelse return, config.set_route);
}

/// Updates DNS Settings using `resolv.conf`.
pub fn updateDNSResConf(config: Config) !void {
    const cwd = fs.cwd();
    var res_conf_file = try cwd.openFile("/etc/resolv.conf", .{ .mode = .read_write });
    var res_conf_buf: [16_000]u8 = undefined;
    const start = try res_conf_file.readAll(res_conf_buf[0..]);
    _ = start;
    const res_conf_writer = res_conf_file.writer();
    try res_conf_writer.print("\n# DisCo Adds:", .{});
    for (config.servers) |server| {
        //log.debug("- Adding DNS: {s}", .{ IPF{ .bytes = server[0..] } });
        try res_conf_writer.print(
            "\nnameserver '{s}'",
            IPF{ .bytes = server[0..] },
        );
    }
    try res_conf_writer.print("\n# End DisCo Adds\n", .{});
}

/// Updates DNS settings using systemd-resolved via DBus.
pub fn updateDNSDBus(dbus_conn: *dbus.Connection, config: Config) !void {
    var buf: [16_000]u8 = undefined;
    var fba: std.heap.FixedBufferAllocator = .init(buf[0..]);
    var handler: Handler = try .init(fba.allocator(), dbus_conn, 1_000, config);
    while (handler.state != .done) {
        handler.step() catch |err| switch (err) {
            error.ReadFailed => {},
            else => return err,
        };
    }
}



/// Build a Set DNS Message.
fn buildSetDNSData(buf: []u8, config: Config) ![]const u8 {
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
        offset += 4;
        // Write address as byte array
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
    var uuid_buf: [286]u8 = undefined;
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
            .value = "org.freedesktop.resolve1",
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
    // Construct the DBus Route message to update DNS settings
    //log.debug("Building DBus DNS Route Message.", .{});
    var dns_msg: [8]u8 = @splat(0);
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
    //log.debug("DBus DNS Route Message:\n{s}\n---\n{s}", .{ dns_msg, HexF{ .bytes = dns_msg } });
    // Send the message
    //log.debug("Sending DBus DNS Message.", .{});
    var msg_buf: [4096]u8 = undefined;
    //try sock.writeAll(dns_msg);
    try dbus.sendMsg(
        msg_buf[0..],
        dbus_ctx.sock,
        header_fields[0..],
        dns_msg[0..],
    );
    // Read and Verify response
    var response_buf: [4096]u8 = undefined;
    //log.debug("Reading DBus DNS Response.", .{});
    //const read = try posix.read(sock, response_buf[0..]);
    const read = try dbus_ctx.sock.read(response_buf[0..]);
    if (read == 0) return error.MessageError;
    //log.debug("Verifying DBus DNS Response.", .{});
    //try dbus.verifyResponse(response_buf[0..read]);
}
