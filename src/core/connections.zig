//! Connection Tracking

const std = @import("std");
const atomic = std.atomic;
const fmt = std.fmt;
const linux = std.os.linux;
const log = std.log.scoped(.connections);
const math = std.math;
const mem = std.mem;
const meta = std.meta;
const posix = std.posix;
const time = std.time;

const zeit = @import("zeit");

const netdata = @import("../netdata.zig");
const address = netdata.address;
const MACF = address.MACFormatter;
const IPF = address.IPFormatter;
const core = @import("../core.zig");
const nl = @import("../netlink.zig");
const proto = @import("../protocols.zig");
const dhcp = proto.dhcp;
const wpa = proto.wpa;
const utils = @import("../utils.zig");
const c = utils.toStruct;


/// The Current State of a Connection.
pub const State = enum {
    /// Searching f/ the Network
    search,
    /// Authenticating to the Network
    auth,
    /// Associating to the Network
    assoc,
    /// Handling the 4 Way Handshake w/ the Router
    eapol,
    /// Requesting Routing Info via DHCP
    dhcp,
    /// Connected to the Network
    conn,
    /// Disconnected from the Network
    disc,

    pub fn format(
        self: @This(),
        _: []const u8,
        _: fmt.FormatOptions,
        writer: anytype,
    ) !void {
        try writer.print(
            "{s}",
            .{
                switch (self) {
                    .search => "Searching f/ the Network",
                    .auth => "Authenticating to the Network",
                    .assoc => "Associating to the Network",
                    .eapol => "Handling the 4 Way Handshake w/ the Router",
                    .dhcp => "Requesting Routing Info via DHCP",
                    .conn => "Connected to the Network",
                    .disc => "Disconnected from the Network",
                }
            },
        );
    }
};

/// Config
pub const Config = struct {
    /// Interfaces that are allowed to Connect to the corresponding Network.
    /// If this is left empty, any Interface may connect to the Network.
    if_names: []const []const u8 = &.{},
    ssid: []const u8,
    passphrase: []const u8,
    security: nl._80211.SecurityType = .wpa2,
    dhcp: ?proto.dhcp.LeaseConfig = null,
};

/// Connection Info
pub const Connection = struct {
    if_index: i32,
    state: State,
    bssid: [6]u8,
    ssid: []const u8,
    freq: u32,
    passphrase: []const u8,
    psk: [32]u8 = .{ 0 } ** 32,
    security: nl._80211.SecurityType = .wpa2,
    auth: nl._80211.AuthType = .psk,
    dhcp_info: ?dhcp.Info = null,

    pub fn deinit (self: *const @This(), alloc: mem.Allocator) void {
        alloc.free(self.ssid);
        alloc.free(self.passphrase);
    }
};

/// Connection Context
pub const Context = struct {
    /// Configs for Networks to Connect to.
    /// ID = Network SSID
    configs: *core.ThreadHashMap([]const u8, Config),
    /// Active & Previous Connections.
    /// ID = 6B Network BSSID + 4B Interface Index
    connections: *core.ThreadHashMap([10]u8, Connection),
    conn_pool: *std.Thread.Pool,
    conn_group: *std.Thread.WaitGroup,


    /// Initialize all Maps.
    pub fn init(alloc: mem.Allocator) !@This() {
        var self: @This() = undefined;
        inline for (meta.fields(@This())) |field| {
            switch (field.type) {
                inline else => |f_ptr_type| {
                    const f_type = @typeInfo(f_ptr_type).Pointer.child;
                    const ctx_field = try alloc.create(f_type);
                    ctx_field.* = switch (f_type) {
                        std.Thread.Pool => .{ .threads = &[_]std.Thread{}, .allocator = alloc },
                        inline else => .{},
                    };
                    @field(self, field.name) = ctx_field;
                }
            }
        }
        return self;
    }

    /// Deinitialize all Maps.
    pub fn deinit(self: *@This(), alloc: mem.Allocator) void {
        if (self.configs.count() > 0)
            self.configs.deinit(alloc);
        var conn_iter = self.connections.iterator();
        while (conn_iter.next()) |conn_entry|
            conn_entry.value_ptr.deinit(alloc);
        conn_iter.unlock();
        if (self.connections.count() > 0)
            self.connections.deinit(alloc);
    }
};

/// Track All Connections
pub fn trackConnections(
    alloc: mem.Allocator,
    active: *const atomic.Value(bool),
    interval: *const usize,
    ctx: *Context,
    if_ctx: *const core.interfaces.Context,
    nw_ctx: *const core.networks.Context,
) void {
    log.debug("Searching for {d} Connection(s)...", .{ ctx.configs.count() });
    var err_count: usize = 0;
    var job_count: u32 = 0;
    var if_iter = if_ctx.interfaces.iterator();
    errdefer if_iter.unlock();
    while (if_iter.next()) |if_entry| {
        const conn_if = if_entry.value_ptr;
        if (conn_if.usage == .available or conn_if.usage == .scanning) job_count += 1;
    }
    if_iter.unlock();
    ctx.conn_pool.init(.{ .allocator = alloc, .n_jobs = job_count }) catch |err| {
        log.err("Connection Tracking Error: {s}. Terminating Tracking!", .{ @errorName(err) });
        return;
    };
    while (active.load(.acquire)) {
        defer {
            if (err_count > 10) @panic("Connection Tracking encountered too many errors to continue!");
            time.sleep(interval.*);
        }
        var confs_iter = ctx.configs.iterator();
        defer confs_iter.unlock();
        checkConfs: while (confs_iter.next()) |conf_entry| {
            const conf = conf_entry.value_ptr;
            //log.debug("Searching for SSID '{s}' to Connect.", .{ conf.ssid });
            {
                var conns_iter = ctx.connections.iterator();
                defer conns_iter.unlock();
                while (conns_iter.next()) |conn| {
                    if (mem.eql(u8, conf.ssid, conn.value_ptr.ssid)) 
                        continue :checkConfs;
                }
            }
            var nw_iter = nw_ctx.networks.iterator();
            defer nw_iter.unlock();
            while (nw_iter.next()) |nw_entry| {
                const nw = nw_entry.value_ptr;
                if (!mem.eql(u8, conf.ssid, nw.ssid)) continue;
                log.debug("FOUND CONNECTION SSID: {s}", .{ nw.ssid });
                var ifs_iter = if_ctx.interfaces.iterator();
                defer ifs_iter.unlock();
                connIF: while (ifs_iter.next()) |if_entry| {
                    const conn_if = if_entry.value_ptr;
                    if (conf.if_names.len > 0) confIF: {
                        for (conf.if_names) |if_name| {
                            if (mem.eql(u8, if_name, conn_if.name))
                                break :confIF;
                        }
                        continue :connIF;
                    }
                    switch (conn_if.usage) {
                        .available, .scanning => {},
                        else => continue :connIF,
                    }
                    log.debug("Using Interface: ({d}) {s}", .{ conn_if.index, conn_if.name });
                    var set_if = (if_ctx.interfaces.map.getEntry(conn_if.index) orelse continue).value_ptr;
                    set_if.usage = .connecting;
                    const conn_id = nw.bssid ++ mem.toBytes(conn_if.index);
                    const psk = wpa.genKey(conf.security, conf.ssid, conf.passphrase) catch |err| {
                        log.err("Connection Update Error: {s}", .{ @errorName(err) });
                        err_count += 1;
                        continue;
                    };
                    ctx.connections.put(
                        alloc,
                        conn_id,
                        .{
                            .if_index = conn_if.index,
                            .state = .search,
                            .bssid = nw.bssid,
                            .ssid = alloc.dupe(u8, nw.ssid) catch @panic("OOM"),
                            .freq = nw.freq,
                            .passphrase = alloc.dupe(u8, conf.passphrase) catch @panic("OOM"),
                            .psk = psk,
                            .security = conf.security,
                        },
                    ) catch |err| {
                        log.err("Connection Update Error: {s}", .{ @errorName(err) });
                        err_count += 1;
                        continue;
                    };
                    ctx.conn_pool.spawnWg(
                        ctx.conn_group,
                        handleConnectionNoErr,
                        .{
                            alloc,
                            active,
                            interval,
                            ctx,
                            conn_id,
                            nw_ctx.scan_results.get(nw.bssid) orelse continue,
                            if_ctx,
                            conn_if.index,
                        },
                    );
                    time.sleep(interval.*);
                    break;
                }
            }
        }
    }
    defer {
        ctx.conn_pool.waitAndWork(ctx.conn_group);
        ctx.conn_pool.deinit();
        ctx.conn_group.reset();
    }

}

/// Handle an Individual Connection
/// TODO Implement all Security Protocols/Types
pub fn handleConnectionNoErr(
    alloc: mem.Allocator,
    active: *const atomic.Value(bool),
    interval: *const usize,
    ctx: *Context,
    conn_id: [10]u8,
    scan_results: nl._80211.ScanResults,
    if_ctx: *const core.interfaces.Context,
    if_index: i32,
) void {
    handleConnection(
        alloc,
        active,
        interval,
        ctx,
        conn_id,
        scan_results,
        if_ctx,
        if_index,
    ) catch |err| {
        log.err("Connection Handling Error: {s}", .{ @errorName(err) });
        return;
    };
}

/// Handle an Individual Connection
/// TODO Implement all Security Protocols/Types
pub fn handleConnection(
    alloc: mem.Allocator,
    active: *const atomic.Value(bool),
    interval: *const usize,
    ctx: *Context,
    conn_id: [10]u8,
    scan_results: nl._80211.ScanResults,
    if_ctx: *const core.interfaces.Context,
    if_index: i32,
) !void {
    const err_max = 10;
    var err_count: usize = 0;
    var last_err: anyerror = error.Unknown;
    var conn = ctx.connections.get(conn_id) orelse return error.ConnectionNotFound;
    const conn_if = if_ctx.interfaces.get(if_index) orelse return error.InterfaceNotFound;
    defer {
        if (conn.dhcp_info) |dhcp_info| {
            proto.dhcp.releaseDHCP(
                conn_if.name,
                conn_if.index,
                conn_if.mac,
                dhcp_info.server_id,
                dhcp_info.assigned_ip,
            ) catch |err| {
                log.warn("Couldn't release the DHCP Lease for '{s}': {s}", .{ conn_if.name, @errorName(err) });
            };
        }
        if (if_ctx.interfaces.getEntry(if_index)) |conn_if_entry| {
            conn_if_entry.value_ptr.usage = .available;
            if_ctx.interfaces.mutex.unlock();
        }
        else log.err("Couldn't update Interface State to Available: InterfaceNotFound", .{});
        if (ctx.connections.getEntry(conn_id)) |conn_entry| {
            conn_entry.value_ptr.state = .disc;
            ctx.connections.mutex.unlock();
        }
        else log.err("Couldn't update Connection State to Disconnected: ConnectionNotFound", .{});
    }
    log.debug(
        \\Handling Connection {X}:
        \\- nw: ({s}) {s}
        \\- if: ({d}) {s}
        \\- ch: ({d} MHz) {d}
        , .{ 
            conn_id,
            MACF{ .bytes = conn.bssid[0..] },
            conn.ssid, 
            conn_if.index, 
            conn_if.name,
            conn.freq,
            try nl._80211.channelFromFreq(conn.freq),
        }
    );
    // Netlink Setup
    const bss = scan_results.BSS orelse return error.MissingBSS;
    const ies = bss.INFORMATION_ELEMENTS orelse return error.MissingIEs;
    const ie_bytes = try nl.parse.toBytes(alloc, nl._80211.InformationElements, ies);
    defer alloc.free(ie_bytes);
    const rsn_bytes = rsnBytes: {
        const rsn = ies.RSN orelse return error.MissingRSN;
        const bytes = try nl.parse.toBytes(alloc, nl._80211.InformationElements.RobustSecurityNetwork, rsn);
        errdefer alloc.free(bytes);
        var buf = std.ArrayListUnmanaged(u8).fromOwnedSlice(bytes);
        errdefer buf.deinit(alloc);
        try buf.insert(alloc, 0, @intCast(bytes.len));
        try buf.insert(alloc, 0, c(nl._80211.IE).RSN);
        break :rsnBytes try buf.toOwnedSlice(alloc);
    };
    defer alloc.free(rsn_bytes);
    try nl._80211.registerFrames(
        alloc,
        conn_if.nl_sock,
        if_index,
        &.{ 0x00d0, 0x00d0, 0x00d0, 0x00d0, 0x00d0 },
        &.{ 0x0003, 0x0005, 0x0006, 0x0008, 0x000c },
    );
    time.sleep(interval.*);
    // Authenticate
    log.debug("Connection {X}: Authenticating", .{ conn_id });
    conn.state = .auth;
    try ctx.connections.put(alloc, conn_id, conn);
    while (active.load(.acquire)) {
        if (err_count >= err_max) {
            log.err("Authentication Error: {s}", .{ @errorName(last_err) });
            return last_err;
        }
        switch (conn.security) {
            .wpa2, .wpa3t => {
                nl._80211.authWPA2(
                    alloc,
                    conn_if.nl_sock,
                    conn_if.index,
                    conn.ssid,
                    scan_results,
                ) catch |err| {
                    err_count += 1;
                    last_err = err;
                    time.sleep(interval.*);
                    continue;
                };
                break;
            },
            else => |sec_proto| {
                log.err("The Security Protocol/Type '{s}' is not implemented.", .{ @tagName(sec_proto) });
                return error.UnimplementedSecurityType;
            },
        }
    }
    // Associacate
    log.debug("Connection {X}: Associating", .{ conn_id });
    conn.state = .assoc;
    try ctx.connections.put(alloc, conn_id, conn);
    while (active.load(.acquire)) {
        if (err_count >= err_max) {
            log.err("Association Error: {s}", .{ @errorName(last_err) });
            return last_err;
        }
        if_ctx.wifi_ifs.mutex.lock();
        defer if_ctx.wifi_ifs.mutex.unlock();
        const conn_wifi_if = if_ctx.wifi_ifs.map.get(conn_if.index) orelse {
            err_count += 1;
            last_err = error.MissingWiFiInterface;
            time.sleep(interval.*);
            continue;
        };
        if_ctx.wiphys.mutex.lock();
        defer if_ctx.wiphys.mutex.unlock();
        const conn_wiphy = if_ctx.wiphys.map.get(conn_if.phy_index) orelse {
            err_count += 1;
            last_err = error.MissingWiPhy;
            time.sleep(interval.*);
            continue;
        };
        switch (conn.security) {
            .wpa2, .wpa3t => {
                nl._80211.assocWPA2(
                    alloc,
                    conn_if.nl_sock,
                    conn_wifi_if,
                    conn_wiphy,
                    conn.ssid,
                    scan_results,
                ) catch |err| {
                    err_count += 1;
                    last_err = err;
                    time.sleep(interval.*);
                    continue;
                };
                break;
            },
            else => |sec_proto| {
                log.err("The Security Protocol/Type '{s}' is not implemented.", .{ @tagName(sec_proto) });
                return error.UnimplementedSecurityType;
            },
        }
    }
    // EAPoL - TODO Make this stateful f/ different Security Types
    log.debug("Connection {X}: Handling EAPoL", .{ conn_id });
    try posix.setsockopt(
        conn_if.nl_sock,
        posix.SOL.SOCKET,
        posix.SO.RCVTIMEO,
        mem.toBytes(posix.timeval{ .tv_sec = 4, .tv_usec = 0 })[0..],
    );
    conn.state = .eapol;
    try ctx.connections.put(alloc, conn_id, conn);
    log.debug("{s}: {s}", .{ conn_if.name, conn.state });
    const ptk,
    const gtk = keys: while (active.load(.acquire)) {
        if (err_count >= err_max) {
            log.err("EAPoL Error: {s}", .{ @errorName(last_err) });
            return last_err;
        }
        const ptk,
        const gtk = proto.wpa.handle4WHS(if_index, conn.psk, rsn_bytes) catch |err| {
            err_count += 1;
            last_err = err;
            time.sleep(interval.*);
            continue;
        };
        break :keys .{ ptk, gtk };
    }
    else return last_err;
    inline for (&.{ ptk[32..], gtk[0..] }, 0..) |key, idx| {
        try nl._80211.addKey(
            alloc,
            conn_if.nl_sock,
            if_index,
            if (idx == 0) bss.BSSID else null,
            .{
                .DATA = key.*,
                .CIPHER = c(nl._80211.CIPHER_SUITES).CCMP,
                .SEQ = if (idx == 0) null else .{ 2 } ++ .{ 0 } ** 5,
                .IDX = idx,
            },
        );
    }
    try posix.setsockopt(
        conn_if.nl_sock,
        posix.SOL.SOCKET,
        posix.SO.RCVTIMEO,
        mem.toBytes(posix.timeval{ .tv_sec = math.maxInt(u32), .tv_usec = 0 })[0..],
    );
    // DHCP
    conn.state = .conn;
    try ctx.connections.put(alloc, conn_id, conn);
    log.debug("{s}: {s}", .{ conn_if.name, conn.state });
    const conf = ctx.configs.get(conn.ssid).?;
    if (conf.dhcp) |dhcp_conf| {
        log.debug("Connection {X}: Handling DHCP", .{ conn_id });
        while (active.load(.acquire)) {
            if (err_count >= err_max) {
                log.err("DHCP Error: {s}", .{ @errorName(last_err) });
                return last_err;
            }
            const dhcp_info = proto.dhcp.handleDHCP(
                conn_if.name,
                conn_if.index,
                conn_if.mac,
                dhcp_conf,
            ) catch |err| {
                err_count += 1;
                last_err = err;
                time.sleep(interval.*);
                continue;
            };
            conn.dhcp_info = dhcp_info;
            try ctx.connections.put(alloc, conn_id, conn);
            break;
        }
    }
    // Connected
    var set_if = (if_ctx.interfaces.getEntry(if_index) orelse return error.InterfaceNotFound).value_ptr;
    set_if.usage = .connecting;
    if_ctx.interfaces.mutex.unlock();
    conn.state = .conn;
    try ctx.connections.put(alloc, conn_id, conn);
    log.debug("{s}: {s}", .{ conn_if.name, conn.state });
    while (active.load(.acquire))
        time.sleep(interval.*);
}
