//! Connection Tracking

const std = @import("std");
const atomic = std.atomic;
const crypto = std.crypto;
const Ed25519 = crypto.ecc.Edwards25519;
const P256 = crypto.ecc.P256;
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
const dns = proto.dns;
const sae = proto.sae;
const wpa = proto.wpa;
const utils = @import("../utils.zig");
const c = utils.toStruct;
const HexF = utils.HexFormatter;


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
    /// Error during Connnection
    err,

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
                    .err => "Error during Connection"
                }
            },
        );
    }
};

/// Config for All Connections.
pub const GlobalConfig = struct {
    /// The Max Age, in milliseconds, of a Network that's allowed for Connection attempts.
    network_max_age: usize = 10_000,
    /// DHCP Config.
    dhcp: ?proto.dhcp.LeaseConfig = null,
    /// Add a Default Route Gateway & DNS.
    add_gw: bool = false,
    /// The Delay, in milliseconds, between specifc socket operations.
    /// If this is left `null` a dynamic delay will be calculated based on RSSI.
    op_delay: ?usize = null,
};

/// Config for a Single Connection.
pub const Config = struct {
    /// Interfaces that are allowed to Connect to the corresponding Network.
    /// If this is left empty, any Interface may connect to the Network.
    if_names: []const []const u8 = &.{},
    ssid: []const u8,
    passphrase: []const u8 = "",
    security: nl._80211.SecurityType = .wpa2,
    auth: nl._80211.AuthType = .psk,
    /// DHCP Config.
    dhcp: ?proto.dhcp.LeaseConfig = null,
    /// Add a Default Route Gateway & DNS.
    add_gw: ?bool = null,
};

/// Connection Info
pub const Connection = struct {
    active: atomic.Value(bool) = atomic.Value(bool).init(false),
    if_index: i32,
    state: State = .search,
    bssid: [6]u8,
    ssid: []const u8,
    freq: u32,
    passphrase: []const u8,
    psk: [32]u8 = .{ 0 } ** 32,
    security: nl._80211.SecurityType = .wpa2,
    auth: nl._80211.AuthType = .psk,
    eapol_keys: ?nl._80211.EAPoLKeys = null,
    dhcp_conf: ?proto.dhcp.LeaseConfig = null,
    dhcp_info: ?dhcp.Info = null,
    add_gw: bool = false,

    pub fn deinit (self: *const @This(), alloc: mem.Allocator) void {
        alloc.free(self.ssid);
        alloc.free(self.passphrase);
    }
};

/// Connection Context
pub const Context = struct {
    /// Global Config for All Connections. (Used as a fallback for overlapping fields)
    global_config: *GlobalConfig,
    /// Configs for Networks to Connect to.
    /// ID = Network SSID
    configs: *core.ThreadHashMap([]const u8, Config),
    /// Active & Previous Connections.
    /// ID = 6B Network BSSID + 4B Interface Index
    connections: *core.ThreadHashMap([10]u8, Connection),
    //connections: *core.ThreadHashMap([6]u8, Connection),
    thread_pool: *std.Thread.Pool,
    wait_group: *std.Thread.WaitGroup,


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
    core_config: *const core.Core.Config,
    ctx: *Context,
    if_ctx: *const core.interfaces.Context,
    nw_ctx: *const core.networks.Context,
) void {
    log.debug("Searching for {d} Connection(s)...", .{ ctx.configs.count() });
    var track_count: u8 = 0;
    const err_max: usize = 10;
    var err_count: usize = 0;
    var job_count: u32 = 0;
    var if_iter = if_ctx.interfaces.iterator();
    errdefer if_iter.unlock();
    while (if_iter.next()) |if_entry| {
        const conn_if = if_entry.value_ptr;
        if (conn_if.usage == .available) job_count += 10;
    }
    if_iter.unlock();
    ctx.thread_pool.init(.{ .allocator = alloc, .n_jobs = job_count }) catch |err| {
        log.err("Connection Tracking Error: {s}. Terminating Tracking!", .{ @errorName(err) });
        return;
    };
    while (active.load(.acquire)) {
        defer {
            track_count +%= 1;
            if (track_count % err_max == 0) err_count -|= 1;
            if (err_count > err_max) @panic("Connection Tracking encountered too many errors to continue!");
            time.sleep(interval.*);
        }
        checkIFs: {
            if_iter = if_ctx.interfaces.iterator();
            defer if_iter.unlock();
            while (if_iter.next()) |if_entry| {
                const conn_if = if_entry.value_ptr;
                if (conn_if.usage == .available) break :checkIFs;
            }
            continue;
        }
        var confs_iter = ctx.configs.iterator();
        defer confs_iter.unlock();
        //checkConfs: while (confs_iter.next()) |conf_entry| {
        while (confs_iter.next()) |conf_entry| {
            const conf = conf_entry.value_ptr;
            var nw_iter = nw_ctx.networks.iterator();
            defer nw_iter.unlock();
            checkNW: while (nw_iter.next()) |nw_entry| {
                const nw = nw_entry.value_ptr;
                const now = zeit.instant(.{}) catch {
                    log.warn("Could not get current time!", .{});
                    continue;
                };
                const diff_seen = @divFloor((now.timestamp -| nw.last_seen.timestamp), @as(i128, time.ns_per_ms));
                if (diff_seen >= ctx.global_config.network_max_age) continue;
                if (mem.indexOf(u8, nw.ssid, conf.ssid) == null) continue;
                {
                    var conns_iter = ctx.connections.iterator();
                    defer conns_iter.unlock();
                    while (conns_iter.next()) |conn_entry| {
                        const conn = conn_entry.value_ptr;
                        if (
                            mem.eql(u8, conf.ssid, conn.ssid) and
                            mem.eql(u8, conn.bssid[0..], nw.bssid[0..]) and
                            conn.active.load(.acquire)
                        ) {
                            //log.debug("Found Connection SSID but ignoring: {s}, Active: {}", .{ nw.ssid, conn.active.load(.acquire) });
                            time.sleep(interval.*);
                            continue :checkNW;
                        }
                    }
                }
                //log.debug("Found Connection SSID: {s}", .{ nw.ssid });
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
                    checkLink: {
                        const get_link = (if_ctx.links.get(conn_if.index) orelse break :checkLink).link;
                        const oper_state = get_link.OPERSTATE orelse break :checkLink;
                        if (oper_state == c(nl.route.IF_OPER).NOTPRESENT) continue :connIF;
                    }
                    switch (conn_if.usage) {
                        .available => {},
                        else => continue :connIF,
                    }
                    log.debug("Using Interface: ({d}) {s}", .{ conn_if.index, conn_if.name });
                    var set_if = (if_ctx.interfaces.map.getEntry(conn_if.index) orelse continue).value_ptr;
                    set_if.usage = .connecting;
                    const conn_id = nw.bssid ++ mem.toBytes(conn_if.index);
                    //const conn_id = nw.bssid;
                    const psk = switch (conf.security) {
                        .wpa2, .wpa3t => wpa.genKey(conf.security, nw.ssid, conf.passphrase) catch |err| {
                            log.err("Connection Update Error: {s}", .{ @errorName(err) });
                            err_count += 1;
                            continue;
                        },
                        .open, .wpa3 => .{ 0 } ** 32,
                        else => continue,
                    };
                    if (ctx.connections.getEntry(conn_id)) |conn_entry| {
                        conn_entry.value_ptr.deinit(alloc);
                    }
                    ctx.connections.mutex.unlock();
                    ctx.connections.put(
                        alloc,
                        conn_id,
                        .{
                            .active = atomic.Value(bool).init(true),
                            .if_index = conn_if.index,
                            .state = .search,
                            .bssid = nw.bssid,
                            .ssid = alloc.dupe(u8, nw.ssid) catch @panic("OOM"),
                            .freq = nw.freq,
                            .passphrase = alloc.dupe(u8, conf.passphrase) catch @panic("OOM"),
                            .psk = psk,
                            .security = conf.security,
                            .auth = conf.auth,
                            .dhcp_conf = conf.dhcp orelse ctx.global_config.dhcp,
                            .add_gw = conf.add_gw orelse ctx.global_config.add_gw,
                        },
                    ) catch |err| {
                        log.err("Connection Update Error: {s}", .{ @errorName(err) });
                        err_count += 1;
                        continue;
                    };
                    ctx.thread_pool.spawnWg(
                        ctx.wait_group,
                        handleConnectionNoErr,
                        .{
                            alloc,
                            active,
                            interval,
                            core_config,
                            ctx,
                            conn_id,
                            nw_ctx.scan_results,
                            if_ctx,
                            conn_if.index,
                        },
                    );
                    break :checkNW;
                }
            }
        }
    }
    defer {
        ctx.thread_pool.waitAndWork(ctx.wait_group);
        ctx.thread_pool.deinit();
        ctx.wait_group.reset();
    }
}

/// Handle an Individual Connection
/// TODO Implement all Security Protocols/Types
pub fn handleConnectionNoErr(
    alloc: mem.Allocator,
    active: *const atomic.Value(bool),
    interval: *const usize,
    core_config: *const core.Core.Config,
    ctx: *Context,
    conn_id: [10]u8,
    //conn_id: [6]u8,
    nw_scan_results: *core.ThreadHashMap([6]u8, nl._80211.ScanResults),
    if_ctx: *const core.interfaces.Context,
    if_index: i32,
) void {
    handleConnection(
        alloc,
        active,
        interval,
        core_config,
        ctx,
        conn_id,
        nw_scan_results,
        if_ctx,
        if_index,
    ) catch |err| {
        log.err("Connection Handling Error: {s}", .{ @errorName(err) });
        time.sleep(interval.*);
        return;
    };
}

/// Handle an Individual Connection
/// TODO Implement all Security Protocols/Types
pub fn handleConnection(
    alloc: mem.Allocator,
    active: *const atomic.Value(bool),
    interval: *const usize,
    core_config: *const core.Core.Config,
    ctx: *Context,
    conn_id: [10]u8,
    nw_scan_results: *core.ThreadHashMap([6]u8, nl._80211.ScanResults),
    if_ctx: *const core.interfaces.Context,
    if_index: i32,
) !void {
    const err_max = 3;
    var err_count: usize = 0;
    var last_err: anyerror = error.Unknown;
    var conn = ctx.connections.get(conn_id) orelse return error.ConnectionNotFound;
    const conn_active: *atomic.Value(bool) = connActive: {
        var get_conn = (ctx.connections.getEntry(conn_id) orelse {
            ctx.connections.mutex.unlock();
            return error.ConnectionNotFound;
        }).value_ptr;
        defer ctx.connections.mutex.unlock();
        break :connActive &get_conn.active;
    };
    var set_conn = (ctx.connections.getEntry(conn_id) orelse {
        ctx.connections.mutex.unlock();
        return error.ConnectionNotFound;
    }).value_ptr;
    ctx.connections.mutex.unlock();
    errdefer errOut: {
        defer ctx.connections.mutex.unlock();
        set_conn = (ctx.connections.getEntry(conn_id) orelse break :errOut).value_ptr;
        set_conn.state = .err;
    }
    var conn_if = if_ctx.interfaces.get(if_index) orelse return error.InterfaceNotFound;
    conn_if.name = try alloc.dupe(u8, conn_if.name);
    conn_if.phy_name = try alloc.dupe(u8, conn_if.phy_name);
    defer {
        log.info("Cleaning Connection (ssid: {s}, if: {s})...", .{ conn.ssid, conn_if.name });
        const cur_conn = ctx.connections.get(conn_id);
        if (cur_conn) |get_conn| relDHCP: {
            alloc.free(conn_if.name);
            alloc.free(conn_if.phy_name);
            conn_if = if_ctx.interfaces.get(if_index) orelse break :relDHCP;
            if (conn_if.usage == .unavailable) break :relDHCP;
            const dhcp_info = get_conn.dhcp_info orelse break :relDHCP;
            proto.dhcp.releaseDHCP(
                conn_if.name,
                conn_if.index,
                conn_if.mac,
                dhcp_info.server_id,
                dhcp_info.assigned_ip,
            ) catch |err| {
                log.warn("- Couldn't release the DHCP Lease for '{s}': {s}", .{ conn_if.name, @errorName(err) });
                break :relDHCP;
            };
            log.info("- Released DHCP lease.", .{});
        }
        defer if (cur_conn == null) {
            alloc.free(conn_if.name);
            alloc.free(conn_if.phy_name);
        };
        {
            defer if_ctx.interfaces.mutex.unlock();
            if (if_ctx.interfaces.getEntry(if_index)) |conn_if_entry| {
                const set_conn_if = conn_if_entry.value_ptr;
                set_conn_if.restore(alloc, &.{ .ips, .dns });
                set_conn_if.usage = .available;
                log.debug("- Interface '({d}) {s}' made Available.", .{ conn_if_entry.key_ptr.*, conn_if_entry.value_ptr.name });
            }
            else log.err("- Couldn't update Interface State to Available: InterfaceNotFound", .{});
        }
        {
            defer ctx.connections.mutex.unlock();
            if (ctx.connections.getEntry(conn_id)) |conn_entry|
                conn_entry.value_ptr.state = .disc
            else log.err("- Couldn't update Connection State to Disconnected: ConnectionNotFound", .{});
        }
        conn_active.store(false, .seq_cst);
        log.info("Cleaned Connection (ssid: {s}, if: {s}).", .{ conn.ssid, conn_if.name });
    }
    log.info(
        \\Connecting to '({s}) {s}'...
        \\- if:  ({d}) {s}
        \\- ch:  ({d} MHz) {d}
        \\- sec: {s} {s}
        , .{
            MACF{ .bytes = conn.bssid[0..] },
            conn.ssid,
            conn_if.index,
            conn_if.name,
            conn.freq,
            try nl._80211.channelFromFreq(conn.freq),
            @tagName(conn.security),
            @tagName(conn.auth),
        }
    );
    // Netlink Setup
    if (!active.load(.acquire) or !conn_active.load(.acquire)) return;
    try nl._80211.registerFrames(
        alloc,
        conn_if.nl_sock,
        if_index,
        &.{ 0x00d0, 0x00d0, 0x00d0, 0x00d0, 0x00d0 },
        &.{ &.{ 0x00, 0x03 }, &.{ 0x00, 0x05 }, &.{ 0x00, 0x06 }, &.{ 0x00, 0x08 }, &.{ 0x00, 0x0c } },
    );
    // This block locks Scan Tracking.
    var op_delay: u64 = 50;
    {
        // Scan Results
        const scan_results = (nw_scan_results.getEntry(conn.bssid) orelse return error.ScanResultsNotFound).value_ptr.*;
        defer nw_scan_results.mutex.unlock();
        const bss = scan_results.BSS orelse return error.MissingBSS;
        op_delay = opDelay: { 
            if (ctx.global_config.op_delay) |delay| 
                break :opDelay delay * time.ns_per_ms;
            break :opDelay calcOpDelay(bss);
        };
        log.debug("Op Delay: {d}ms (RSSI: {d}dB)", .{ @divFloor(op_delay, time.ns_per_ms), @divFloor(bss.SIGNAL_MBM orelse -10_000, 100) });
        time.sleep(op_delay);
        const ies = bss.INFORMATION_ELEMENTS orelse return error.MissingIEs;
        const ie_bytes = try nl.parse.toBytes(alloc, nl._80211.InformationElements, ies);
        defer alloc.free(ie_bytes);
        // Authenticate
        var conn_psk: [32]u8 = connPSK: {
            defer ctx.connections.mutex.unlock();
            if (ctx.connections.getEntry(conn_id)) |conn_entry|
                break :connPSK conn_entry.value_ptr.psk
            else
                break :connPSK .{ 0 } ** 32;
        };
        if (!active.load(.acquire) or !conn_active.load(.acquire)) return;
        log.debug("Connection {X}: Authenticating", .{ conn_id });
        set_conn = (ctx.connections.getEntry(conn_id) orelse {
            ctx.connections.mutex.unlock();
            return error.ConnectionNotFound;
        }).value_ptr;
        set_conn.state = .auth;
        ctx.connections.mutex.unlock();
        while (active.load(.acquire) and conn_active.load(.acquire)) {
            if (err_count >= err_max) {
                log.err("Authentication Error: {s}", .{ @errorName(last_err) });
                return last_err;
            }
            switch (conn.security) {
                .open, .wpa2, .wpa3t => {
                    nl._80211.authenticate(
                        alloc,
                        conn_if.nl_sock,
                        conn_if.index,
                        conn.ssid,
                        scan_results,
                        null,
                    ) catch |err| {
                        err_count += 1;
                        last_err = err;
                        time.sleep(op_delay * err_count * err_count);
                        continue;
                    };
                    break;
                },
                .wpa3 => {
                    try posix.setsockopt(
                        conn_if.nl_sock,
                        posix.SOL.SOCKET,
                        posix.SO.RCVTIMEO,
                        mem.toBytes(posix.timeval{ .tv_sec = 1, .tv_usec = 0 })[0..],
                    );
                    const nl80211_info = nl._80211.ctrl_info orelse @panic("Netlink 802.11 (nl80211) not Initialized!");
                    const nl80211_mlme = nl80211_info.MCAST_GROUPS.get("mlme") orelse @panic("Netlink 802.11 (nl80211) not Initialized!");
                    try posix.setsockopt(
                        conn_if.nl_sock,
                        posix.SOL.NETLINK,
                        nl.NETLINK_OPT.ADD_MEMBERSHIP,
                        mem.toBytes(nl80211_mlme)[0..],
                    );
                    nl._80211.registerFrames(
                        alloc,
                        conn_if.nl_sock,
                        conn_if.index,
                        &.{ 0x00b0 },
                        &.{ &.{ 0xb0, 0x00, 0x03, 0x00 } },
                    ) catch |err| {
                        log.warn("Issue Registering Frames for Authentication Response: {s}", .{ @errorName(err) });
                    };
                    time.sleep(op_delay * 10);
                    var sae_ctx = sae.genCommit(conn.passphrase, conn.bssid, conn_if.mac) catch |err| {
                        err_count += 1;
                        last_err = err;
                        time.sleep(op_delay * err_count * err_count);
                        continue;
                    };
                    const sae_commit: [102]u8 =
                        // Commit
                        mem.toBytes(@as(u32, 1)) ++
                        // Group
                        mem.toBytes(@as(u16, 19)) ++
                        sae_ctx.commit.scalar ++
                        sae_ctx.commit.element.x.toBytes(.big) ++
                        sae_ctx.commit.element.y.toBytes(.big);
                    log.debug("SAE Commit Data:{s}\n", .{ HexF{ .bytes = sae_commit[0..] } });
                    log.debug("WPA3 Auth SAE Commit...", .{});
                    nl._80211.authenticate(
                        alloc,
                        conn_if.nl_sock,
                        conn_if.index,
                        conn.ssid,
                        scan_results,
                        sae_commit[0..],
                    ) catch |err| {
                        log.warn("Issue sending WPA3 SAE Commit data: {s}", .{ @errorName(err) });
                        err_count += 1;
                        last_err = err;
                        time.sleep(op_delay * err_count * err_count);
                        continue;
                    };
                    //log.debug("WPA3 Auth SAE Commit done.", .{});
                    const sae_commit_resp_data = nl._80211.handleAuthResponse(alloc, conn_if.nl_sock) catch |err| {
                        log.warn("Issue handling WPA3 SAE Commit response data: {s}", .{ @errorName(err) });
                        err_count += 1;
                        last_err = err;
                        time.sleep(op_delay * err_count * err_count);
                        continue;
                    };
                    defer {
                        for (sae_commit_resp_data) |scr_data|
                            nl.parse.freeBytes(alloc, nl._80211.AuthResponse, scr_data);
                        alloc.free(sae_commit_resp_data);
                    }
                    if (sae_commit_resp_data.len == 0) {
                        log.warn("Issue handling WPA3 SAE Commit response data: EmptyCommitResponse", .{});
                        err_count += 1;
                        last_err = error.EmptyCommitResponse;
                        time.sleep(op_delay * err_count * err_count);
                        continue;
                    }
                    log.debug("SAE Commit Response Data: {d}B{s}", .{ sae_commit_resp_data[0].FRAME.len, HexF{ .bytes = sae_commit_resp_data[0].FRAME } });
                    if (sae_commit_resp_data[0].FRAME.len < 96) {
                        log.warn("Issue handling WPA3 SAE Commit response data: InvalidCommitResponse (Len = {d}B)", .{ sae_commit_resp_data[0].FRAME.len });
                        err_count += 1;
                        last_err = error.InvalidCommitResponse;
                        time.sleep(op_delay * err_count * err_count);
                        continue;
                    }
                    const sae_commit_resp = sae_commit_resp_data[0].FRAME[32..];
                    const peer: sae.Commit = .{
                        .scalar = sae_commit_resp[0..32].*,
                        .element = P256.fromSerializedAffineCoordinates(sae_commit_resp[32..64].*, sae_commit_resp[64..96].*, .big) catch |err| {
                            log.warn("Issue handling WPA3 SAE Commit response Peer: {s}", .{ @errorName(err) });
                            err_count += 1;
                            last_err = err;
                            time.sleep(op_delay * err_count * err_count);
                            continue;
                        },
                    };
                    sae.genConfirm(&sae_ctx, peer) catch |err| {
                        log.warn("Issue generating WPA3 SAE Confirm data: {s}", .{ @errorName(err) });
                        err_count += 1;
                        last_err = err;
                        time.sleep(op_delay * err_count * err_count);
                        continue;
                    };
                    log.debug("WPA3 Auth SAE Confirm...", .{});
                    const sae_confirm: [38]u8 =
                        // Confirm
                        mem.toBytes(@as(u32, 2)) ++
                        // Send Confirm
                        sae_ctx.send_confirm ++
                        sae_ctx.confirm.?[0..32].*;
                    nl._80211.authenticate(
                        alloc,
                        conn_if.nl_sock,
                        conn_if.index,
                        conn.ssid,
                        scan_results,
                        sae_confirm[0..],
                    ) catch |err| {
                        err_count += 1;
                        last_err = err;
                        time.sleep(op_delay * err_count * err_count);
                        continue;
                    };
                    const sae_confirm_resp_data = nl._80211.handleAuthResponse(alloc, conn_if.nl_sock) catch |err| {
                        log.warn("Issue handling WPA3 SAE Confirm response data: {s}", .{ @errorName(err) });
                        err_count += 1;
                        last_err = err;
                        time.sleep(op_delay * err_count * err_count);
                        continue;
                    };
                    defer {
                        for (sae_confirm_resp_data) |scr_data|
                            nl.parse.freeBytes(alloc, nl._80211.AuthResponse, scr_data);
                        alloc.free(sae_confirm_resp_data);
                    }
                    log.debug("SAE Confirm Response Data: {d}B{s}", .{ sae_confirm_resp_data[0].FRAME.len, HexF{ .bytes = sae_confirm_resp_data[0].FRAME } });
                    const resp_type: u16 = mem.readInt(u16, sae_confirm_resp_data[0].FRAME[26..28], .little);
                    if (resp_type != 2) {
                        log.warn("Issue handling WPA3 SAE Confirm response data: Non-Confirm Response ({d})", .{ resp_type });
                        err_count += 1;
                        last_err = error.NonConfirmResponse;
                        time.sleep(op_delay * err_count * err_count);
                        continue;
                    }
                    const resp_code: u16 = mem.readInt(u16, sae_confirm_resp_data[0].FRAME[28..30], .little);
                    if (resp_code != 0) {
                        log.warn("Issue handling WPA3 SAE Confirm response data: Confirm Response Error ({X:0>4})", .{ resp_code });
                        err_count += 1;
                        last_err = error.ConfirmResponseError;
                        time.sleep(op_delay * err_count * err_count);
                        continue;
                    }
                    const peer_ctx: sae.Context = .{
                        .kck = sae_ctx.kck,
                        .send_confirm = sae_confirm_resp_data[0].FRAME[30..32].*,
                        .confirm = sae_confirm_resp_data[0].FRAME[32..64].*,
                        .commit = peer,
                        .pwe = P256.basePoint,
                        .private = .{ 0 } ** 32,
                    }; 
                    sae.checkConfirm(peer_ctx.confirm.?, sae_ctx.commit, peer_ctx) catch {
                        log.warn("Issue handling WPA3 SAE Confirm response: Confirm Token Verification Mismatch", .{});
                        err_count += 1;
                        last_err = error.ConfirmResponseError;
                        time.sleep(op_delay * err_count * err_count);
                        continue;
                    };
                    conn_psk = sae_ctx.pmk.?;
                    log.debug("WPA3 Auth SAE Confirm done.", .{});
                    set_conn = (ctx.connections.getEntry(conn_id) orelse {
                        ctx.connections.mutex.unlock();
                        return error.ConnectionNotFound;
                    }).value_ptr;
                    ctx.connections.mutex.unlock();
                    break;
                },
                else => |sec_proto| {
                    log.err("The Security Protocol/Type '{s}' is not implemented.", .{ @tagName(sec_proto) });
                    return error.UnimplementedSecurityType;
                },
            }
        }
        time.sleep(op_delay);
        // Associate
        if (!active.load(.acquire) or !conn_active.load(.acquire)) return;
        log.debug("Connection {X}: Associating", .{ conn_id });
        set_conn = (ctx.connections.getEntry(conn_id) orelse {
            ctx.connections.mutex.unlock();
            return error.ConnectionNotFound;
        }).value_ptr;
        set_conn.state = .assoc;
        ctx.connections.mutex.unlock();
        while (active.load(.acquire) and conn_active.load(.acquire)) {
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
            defer if_ctx.wiphys.mutex.unlock();
            const conn_wiphy = (if_ctx.wiphys.getEntry(conn_if.phy_index) orelse {
                err_count += 1;
                last_err = error.MissingWiPhy;
                time.sleep(interval.*);
                continue;
            }).value_ptr.*;
            //log.debug("WIPHY:\n{}", .{ conn_wiphy });
            switch (conn.security) {
                .open, .wpa2, .wpa3t, .wpa3 => {
                    nl._80211.associate(
                        alloc,
                        conn_if.nl_sock,
                        conn_wifi_if,
                        conn_wiphy,
                        conn.ssid,
                        scan_results,
                    ) catch |err| {
                        err_count += 1;
                        last_err = err;
                        time.sleep(interval.* * err_count * err_count);
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
        time.sleep(op_delay);
        // EAPoL
        if (!active.load(.acquire) or !conn_active.load(.acquire)) return;
        switch (conn.security) {
            .wpa2, .wpa3t, .wpa3 => {
                log.debug("Connection {X}: Handling EAPoL", .{ conn_id });
                try posix.setsockopt(
                    conn_if.nl_sock,
                    posix.SOL.SOCKET,
                    posix.SO.RCVTIMEO,
                    mem.toBytes(posix.timeval{ .tv_sec = 1, .tv_usec = 0 })[0..],
                );
                set_conn = (ctx.connections.getEntry(conn_id) orelse {
                    ctx.connections.mutex.unlock();
                    return error.ConnectionNotFound;
                }).value_ptr;
                set_conn.state = .eapol;
                log.debug("{s}: {s}", .{ conn_if.name, set_conn.state });
                ctx.connections.mutex.unlock();
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
                const keys = keys: while (active.load(.acquire) and conn_active.load(.acquire)) {
                    if (err_count >= err_max) {
                        log.err("EAPoL Error: {s}", .{ @errorName(last_err) });
                        return last_err;
                    }
                    break :keys proto.wpa.handle4WHS(
                        if_index, 
                        conn_psk, 
                        rsn_bytes,
                        conn.security,
                    ) catch |err| {
                        err_count += 1;
                        last_err = err;
                        time.sleep(op_delay * err_count * err_count);
                        continue;
                    };
                }
                else return last_err;
                inline for (&.{ keys.ptk[32..], keys.gtk[0..] }, 0..) |key, idx| {
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
                set_conn = (ctx.connections.getEntry(conn_id) orelse {
                    ctx.connections.mutex.unlock();
                    return error.ConnectionNotFound;
                }).value_ptr;
                set_conn.eapol_keys = keys;
                ctx.connections.mutex.unlock();
            },
            .open => {},
            else => return error.UnsupportedSecurityType,
        }
    }
    // Connected
    if (!active.load(.acquire) or !conn_active.load(.acquire)) return;
    try posix.setsockopt(
        conn_if.nl_sock,
        posix.SOL.SOCKET,
        posix.SO.RCVTIMEO,
        mem.toBytes(posix.timeval{ .tv_sec = math.maxInt(u32), .tv_usec = 0 })[0..],
    );
    var set_if = setIF: {
        defer if_ctx.interfaces.mutex.unlock();
        var set_if = (if_ctx.interfaces.getEntry(if_index) orelse return error.InterfaceNotFound).value_ptr;
        set_if.usage = .connected;
        break :setIF set_if;
    };
    // DHCP
    if (!active.load(.acquire) or !conn_active.load(.acquire)) return;
    set_conn = (ctx.connections.getEntry(conn_id) orelse {
        ctx.connections.mutex.unlock();
        return error.ConnectionNotFound;
    }).value_ptr;
    set_conn.state = .dhcp;
    log.debug("{s}: {s}", .{ conn_if.name, set_conn.state });
    ctx.connections.mutex.unlock();
    if (conn.dhcp_conf) |dhcp_conf| tryDHCP: {
        log.debug("Connection {X}: Handling DHCP", .{ conn_id });
        while (active.load(.acquire) and conn_active.load(.acquire)) {
            if (err_count >= err_max) {
                log.err("DHCP Error: {s}", .{ @errorName(last_err) });
                break :tryDHCP;
            }
            var dhcp_hn_conf = dhcp_conf;
            if (core_config.profile.mask) |pro_mask|
                dhcp_hn_conf.hostname = pro_mask.hostname;
            const dhcp_info = proto.dhcp.handleDHCP(
                conn_if.name,
                conn_if.index,
                conn_if.mac,
                dhcp_hn_conf,
            ) catch |err| {
                err_count += 1;
                last_err = err;
                time.sleep(op_delay);
                continue;
            };
            set_conn = (ctx.connections.getEntry(conn_id) orelse {
                ctx.connections.mutex.unlock();
                return error.ConnectionNotFound;
            }).value_ptr;
            set_conn.dhcp_info = dhcp_info;
            {
                defer if_ctx.interfaces.mutex.unlock();
                set_if = (if_ctx.interfaces.getEntry(if_index) orelse return error.InterfaceNotFound).value_ptr;
                const dhcp_cidr = address.cidrFromSubnet(dhcp_info.subnet_mask);
                nl.route.addIP(
                    alloc,
                    set_if.index,
                    dhcp_info.assigned_ip,
                    dhcp_cidr,
                ) catch {
                    log.warn("Couldn't add IP '{s}/{d}' to Interface '({d}) {s}'", .{
                        IPF{ .bytes = dhcp_info.assigned_ip[0..] },
                        dhcp_cidr,
                        set_if.index,
                        set_if.name,
                    });
                };
                log.info("Added IP '{s}/{d}' to ({d}) {s}", .{
                    IPF{ .bytes = dhcp_info.assigned_ip[0..] },
                    dhcp_cidr,
                    set_if.index,
                    set_if.name,
                });
                if (conn.add_gw) addGW: {
                    nl.route.addRoute(
                        alloc,
                        set_if.index,
                        address.IPv4.default.addr,
                        .{
                            .cidr = address.IPv4.default.cidr,
                            .gateway = dhcp_info.router,
                        },
                    ) catch |err| {
                        log.warn("Couldn't add Default Gateway '{s}/{d}' to Interface '({d}) {s}':\nError: {s}", .{
                            IPF{ .bytes = dhcp_info.router[0..] },
                            dhcp_cidr,
                            set_if.index,
                            set_if.name,
                            if (err == error.EXIST) "There's already a Default Gateway."
                            else @errorName(err),
                        });
                        break :addGW;
                    };
                    log.info("Added Default Gateway '{s}/{d}' to ({d}) {s}", .{
                        IPF{ .bytes = dhcp_info.router[0..] },
                        dhcp_cidr,
                        set_if.index,
                        set_if.name,
                    });
                    var dns_ips_buf: [4][4]u8 = undefined;
                    const dns_ips: []const [4]u8 = dnsIPs: {
                        //log.debug("DNS IPs: {s}", .{ if (dhcp_info.dns_ips[0]) |_| "" else "none" });
                        var total_dns: usize = 0;
                        defer log.debug("- Total DNS: {d}", .{ total_dns });
                        dnsLoop: for (dhcp_info.dns_ips, 0..) |dns_ip, idx| {
                            const next_dns = dns_ip orelse break :dnsIPs dns_ips_buf[0..total_dns];
                            for (dns_ips_buf[0..idx]) |prev_dns| {
                                if (mem.eql(u8, prev_dns[0..], next_dns[0..])) continue :dnsLoop;
                            }
                            //log.debug("- {s}", .{ IPF{ .bytes = next_dns[0..] } });
                            dns_ips_buf[idx] = next_dns;
                            total_dns += 1;
                        }
                        break :dnsIPs &.{};
                    };
                    if (dns_ips.len > 0) setDNS: {
                        dns.updateDNS(.{ .if_index = if_index, .servers = dns_ips }) catch |err| {
                        //dns.updateDNS(.{ .if_index = if_index, .servers = dns_ips[0..1] }) catch |err| {
                            log.err("Could not set DNS: {s}", .{ @errorName(err) });
                            break :setDNS;
                        };
                        log.info("Added DNS '{s}' to ({d}) {s}", .{ 
                            IPF{ .bytes = dns_ips[0][0..] },
                            set_if.index,
                            set_if.name,
                        });
                    }
                }
            }
            //log.debug("{s}: {s}", .{ conn_if.name, set_conn.state });
            ctx.connections.mutex.unlock();
            break;
        }
    }
    // Hold Connection
    set_conn = (ctx.connections.getEntry(conn_id) orelse {
        ctx.connections.mutex.unlock();
        return error.ConnectionNotFound;
    }).value_ptr;
    set_conn.state = .conn;
    log.info("{s}: {s} '{s}'", .{ conn_if.name, set_conn.state, conn.ssid });
    ctx.connections.mutex.unlock();
    var no_carrier_count: usize = 0;
    while (
        active.load(.acquire) and
        conn_active.load(.acquire) and
        no_carrier_count < err_max
    ) {
        const get_if = if_ctx.interfaces.get(if_index) orelse break;
        if (get_if.usage == .unavailable) break;
        const get_link = (if_ctx.links.get(conn_if.index) orelse continue).link;
        const carrier = get_link.CARRIER orelse continue;
        if (carrier == 0) no_carrier_count += 1
        else no_carrier_count = 0;
        time.sleep(interval.*);
    }
    //log.debug(
    //    \\Connection End:
    //    \\- NCC {d}
    //    \\- Active: {}
    //    \\- Conn Active: {}
    //    \\
    //    , .{
    //        no_carrier_count,
    //        active.load(.acquire),
    //        conn_active.load(.acquire),
    //    }
    //);
    //time.sleep(3 * time.ns_per_s);
}

/// Use the provided Basic Service Set (`bss`) to Calculate a Delay, in milliseconds, between WiFi Connection Operations to make the connection process more resilient.
fn calcOpDelay(bss: nl._80211.BasicServiceSet) u64 {
    // Initial delay based on RSSI
    var delay: u64 = rssiDelay: {
        const rssi = @divFloor(bss.SIGNAL_MBM orelse -10_000, 100);
        //if (rssi > -50) break :rssiDelay 30;
        if (rssi > -65) break :rssiDelay 40;
        if (rssi > -80) break :rssiDelay 80;
        if (rssi > -90) break :rssiDelay 160;
        break :rssiDelay 300;
    };
    // Adjust for unstable beacon interval
    const beacon_interval = bss.BEACON_INTERVAL orelse 100;
    if (beacon_interval > 105 or beacon_interval < 95)
        delay += 50;
    // Adjust for high frequency bands (5GHz, 6GHz)
    if (bss.FREQUENCY > 5000)
        delay += 20;
    return delay * time.ns_per_ms;
}

