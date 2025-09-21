//! Connection Tracking

const std = @import("std");
const atomic = std.atomic;
const crypto = std.crypto;
const P256 = crypto.ecc.P256;
const fmt = std.fmt;
const heap = std.heap;
const linux = std.os.linux;
const log = std.log.scoped(.connections);
const math = std.math;
const mem = std.mem;
const meta = std.meta;
const posix = std.posix;
const sort = std.sort;
const time = std.time;
const ArrayList = std.ArrayList;
const Io = std.Io;
const Thread = std.Thread;

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
const ThreadArrayList = utils.ThreadArrayList;
const ThreadHashMap = utils.ThreadHashMap;



/// Config for All Connections.
pub const GlobalConfig = struct {
    /// The Max Age, in milliseconds, of a Network that's allowed for Connection attempts.
    max_network_age: usize = 60_000,
    /// The Max Age, in milliseconds, of an inactive Connection before it's dropped.
    max_inactive_age: usize = 30_000,
    /// The Max # of Retries that will be attempted on error before a Connection is dropped.
    max_retries: u8 = 3,
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
    /// Security "Type" of the Network.
    /// If this is left `null` it will be derived from the Network's Beacon Frames.
    security: ?nl._80211.SecurityType = null,
    /// Authentication "Type" of the Network.
    /// If this is left `null` it will be derived from the Network's Beacon Frames.
    auth: ?nl._80211.AuthType = null,
    /// DHCP Config.
    dhcp: ?proto.dhcp.LeaseConfig = null,
    /// Add a Default Route Gateway & DNS.
    add_gw: ?bool = null,
};

/// Status of a Connection
pub const Status = struct {
    bssid: [6]u8,
    conn_if: [6]u8,
    started: zeit.Instant,
    ended: ?zeit.Instant = null,
};

/// Connection Context
pub const Context = struct {
    /// Connection Candidates
    /// *Internal Use Only*
    _candidates: *ArrayList(Candidate),
    /// Thread State Maps for Connections
    _thread_state_maps: *ArrayList(*ThreadHashMap([]const u8, Connection.ThreadState)),
    /// Status of Active & Previous Connections.
    statuses: *ThreadArrayList(Status),
    timer: time.Timer,


    /// Initialize all Maps.
    pub fn init(core_ctx: *core.Core) !@This() {
        var self: @This() = undefined;
        self.statuses = core_ctx.alloc.create(ThreadArrayList(Status)) catch @panic("OOM");
        self.statuses.* = .empty;
        self._candidates = core_ctx.alloc.create(ArrayList(Candidate)) catch @panic("OOM");
        self._candidates.* = .empty;
        self._thread_state_maps = core_ctx.alloc.create(ArrayList(*ThreadHashMap([]const u8, Connection.ThreadState))) catch @panic("OOM");
        self._thread_state_maps.* = .empty;
        self.timer = try .start();
        const nl80211_info = nl._80211.ctrl_info orelse @panic("Netlink 802.11 (nl80211) not Initialized!");
        const nl80211_mlme = nl80211_info.MCAST_GROUPS.get("mlme") orelse @panic("Netlink 802.11 (nl80211) not Initialized!");
        try posix.setsockopt(
            core_ctx.nl80211_handler.nl_sock,
            posix.SOL.NETLINK,
            nl.NETLINK_OPT.ADD_MEMBERSHIP,
            mem.toBytes(nl80211_mlme)[0..],
        );
        return self;
    }

    /// Deinitialize all Maps.
    pub fn deinit(self: *@This(), alloc: mem.Allocator) void {
        self.statuses.deinit(alloc);
        alloc.destroy(self.statuses);
        self._candidates.deinit(alloc);
        alloc.destroy(self._candidates);
        for (self._thread_state_maps.items) |map| {
            map.deinit(alloc);
            alloc.destroy(map);
        }
        self._thread_state_maps.deinit(alloc);
        alloc.destroy(self._thread_state_maps);
    }

    /// Update Connections
    pub fn update(self: *@This(), core_ctx: *core.Core) !void {
        try self.scoreCandidates(core_ctx);
        //log.debug("Candidates: {d}", .{ self._candidates.items.len });
        const statuses = self.statuses.items();
        defer self.statuses.mutex.unlock();
        core_ctx.if_ctx.interfaces.mutex.lock();
        defer core_ctx.if_ctx.interfaces.mutex.unlock();
        var if_iter = core_ctx.if_ctx.interfaces.map.iterator();
        while (if_iter.next()) |conn_if_entry| {
            const conn_if = conn_if_entry.value_ptr;
            if (conn_if.usage != .connect) continue;
            conn_if.usage.connect.handle(core_ctx) catch |err| {
                switch (err) {
                    error.OSError => {
                        conn_if.penalty = conn_if.max_penalty;
                        log.warn("Potential issue with the Interface '{s}' or the Network '{s}'. Cooling off for '{d}'ms.", .{ conn_if.name, conn_if.usage.connect.ssid, conn_if.max_penalty });
                    },
                    error.NODEV,
                    error.BUSY,
                    => {
                        log.warn("The Interface '{s}' is in an unrecoverable state ('{t}'). Please try unplugging it for 5 seconds then plugging it back in.", .{ conn_if.name, err });
                        conn_if.usage.connect.deinit(core_ctx.alloc);
                        conn_if.usage = .{ .err = err };
                    },
                    else => {},
                }
            };
        }
        connLoop: for (self._candidates.items) |candidate| {
            const conn_if_entry = core_ctx.if_ctx.interfaces.map.getEntry(candidate.conn_if) orelse continue;
            const conn_if = conn_if_entry.value_ptr;
            if_iter = core_ctx.if_ctx.interfaces.map.iterator();
            while (if_iter.next()) |check_if_entry| {
                const check_if = check_if_entry.value_ptr;
                switch (check_if.usage) {
                    .connect => |conn| {
                        if (mem.eql(u8, conn.bssid[0..], candidate.bssid[0..])) continue :connLoop;
                    },
                    else => {},
                }
            }
            if (conn_if.usage != .available) continue;
            for (statuses) |status| {
                if (!mem.eql(u8, candidate.bssid[0..], status.bssid[0..])) continue;
                if (status.ended) |_| continue :connLoop;
            }
            //log.debug("Found Viable Connection: '{s}' | '{s}'", .{ candidate.network, conn_if.name });
            conn_if.usage = .{ .connect = try .start(core_ctx, candidate) };
        }
    }

    /// Score Candidate Networks
    fn scoreCandidates(self: *@This(), core_ctx: *core.Core) !void {
        //log.debug("Scoring Connections", .{});
        //defer log.debug("Scored {d} Connections.", .{ self._candidates.items.len });
        self._candidates.deinit(core_ctx.alloc);
        self._candidates.* = .empty;
        //log.debug("- Total Networks: {d} | Total Configs: {d}", .{ core_ctx.network_ctx.networks.count(), core_ctx.config.connect_configs.len });
        const max_age = core_ctx.config.global_connect_config.max_network_age;
        var nw_iter = core_ctx.network_ctx.networks.iterator();
        defer core_ctx.network_ctx.networks.mutex.unlock();
        while (nw_iter.next()) |network_entry| {
            const network = network_entry.value_ptr;
            const config = connConfig: {
                for (core_ctx.config.connect_configs) |conf| {
                    if (!mem.eql(u8, conf.ssid, network.ssid)) continue;
                    break :connConfig conf;
                }
                continue;
            };
            var net_meta_iter = network.net_meta.iterator();
            defer network.net_meta.mutex.unlock();
            while (net_meta_iter.next()) |net_meta_entry| {
                const net_meta = net_meta_entry.value_ptr;
                checkIF: {
                    if (config.if_names.len == 0) break :checkIF;
                    for (config.if_names) |if_name| {
                        if (mem.eql(u8, net_meta.seen_by, if_name)) break :checkIF;
                    }
                    else continue;
                }
                //log.debug("Network '{s}':", .{ network.ssid });
                const time_score: u8 = timeScore: {
                    const now = (try zeit.instant(.{})).milliTimestamp();
                    const last_seen = net_meta.last_seen.milliTimestamp();
                    const age = @min(now - last_seen, max_age);
                    //log.debug("- Age: {d}ms", .{ age });
                    //const percentage: u8 = @intFromFloat(@as(f128, @floatFromInt(@divFloor(age, max_age) * 100)));
                    const percent: f16 = @as(f16, @floatFromInt(age)) / @as(f16, @floatFromInt(max_age)) * 100;
                    //log.debug("- Percent: {d}", .{ percent });
                    const diff = 100.0 - percent;
                    break :timeScore @intFromFloat(@min(diff * 0.5, 50));
                };
                //log.debug("- Time Score: {d}", .{ time_score });
                if (time_score == 0) continue;
                const sig_score: u8 = sigScore: {
                    const rxq = net_meta.calcRxQual();
                    if (rxq > 0) break :sigScore @intFromFloat(@as(f16, @floatFromInt(rxq)) * 0.5);
                    //log.debug("- RSSI: {d} dBm", .{ net_meta.rssi });
                    break :sigScore @intFromFloat(@as(f16, @floatFromInt(100 +| net_meta.rssi)) * 0.25);
                };
                //log.debug("- Signal Score: {d}", .{ sig_score });
                const candidate: Candidate = .{
                    .score = @min(100, time_score +| sig_score),
                    .bssid = network.bssid,
                    .conn_if = net_meta_entry.key_ptr.*,
                    .channel = network.channel,
                    .config = config,
                    .network = network.bssid,
                };
                self._candidates.append(
                    core_ctx.alloc,
                    candidate,
                ) catch @panic("OOM");
                //log.debug("Network '{s}' Score:\n{s}", .{ network.ssid, candidate });
            }
        }
        sort.block(
            Candidate,
            self._candidates.items,
            {},
            Candidate.greaterThan,
        );
    }
};

/// Connection Candidate
const Candidate = struct {
    score: u8,
    bssid: [6]u8,
    conn_if: [6]u8,
    channel: u32,
    config: Config,
    network: [6]u8,

    pub fn lessThan(_: void, a: @This(), b: @This()) bool {
        return a.score < b.score;
    }

    pub fn greaterThan(_: void, a: @This(), b: @This()) bool {
        return a.score > b.score;
    }

    pub fn format(self: @This(), writer: *Io.Writer) Io.Writer.Error!void {
        try writer.print(
            \\- Score:   {d}
            \\- BSSID:   {f}
            \\- Conn IF: {f}
            \\- Channel: {d}
            \\
            , .{
                self.score,
                MACF{ .bytes = self.bssid[0..] },
                MACF{ .bytes = self.conn_if[0..] },
                self.channel,
            },
        );
    }
};

/// Connection Info
pub const Connection = struct {
    // Configurable
    if_mac: [6]u8,
    bssid: [6]u8,
    ssid: []const u8,
    freq: u32,
    passphrase: []const u8,
    security: nl._80211.SecurityType,
    auth: nl._80211.AuthType,
    dhcp_conf: ?proto.dhcp.LeaseConfig = null,
    add_gw: bool = false,
    max_retries: u8,
    max_inactive_age: usize,
    thread_timeout: usize = 9_000,
    // Derived
    _if_index: ?i32 = null,
    _psk: [32]u8 = @splat(0),
    _scan_result: nl._80211.ScanResults,
    _rsn_bytes: []const u8 = &.{},
    _eapol_keys: ?nl._80211.EAPoLKeys = null,
    _dhcp_info: ?dhcp.Info = null,
    _station: ?nl._80211.Station = null,
    // State
    _state: State = .setup,
    _retries: u8 = 0,
    _nl_state: core.AsyncState = .ready,
    _nl80211_req_ctx: nl.io.RequestContext,
    _rtnetlink_req_ctx: nl.io.RequestContext,
    _thread_states: *ThreadHashMap([]const u8, ThreadState),

    /// The Current State of a Connection.
    pub const State = union(enum) {
        /// Setup the Connection
        setup,
        ///// Searching f/ the Network
        //search,
        /// Authenticating to the Network
        auth: struct {
            auth_timer: time.Timer,
            sae_state: enum {
                setup,
                commit,
                confirm,
            } = .setup,
            sae_ctx: ?sae.Context = null,
            sae_peer: ?sae.Commit = null,
        },
        /// Associating to the Network
        assoc,
        /// Handling the 4 Way Handshake w/ the Router
        eapol: u8,
        /// Requesting Routing Info via DHCP
        dhcp: enum { wait, ip, gw, dns },
        /// Connected to the Network
        conn: enum { init, running },
        /// Disconnected from the Network
        disconn: enum {
            start,
            //thread,
            dhcp,
            ip,
            disassoc,
            deauth,
            disc,
        },
        /// Error during Connnection
        err,

        pub fn format(self: @This(), writer: *Io.Writer) Io.Writer.Error!void {
            try writer.print(
                "{s}",
                .{
                    switch (self) {
                        //.search => "Searching for the Network",
                        .setup => "Setting up the Interface for Connection",
                        .auth => "Authenticating to the Network",
                        .assoc => "Associating to the Network",
                        .eapol => "Handling the 4 Way Handshake w/ the Router",
                        .dhcp => "Requesting Routing Info via DHCP",
                        .conn => "Connected to the Network",
                        .disc => "Disconnected from the Network",
                        .err => "Error during Connection",
                    }
                },
            );
        }
    };

    /// Current Thread State for a Connection.
    const ThreadState = union(enum) {
        ready,
        starting,
        working: struct { timer: time.Timer, id: u32 },
        done,
        err: anyerror,
    };

    /// Start a new Connection
    pub fn start(core_ctx: *core.Core, candidate: Candidate) !@This() {
        defer core_ctx.network_ctx.networks.mutex.unlock();
        const network_entry = core_ctx.network_ctx.networks.getEntry(candidate.network) orelse return error.NetworkNotFound;
        const network = network_entry.value_ptr;
        const security = candidate.config.security orelse network.security;
        const auth = candidate.config.auth orelse network.auth;
        const psk = switch (security) {
            .wpa2 => wpa.genKey(security, candidate.config.ssid, candidate.config.passphrase) catch |err| {
                log.err("Key Generation Error: {t}", .{ err });
                return error.UnableToGenKey;
            },
            .open, .wpa3t, .wpa3 => @as([32]u8, @splat(0)),
            else => {
                log.err("Could not connect to '{s}' due to unimplemented Security Type '{t}'", .{ network.ssid, network.security });
                return error.UnimplementedSecurityType;
            },
        };
        const scan_result = try nl.parse.clone(core_ctx.alloc, nl._80211.ScanResults, network.scan_result);
        errdefer nl.parse.freeBytes(core_ctx.alloc, nl._80211.ScanResults, scan_result);
        const rsn_bytes = rsnBytes: {
            const bss = scan_result.BSS orelse return error.MissingBSS;
            const ies = bss.INFORMATION_ELEMENTS orelse return error.MissingIEs;
            var rsn = ies.RSN orelse return error.MissingRSN;
            if (security == .wpa3t) {
                rsn.AKM_SUITES = &.{ .{ .OUI = [_]u8{ 0x00, 0x0F, 0xAC }, .TYPE = 0x08 } };
                rsn.AKM_SUITE_COUNT = 1;
            }
            const bytes = try nl.parse.toBytes(core_ctx.alloc, nl._80211.InformationElements.RobustSecurityNetwork, rsn);
            var buf = ArrayList(u8).fromOwnedSlice(bytes);
            errdefer buf.deinit(core_ctx.alloc);
            try buf.insert(core_ctx.alloc, 0, @intCast(bytes.len));
            try buf.insert(core_ctx.alloc, 0, c(nl._80211.IE).RSN);
            break :rsnBytes try buf.toOwnedSlice(core_ctx.alloc);
        };
        const ssid = core_ctx.alloc.dupe(u8, candidate.config.ssid) catch @panic("OOM");
        errdefer core_ctx.alloc.free(ssid);
        const thread_states: *ThreadHashMap([]const u8, ThreadState) = core_ctx.alloc.create(ThreadHashMap([]const u8, ThreadState)) catch @panic("OOM");
        thread_states.* = .empty;
        core_ctx.conn_ctx._thread_state_maps.append(core_ctx.alloc, thread_states) catch @panic("OOM");
        const self: @This() = .{
            .if_mac = candidate.conn_if,
            .bssid = candidate.bssid,
            .ssid = ssid,
            .freq = network.freq,
            .passphrase = candidate.config.passphrase,
            .security = security,
            .auth = auth,
            .dhcp_conf = candidate.config.dhcp orelse core_ctx.config.global_connect_config.dhcp,
            .add_gw = candidate.config.add_gw orelse core_ctx.config.global_connect_config.add_gw,
            .max_retries = core_ctx.config.global_connect_config.max_retries,
            .max_inactive_age = core_ctx.config.global_connect_config.max_inactive_age,
            ._psk = psk,
            ._scan_result = scan_result,
            ._rsn_bytes = rsn_bytes,
            ._nl80211_req_ctx = try .init(.{ .handler = .{ .handler = core_ctx.nl80211_handler } }),
            ._rtnetlink_req_ctx = try .init(.{ .handler = .{ .handler = core_ctx.rtnetlink_handler } }),
            ._thread_states = thread_states,
        };
        self._thread_states.mutex.lock();
        defer self._thread_states.mutex.unlock();
        self._thread_states.map.put(core_ctx.alloc, "eapol", .ready) catch @panic("OOM");
        self._thread_states.map.put(core_ctx.alloc, "dhcp", .ready) catch @panic("OOM");
        self._thread_states.map.put(core_ctx.alloc, "dns", .ready) catch @panic("OOM");
        self._thread_states.map.put(core_ctx.alloc, "rel_dhcp", .ready) catch @panic("OOM");
        try self._nl80211_req_ctx.handler.?.trackCommand(c(nl._80211.CMD).AUTHENTICATE);
        log.debug("Starting connection to '{s}' w/ '{f}'...", .{ candidate.config.ssid, MACF{ .bytes = candidate.conn_if[0..] } });
        return self;
    }

    /// Stop this Connection
    pub fn stop(self: *@This(), core_ctx: *core.Core) void {
        //log.info("(WIP) Connection to '{s}' stopped.", .{ self.ssid });
        stop: switch (self._state) {
            .conn => {
                self._state = .{ .disconn = .start };
                continue :stop self._state;
            },
            .disconn => {
                for (0..10) |_| {
                    self.handle(core_ctx) catch break;
                    Thread.sleep(10 * time.ns_per_ms);
                }
            },
            else => self.deinit(core_ctx.alloc),
        }
    }
    
    pub fn deinit (self: *const @This(), alloc: mem.Allocator) void {
        log.debug("Deinitialized Connection '{s}'", .{ self.ssid });
        alloc.free(self.ssid);
        if (self._station) |sta|
            nl.parse.freeBytes(alloc, nl._80211.Station, sta);
        nl.parse.freeBytes(alloc, nl._80211.ScanResults, self._scan_result);
        if (self._rsn_bytes.len > 0) alloc.free(self._rsn_bytes);
    }

    /// Handle this Connection
    /// TODO: Implement all Security Protocols/Types
    pub fn handle(self: *@This(), core_ctx: *core.Core) !void {
        if (self._retries >= self.max_retries) {
            self._state = .{ .disconn = .start };
            log.warn("Max Retries Reached for Connection '{s}'", .{ self.ssid });
            //return error.MaxRetriesReached;
        }
        //defer core_ctx.if_ctx.interfaces.mutex.unlock();
        const conn_if_entry = core_ctx.if_ctx.interfaces.map.getEntry(self.if_mac) orelse return error.InterfaceNotFound;
        const conn_if = conn_if_entry.value_ptr;
        if (conn_if.usage != .connect) {
            //self.deinit(core_ctx.alloc);
            return error.InterfaceInUse;
        }
        if (conn_if.checkPenalty() and self._state != .disconn) return error.InterfaceUnderPenalty;
        errdefer {
            self._retries +%= 1;
            self._nl_state = .ready;
            //self._thread_state = .ready;
            conn_if.addPenalty();
        }
        if (self._if_index) |idx| idxCheck: {
            if (conn_if.index == idx) break :idxCheck;
            log.warn("The Interface '{s}' was interrupted during the Connection to '{s}'.", .{ conn_if.name, self.ssid });
            self.deinit(core_ctx.alloc);
            conn_if.usage = .available;
            return error.InterfaceInterrupted;
        }
        else {
            self._if_index = conn_if.index;
            log.info("Connecting to '{s}' w/ '{s}'...", .{ self.ssid, conn_if.name });
        }
        state: switch (self._state) {
            .setup => {
                nl_state: switch (self._nl_state) {
                    .ready, .request => {
                        self._nl_state = .ready;
                        //self._thread_state = .ready;
                        conn_if.resetPenalty();
                        self._nl80211_req_ctx.nextSeqID();
                        try nl._80211.requestRegisterFrames(
                            core_ctx.alloc,
                            &self._nl80211_req_ctx,
                            conn_if.index,
                            &.{
                                0x00d0,
                                0x00d0,
                                0x00d0,
                                0x00d0,
                                0x00d0,
                                0x00b0,
                            },
                            &.{
                                &.{ 0x00, 0x03 },
                                &.{ 0x00, 0x05 },
                                &.{ 0x00, 0x06 },
                                &.{ 0x00, 0x08 },
                                &.{ 0x00, 0x0c },
                                &.{ 0xb0, 0x00, 0x03, 0x00 },
                            },
                        );
                        self._nl_state = .await_response;
                        continue :nl_state self._nl_state;
                    },
                    .await_response => {
                        if (!self._nl80211_req_ctx.checkResponse()) return;
                        self._nl_state = .parse;
                        continue :nl_state self._nl_state;
                    },
                    .parse => {
                        const setup_resp = self._nl80211_req_ctx.getResponse().?;
                        if (setup_resp) |resp_data| //
                            core_ctx.alloc.free(resp_data)
                        else |err| regFrameErr: {
                            if (err == error.ALREADY) break :regFrameErr;
                            log.warn("Could not set up Interface '{s}' for a Connection: {t}", .{ conn_if.name, err });
                            return err;
                        }
                        log.debug("Finished setup for Connection: {s} | {s}", .{ self.ssid, conn_if.name });
                        self._nl_state = .request;
                        self._state = .{ .auth = .{ .auth_timer = try .start() } };
                        continue :state self._state;
                    },
                }
            },
            .auth => |*auth_ctx| {
                errdefer {
                    auth_ctx.auth_timer.reset();
                }
                // Authenticate
                switch (self.security) {
                    .open, .wpa2 => {
                        nlState: switch (self._nl_state) {
                            .ready, .request => {
                                log.debug("Connection {s} | {s}: Authenticating ({t})", .{ self.ssid, conn_if.name, self.security });
                                self._nl80211_req_ctx.nextSeqID();
                                try nl._80211.requestAuthenticate(
                                    core_ctx.alloc,
                                    &self._nl80211_req_ctx,
                                    conn_if.index,
                                    self.ssid,
                                    self._scan_result,
                                    null,
                                );
                                self._nl_state = .await_response;
                                continue :nlState self._nl_state;
                            },
                            .await_response => {
                                //log.debug("Awaiting Auth Response...", .{});
                                if (@divFloor(auth_ctx.auth_timer.read(), time.ns_per_ms) > 1_000) {
                                    log.warn("Connection {s} | {s}: Failed Authentication (Timed Out)", .{ self.ssid, conn_if.name });
                                    return error.AuthTimeout;
                                }
                                if (!self._nl80211_req_ctx.handler.?.checkCmdResponses(c(nl._80211.CMD).AUTHENTICATE)) return;
                                self._nl_state = .parse;
                                continue :nlState self._nl_state;
                            },
                            .parse => {
                                //log.debug("Received Auth Response...", .{});
                                const auth_resps = try self._nl80211_req_ctx.handler.?.getCmdResponses(c(nl._80211.CMD).AUTHENTICATE);
                                defer core_ctx.alloc.free(auth_resps);
                                if (auth_resps.len == 0) {
                                    log.warn("Connection {s} | {s}: Failed Authentication (No Response)", .{ self.ssid, conn_if.name });
                                    return error.NoResponse;
                                }
                                var valid = false;
                                var auth_err: anyerror = undefined;
                                for (auth_resps) |auth_resp| {
                                    if (auth_resp) |resp_data| {
                                        core_ctx.alloc.free(resp_data);
                                        valid = true;
                                    } //
                                    else |err| auth_err = err;
                                }
                                if (!valid) {
                                    log.warn("Connection {s} | {s}: Failed Authentication ({t})", .{ self.ssid, conn_if.name, auth_err });
                                    return auth_err;
                                }
                                log.debug("Connection {s} | {s}: Authenticated ({t})", .{ self.ssid, conn_if.name, self.security });
                                self._nl_state = .ready;
                                self._state = .assoc;
                                continue :state self._state;
                            },
                        }
                    },
                    .wpa3t, .wpa3 => {
                        errdefer {
                            auth_ctx.sae_state = .setup;
                        }
                        saeState: switch (auth_ctx.sae_state) {
                            .setup => {
                                log.debug("Connection {s} | {s}: Authenticating ({t})", .{ self.ssid, conn_if.name, self.security });
                                auth_ctx.sae_ctx = try sae.genCommit(self.passphrase, self.bssid, conn_if.mac);
                                auth_ctx.sae_state = .commit;
                                continue :saeState auth_ctx.sae_state;
                            },
                            .commit => {
                                nlState: switch (self._nl_state) {
                                    .ready, .request => {
                                        self._nl80211_req_ctx.nextSeqID();
                                        const sae_commit: [102]u8 =
                                            // Commit
                                            mem.toBytes(@as(u32, 1)) ++
                                            // Group
                                            mem.toBytes(@as(u16, 19)) ++
                                            auth_ctx.sae_ctx.?.commit.scalar ++
                                            auth_ctx.sae_ctx.?.commit.element.x.toBytes(.big) ++
                                            auth_ctx.sae_ctx.?.commit.element.y.toBytes(.big);
                                        log.debug("SAE Commit Data:{f}\n", .{ HexF{ .bytes = sae_commit[0..] } });
                                        log.debug("WPA3 Auth SAE Commit...", .{});
                                        try nl._80211.requestAuthenticate(
                                            core_ctx.alloc,
                                            &self._nl80211_req_ctx,
                                            conn_if.index,
                                            self.ssid,
                                            self._scan_result,
                                            sae_commit[0..],
                                        );
                                        self._nl_state = .await_response;
                                        continue :nlState self._nl_state;
                                    },
                                    .await_response => {
                                        if (@divFloor(auth_ctx.auth_timer.read(), time.ns_per_ms) > 1_000) {
                                            log.warn("Connection {s} | {s}: Failed Authentication (Timed Out)", .{ self.ssid, conn_if.name });
                                            return error.AuthTimeout;
                                        }
                                        if (!self._nl80211_req_ctx.handler.?.checkCmdResponses(c(nl._80211.CMD).AUTHENTICATE)) return;
                                        self._nl_state = .parse;
                                        continue :nlState self._nl_state;
                                    },
                                    .parse => {
                                        const commit_resps = try self._nl80211_req_ctx.handler.?.getCmdResponses(c(nl._80211.CMD).AUTHENTICATE);
                                        defer core_ctx.alloc.free(commit_resps);
                                        if (commit_resps.len == 0) {
                                            log.warn("Connection {s} | {s}: Failed Authentication (No Response)", .{ self.ssid, conn_if.name });
                                            return error.NoResponse;
                                        }
                                        const resp_data = try commit_resps[0];
                                        defer core_ctx.alloc.free(resp_data);
                                        const sae_commit_resp_data = try nl._80211.handleAuthResponseBuf(core_ctx.alloc, resp_data);
                                        defer {
                                            for (sae_commit_resp_data) |scr_data|
                                                nl.parse.freeBytes(core_ctx.alloc, nl._80211.AuthResponse, scr_data);
                                            core_ctx.alloc.free(sae_commit_resp_data);
                                        }
                                        if (sae_commit_resp_data.len == 0) {
                                            log.warn("Issue handling WPA3 SAE Commit response data: EmptyCommitResponse", .{});
                                            return error.EmptyCommitResponse;
                                        }
                                        log.debug("SAE Commit Response Data: {d}B{f}", .{ sae_commit_resp_data[0].FRAME.len, HexF{ .bytes = sae_commit_resp_data[0].FRAME } });
                                        if (sae_commit_resp_data[0].FRAME.len < 96) {
                                            log.warn("Issue handling WPA3 SAE Commit response data: InvalidCommitResponse (Len = {d}B)", .{ sae_commit_resp_data[0].FRAME.len });
                                            return error.InvalidCommitResponse;
                                        }
                                        const sae_commit_resp = sae_commit_resp_data[0].FRAME[32..];
                                        auth_ctx.sae_peer = .{
                                            .scalar = sae_commit_resp[0..32].*,
                                            .element = P256.fromSerializedAffineCoordinates(sae_commit_resp[32..64].*, sae_commit_resp[64..96].*, .big) catch |err| {
                                                log.warn("Issue handling WPA3 SAE Commit response Peer: {t}", .{ err });
                                                return err;
                                            },
                                        };
                                        self._nl_state = .ready;
                                        auth_ctx.sae_state = .confirm;
                                        continue :saeState auth_ctx.sae_state;
                                    },
                                }
                            },
                            .confirm => {
                                nlState: switch (self._nl_state) {
                                    .ready, .request => {
                                        self._nl80211_req_ctx.nextSeqID();
                                        sae.genConfirm(&auth_ctx.sae_ctx.?, auth_ctx.sae_peer.?) catch |err| {
                                            log.warn("Issue generating WPA3 SAE Confirm data: {t}", .{ err });
                                            return err;
                                        };
                                        log.debug("WPA3 Auth SAE Confirm...", .{});
                                        const sae_confirm: [38]u8 =
                                            // Confirm
                                            mem.toBytes(@as(u32, 2)) ++
                                            // Send Confirm
                                            auth_ctx.sae_ctx.?.send_confirm ++
                                            auth_ctx.sae_ctx.?.confirm.?[0..32].*;
                                        try nl._80211.requestAuthenticate(
                                            core_ctx.alloc,
                                            &self._nl80211_req_ctx,
                                            conn_if.index,
                                            self.ssid,
                                            self._scan_result,
                                            sae_confirm[0..],
                                        );
                                        self._nl_state = .await_response;
                                        continue :nlState self._nl_state;
                                    },
                                    .await_response => {
                                        if (@divFloor(auth_ctx.auth_timer.read(), time.ns_per_ms) > 1_000) {
                                            log.warn("Connection {s} | {s}: Failed Authentication (Timed Out)", .{ self.ssid, conn_if.name });
                                            return error.AuthTimeout;
                                        }
                                        if (!self._nl80211_req_ctx.handler.?.checkCmdResponses(c(nl._80211.CMD).AUTHENTICATE)) return;
                                        self._nl_state = .parse;
                                        continue :nlState self._nl_state;
                                    },
                                    .parse => {
                                        const confirm_resps = try self._nl80211_req_ctx.handler.?.getCmdResponses(c(nl._80211.CMD).AUTHENTICATE);
                                        defer core_ctx.alloc.free(confirm_resps);
                                        if (confirm_resps.len == 0) {
                                            log.warn("Connection {s} | {s}: Failed Authentication (No Response)", .{ self.ssid, conn_if.name });
                                            return error.NoResponse;
                                        }
                                        const resp_data = try confirm_resps[0];
                                        defer core_ctx.alloc.free(resp_data);
                                        const sae_confirm_resp_data = try nl._80211.handleAuthResponseBuf(core_ctx.alloc, resp_data);
                                        defer {
                                            for (sae_confirm_resp_data) |scr_data|
                                                nl.parse.freeBytes(core_ctx.alloc, nl._80211.AuthResponse, scr_data);
                                            core_ctx.alloc.free(sae_confirm_resp_data);
                                        }
                                        log.debug("SAE Confirm Response Data: {d}B{f}", .{ sae_confirm_resp_data[0].FRAME.len, HexF{ .bytes = sae_confirm_resp_data[0].FRAME } });
                                        const resp_type: u16 = mem.readInt(u16, sae_confirm_resp_data[0].FRAME[26..28], .little);
                                        if (resp_type != 2) {
                                            log.warn("Issue handling WPA3 SAE Confirm response data: Non-Confirm Response ({d})", .{ resp_type });
                                            return error.NonConfirmResponse;
                                        }
                                        const resp_code: u16 = mem.readInt(u16, sae_confirm_resp_data[0].FRAME[28..30], .little);
                                        if (resp_code != 0) {
                                            log.warn("Issue handling WPA3 SAE Confirm response data: Confirm Response Error ({X:0>4})", .{ resp_code });
                                            return error.ConfirmResponseError;
                                        }
                                        const peer_ctx: sae.Context = .{
                                            .kck = auth_ctx.sae_ctx.?.kck,
                                            .send_confirm = sae_confirm_resp_data[0].FRAME[30..32].*,
                                            .confirm = sae_confirm_resp_data[0].FRAME[32..64].*,
                                            .commit = auth_ctx.sae_peer.?,
                                            .pwe = P256.basePoint,
                                            .private = @splat(0),
                                        }; 
                                        sae.checkConfirm(peer_ctx.confirm.?, auth_ctx.sae_ctx.?.commit, peer_ctx) catch {
                                            log.warn("Issue handling WPA3 SAE Confirm response: Confirm Token Verification Mismatch", .{});
                                            return error.ConfirmResponseError;
                                        };
                                        self._psk = auth_ctx.sae_ctx.?.pmk.?;
                                        log.debug("WPA3 Auth SAE Confirm done.", .{});
                                        self._nl_state = .ready;
                                        self._state = .assoc;
                                        continue :state self._state;
                                    }
                                }
                            },
                        }
                    },
                    else => |sec_proto| {
                        log.err("The Security Protocol/Type '{t}' is not implemented.", .{ sec_proto });
                        self._state = .{ .disconn = .start };
                        return error.UnimplementedSecurityType;
                    },
                }
            },
            .assoc => {
                // Associate
                log.debug("Connection {s} | {s}: Associating ({t})", .{ self.ssid, conn_if.name, self.security });
                switch (self.security) {
                    .open, .wpa2, .wpa3t, .wpa3 => {
                        nlState: switch (self._nl_state) {
                            .ready, .request => {
                                self._nl80211_req_ctx.nextSeqID();
                                totalFreqs: {
                                    var total_freqs: usize = 0;
                                    defer log.debug("Total Freqs: {d}", .{ total_freqs });
                                    const bands = conn_if.wiphy.WIPHY_BANDS orelse break :totalFreqs;
                                    for (bands) |band| {
                                        const freqs = band.FREQS orelse continue;
                                        total_freqs += freqs.len;
                                    }
                                }
                                nl._80211.requestAssociate(
                                    core_ctx.alloc,
                                    &self._nl80211_req_ctx,
                                    conn_if.index,
                                    conn_if.wiphy,
                                    self.ssid,
                                    self._scan_result,
                                ) catch |err| {
                                    log.warn("Connection {s} | {s}: Association Error: {t}", .{ self.ssid, conn_if.name, err });
                                    switch (err) {
                                        //error.MissingOperatingClasses => self._retries = self.max_retries,
                                        else => {},
                                    }
                                    return err;
                                };
                                self._nl_state = .await_response;
                                continue :nlState self._nl_state;
                            },
                            .await_response => {
                                if (!self._nl80211_req_ctx.checkResponse()) return;
                                self._nl_state = .parse;
                                continue :nlState self._nl_state;
                            },
                            .parse => {
                                errdefer {
                                    self._state = .{ .auth = .{ .auth_timer = time.Timer.start() catch @panic("Time Issue") } };
                                }
                                if (self._nl80211_req_ctx.getResponse()) |assoc_resp| {
                                    if (assoc_resp) |resp_data| {
                                        core_ctx.alloc.free(resp_data);
                                        log.debug("Connection {s} | {s}: Associated ({t})", .{ self.ssid, conn_if.name, self.security });
                                        self._nl_state = .ready;
                                        self._state = .{ .eapol = 0 };
                                        continue :state self._state;
                                    }
                                    else |err| {
                                        log.warn("Connection {s} | {s}: Association Error: {t}", .{ self.ssid, conn_if.name, err });
                                        log.warn("Could not Associate to '{s}': {t}", .{ self.ssid, err });
                                        return err;
                                    }
                                }
                            },
                        }
                    },
                    else => |sec_proto| {
                        log.err("The Security Protocol/Type '{t}' is not implemented.", .{ sec_proto });
                        return error.UnimplementedSecurityType;
                    },
                }
            },
            .eapol => |*key_idx| {
                self._thread_states.mutex.lock();
                defer self._thread_states.mutex.unlock();
                const eapol_state = self._thread_states.map.getEntry("eapol").?.value_ptr;
                eapol: switch (eapol_state.*) {
                    .ready => {
                        // EAPoL
                        switch (self.security) {
                            .wpa2, .wpa3t, .wpa3 => {
                                log.debug("Connection {s} | {s}: Handling EAPoL ({t})", .{ self.ssid, conn_if.name, self.security });
                                eapol_state.* = .starting;
                                const eapol_thread = try Thread.spawn(
                                    .{},
                                    handle4WHS,
                                    .{
                                        self._thread_states,
                                        &self._eapol_keys,
                                        conn_if.index,
                                        self._psk,
                                        self._rsn_bytes,
                                        self.security,
                                    },
                                );
                                eapol_thread.detach();
                                continue :eapol eapol_state.*;
                            },
                            .open => {},
                            else => return error.UnsupportedSecurityType,
                        }
                    },
                    .starting => {},
                    .working => |*work| working: {
                        if (@divFloor(work.timer.read(), time.ns_per_ms) < self.thread_timeout) break :working;
                        eapol_state.* = .ready;
                        return error.EAPoLThreadTimeout;
                    },
                    .done => {
                        nlState: switch (self._nl_state) {
                            .ready, .request => {
                                self._nl80211_req_ctx.nextSeqID();
                                const key,
                                const bssid,
                                const seq = keyData: {
                                    if (key_idx.* == 0) break :keyData .{
                                        self._eapol_keys.?.ptk[32..],
                                        self._scan_result.BSS.?.BSSID,
                                        null,
                                    };
                                    break :keyData .{ 
                                        self._eapol_keys.?.gtk[0..],
                                        null,
                                        [_]u8{ 2, 0, 0, 0, 0, 0 },
                                    };
                                };
                                try nl._80211.requestAddKey(
                                    core_ctx.alloc,
                                    &self._nl80211_req_ctx,
                                    conn_if.index,
                                    //if (idx == 0) self._scan_result.BSS.?.BSSID else null,
                                    bssid,
                                    .{
                                        .DATA = key.*,
                                        .CIPHER = c(nl._80211.CIPHER_SUITES).CCMP,
                                        //.SEQ = if (idx == 0) null else .{ 2 } ++ .{ 0 } ** 5,
                                        .SEQ = seq,
                                        //.IDX = idx,
                                        .IDX = key_idx.*,
                                    },
                                );
                                self._nl_state = .await_response;
                            },
                            .await_response => {
                                if (!self._nl80211_req_ctx.checkResponse()) return;
                                self._nl_state = .parse;
                                continue :nlState self._nl_state;
                            },
                            .parse => {
                                const add_key_resp = self._nl80211_req_ctx.getResponse().?;
                                const add_key_resp_data = try add_key_resp;
                                defer core_ctx.alloc.free(add_key_resp_data);
                                self._nl_state = .ready;
                                if (key_idx.* == 0) {
                                    key_idx.* = 1;
                                    continue :nlState self._nl_state;
                                }
                                eapol_state.* = .ready;
                                log.debug("Connection {s} | {s}: Finished EAPoL ({t})", .{ self.ssid, conn_if.name, self.security });
                                self._state = .{ .dhcp = .ip };
                                continue :state self._state;
                            },

                        }
                    },
                    .err => |err| {
                        return err;
                    }
                }
            },
            .dhcp => |*dhcp_setup| {
                // DHCP
                dhcpSetup: switch (dhcp_setup.*) {
                    .wait => wait: {
                        var if_iter = core_ctx.if_ctx.interfaces.map.iterator();
                        while (if_iter.next()) |other_if_entry| {
                            if (mem.eql(u8, other_if_entry.key_ptr[0..], conn_if.og_mac[0..])) continue;
                            const other_if = other_if_entry.value_ptr;
                            switch (other_if.usage) {
                                .connect => |o_conn| {
                                    switch (o_conn._state) {
                                        .dhcp => |o_dhcp| {
                                            if (o_dhcp != .wait) break :wait;
                                        },
                                        else => {},
                                    }
                                },
                                else => {},
                            }
                        }
                        dhcp_setup.* = .ip;
                        continue :dhcpSetup dhcp_setup.*;
                    },
                    .ip => {
                        self._thread_states.mutex.lock();
                        defer self._thread_states.mutex.unlock();
                        const dhcp_state = self._thread_states.map.getEntry("dhcp").?.value_ptr;
                        dhcp: switch (dhcp_state.*) {
                            .ready => {
                                var dhcp_conf = self.dhcp_conf orelse {
                                    self._state = .{ .conn = .init };
                                    continue :state self._state;
                                };
                                log.debug("Connection {s} | {s}: Handling DHCP ({t})", .{ self.ssid, conn_if.name, self.security });
                                if (core_ctx.config.profile.mask) |pro_mask| //
                                    dhcp_conf.hostname = pro_mask.hostname;
                                dhcp_state.* = .starting;
                                const dhcp_thread = try Thread.spawn(
                                    .{},
                                    handleDHCP,
                                    .{
                                        self._thread_states,
                                        &self._dhcp_info,
                                        conn_if.name,
                                        conn_if.index,
                                        conn_if.mac,
                                        dhcp_conf,
                                    },
                                );
                                dhcp_thread.detach();
                                continue :dhcp dhcp_state.*;
                            },
                            .starting => {},
                            .working => |*work| working: {
                                if (@divFloor(work.timer.read(), time.ns_per_ms) < self.thread_timeout) break :working;
                                dhcp_state.* = .ready;
                                log.warn("Connection {s} | {s} DHCP Timed Out.", .{ self.ssid, conn_if.name });
                                return error.DHCPThreadTimeout;
                            },
                            .done => {
                                const dhcp_cidr = address.cidrFromSubnet(self._dhcp_info.?.subnet_mask);
                                nlState: switch (self._nl_state) {
                                    .ready, .request => {
                                        try nl.route.requestAddIP(
                                            core_ctx.alloc,
                                            &self._rtnetlink_req_ctx,
                                            conn_if.index,
                                            self._dhcp_info.?.assigned_ip,
                                            dhcp_cidr,
                                        );
                                        self._nl_state = .await_response;
                                        continue :nlState self._nl_state;
                                    },
                                    .await_response => {
                                        if (!self._rtnetlink_req_ctx.checkResponse()) return;
                                        self._nl_state = .parse;
                                        continue :nlState self._nl_state;
                                    },
                                    .parse => {
                                        defer self._nl_state = .ready;
                                        const add_ip_resp = self._rtnetlink_req_ctx.getResponse().?;
                                        const add_ip_data = add_ip_resp catch |err| {
                                            log.warn("Couldn't add IP '{f}/{d}' to Interface '({d}) {s}'", .{
                                                IPF{ .bytes = self._dhcp_info.?.assigned_ip[0..] },
                                                dhcp_cidr,
                                                conn_if.index,
                                                conn_if.name,
                                            });
                                            return err;
                                        };
                                        defer core_ctx.alloc.free(add_ip_data);
                                        log.info("Added IP '{f}/{d}' to ({d}) {s}", .{
                                            IPF{ .bytes = self._dhcp_info.?.assigned_ip[0..] },
                                            dhcp_cidr,
                                            conn_if.index,
                                            conn_if.name,
                                        });
                                        dhcp_state.* = .ready;
                                        if (self.add_gw) {
                                            self._state.dhcp = .gw;
                                            continue :dhcpSetup self._state.dhcp;
                                        }
                                        self._state = .{ .conn = .init };
                                        continue :state self._state;
                                    },
                                }
                            },
                            .err => |err| return err,
                        }
                    },
                    .gw => {
                        const dhcp_cidr = address.cidrFromSubnet(self._dhcp_info.?.subnet_mask);
                        nlState: switch (self._nl_state) {
                            .ready, .request => {
                                try nl.route.requestAddRoute(
                                    core_ctx.alloc,
                                    &self._rtnetlink_req_ctx,
                                    conn_if.index,
                                    address.IPv4.default.addr,
                                    .{
                                        //.cidr = address.IPv4.default.cidr,
                                        .cidr = dhcp_cidr,
                                        .gateway = self._dhcp_info.?.router,
                                    },
                                );
                                self._nl_state = .await_response;
                                continue :nlState self._nl_state;
                            },
                            .await_response => {
                                if (!self._rtnetlink_req_ctx.checkResponse()) return;
                                self._nl_state = .parse;
                                continue :nlState self._nl_state;
                            },
                            .parse => {
                                defer self._nl_state = .ready;
                                const add_gw_resp = self._rtnetlink_req_ctx.getResponse().?;
                                const add_gw_data = add_gw_resp catch |err| {
                                    log.warn("Couldn't add Default Gateway '{f}/{d}' to Interface '({d}) {s}':\nError: {s}", .{
                                        IPF{ .bytes = self._dhcp_info.?.router[0..] },
                                        dhcp_cidr,
                                        conn_if.index,
                                        conn_if.name,
                                        if (err == error.EXIST) "There's already a Default Gateway." //
                                        else @errorName(err),
                                    });
                                    if (err == error.EXIST) {
                                        dhcp_setup.* = .ip;
                                        self._state = .{ .conn = .init };
                                        continue :state self._state;
                                    }
                                    return err;
                                };
                                defer core_ctx.alloc.free(add_gw_data);
                                log.info("Added Default Gateway '{f}/{d}' to ({d}) {s}", .{
                                    IPF{ .bytes = self._dhcp_info.?.router[0..] },
                                    dhcp_cidr,
                                    conn_if.index,
                                    conn_if.name,
                                });
                                dhcp_setup.* = .dns;
                                continue :dhcpSetup dhcp_setup.*;
                            },
                        }
                    },
                    .dns => {
                        if (self._dhcp_info.?.dns_ips.len == 0) {
                            self._state = .{ .conn = .init };
                            continue :state self._state;
                        }
                        self._thread_states.mutex.lock();
                        defer self._thread_states.mutex.unlock();
                        const dns_state = self._thread_states.map.getEntry("dns").?.value_ptr;
                        errdefer {
                            dns_state.* = .ready;
                            self._state = .{ .conn = .init };
                        }
                        dns: switch (dns_state.*) {
                            .ready => {
                                var dns_ips_buf: [4][4]u8 = undefined;
                                const dns_ips: []const [4]u8 = dnsIPs: {
                                    //log.debug("DNS IPs: {s}", .{ if (dhcp_info.dns_ips[0]) |_| "" else "none" });
                                    var total_dns: usize = 0;
                                    defer log.debug("- Total DNS: {d}", .{ total_dns });
                                    dnsLoop: for (self._dhcp_info.?.dns_ips, 0..) |dns_ip, idx| {
                                        const next_dns = dns_ip orelse break :dnsIPs dns_ips_buf[0..total_dns];
                                        for (dns_ips_buf[0..idx]) |prev_dns| {
                                            if (mem.eql(u8, prev_dns[0..], next_dns[0..])) continue :dnsLoop;
                                        }
                                        //log.debug("- {f}", .{ IPF{ .bytes = next_dns[0..] } });
                                        dns_ips_buf[idx] = next_dns;
                                        total_dns += 1;
                                    }
                                    break :dnsIPs &.{};
                                };
                                dns_state.* = .starting;
                                const dns_thread = try Thread.spawn(
                                    .{},
                                    handleDNS,
                                    .{ self._thread_states, dns.DNSConfig{ .if_index = conn_if.index, .servers = dns_ips[0..1] } },
                                );
                                dns_thread.detach();
                                continue :dns dns_state.*;
                            },
                            .starting => {},
                            .working => |*work| working: {
                                if (@divFloor(work.timer.read(), time.ns_per_ms) < self.thread_timeout) break :working;
                                dns_state.* = .ready;
                                return error.DNSThreadTimeout;
                            },
                            .done => {
                                log.info("Added DNS '{f}' to ({d}) {s}", .{
                                    IPF{ .bytes = self._dhcp_info.?.dns_ips[0].?[0..] },
                                    conn_if.index,
                                    conn_if.name,
                                });
                                dns_state.* = .ready;
                                self._state = .{ .conn = .init };
                            },
                            .err => |err| {
                                log.err("Could not set DNS: {t}", .{ err });
                                return err;
                            },
                        }
                    },
                }
            },
            .conn => |*conn| {
                switch (conn.*) {
                    .init => {
                        log.info("Connected to '{s}' w/ '{s}'!", .{ self.ssid, conn_if.name });
                        self._retries = 0;
                        conn_if.subtractPenalty();
                        conn_if.penalty_time = null;
                        conn.* = .running;
                    },
                    .running => {
                        errdefer {
                            if (self._station) |sta| {
                                nl.parse.freeBytes(core_ctx.alloc, nl._80211.Station, sta);
                                self._station = null;
                            }
                            self._nl_state = .request;
                            //self._state = .{ .disconn = .start };
                        }
                        nlState: switch (self._nl_state) {
                            .ready, .request => {
                                //log.debug("Requesting Station Info...", .{});
                                self._nl80211_req_ctx.nextSeqID();
                                try nl._80211.requestStation(
                                    core_ctx.alloc,
                                    &self._nl80211_req_ctx,
                                    conn_if.index,
                                    self.bssid,
                                );
                                self._nl_state = .await_response;
                                continue :nlState self._nl_state;
                            },
                            .await_response => {
                                if (!self._nl80211_req_ctx.checkResponse()) return;
                                self._nl_state = .parse;
                                continue :nlState self._nl_state;
                            },
                            .parse => {
                                //log.debug("Received Station Info Response.", .{});
                                const station_resp = self._nl80211_req_ctx.getResponse() orelse error.NoStationInfo;
                                const station_data = station_resp catch |err| {
                                    log.warn("Could not update Station Status: {t}", .{ err });
                                    return err;
                                };
                                defer core_ctx.alloc.free(station_data);
                                //log.debug("Station Data Raw: {d}B", .{ station_data.len });
                                if (self._station) |sta|
                                    nl.parse.freeBytes(core_ctx.alloc, nl._80211.Station, sta);
                                const stations = try nl._80211.handleStationBuf(core_ctx.alloc, station_data);
                                defer {
                                    if (stations.len > 1) {
                                        for (stations[1..]) |sta| nl.parse.freeBytes(core_ctx.alloc, nl._80211.Station, sta);
                                    }
                                    core_ctx.alloc.free(stations);
                                }
                                if (stations.len > 0) {
                                    self._station = stations[0];
                                    const sta = self._station.?;
                                    const last_seen = sta.STA_INFO.INACTIVE_TIME orelse return error.IncompleteStation;
                                    if (last_seen >= self.max_inactive_age) {
                                        log.warn("The Connection to '{s}' has been inactive for too long.", .{ self.ssid });
                                        return error.InactiveConnection;
                                    }
                                    //log.debug(
                                    //    \\
                                    //    \\ SSID:      {s}
                                    //    \\ Interface: {s}
                                    //    \\ Channel:   {d} | {d}MHz
                                    //    \\ Connected: {d}s
                                    //    \\ Inactive:  {d}ms
                                    //    \\ Signal:    {d}dBm
                                    //    , .{
                                    //        self.ssid,
                                    //        conn_if.name,
                                    //        conn_if.channel.?, try nl._80211.freqFromChannel(conn_if.channel.?),
                                    //        sta.STA_INFO.CONNECTED_TIME orelse 0,
                                    //        sta.STA_INFO.INACTIVE_TIME orelse 99999,
                                    //        @as(i16, sta.STA_INFO.SIGNAL orelse -999),
                                    //    }
                                    //);
                                }
                                self._nl_state = .request;
                                continue :nlState self._nl_state;
                            },
                        }
                    },
                }
            },
            .disconn => |*disc_state| {
                discState: switch (disc_state.*) {
                    .start => {
                        log.info("Cleaning Connection (ssid: {s}, if: {s})...", .{ self.ssid, conn_if.name });
                        disc_state.* = .dhcp;
                        continue :discState disc_state.*;
                    },
                    //.thread => {
                    //    disc_state.* = .dhcp;
                    //    continue :discState disc_state.*;
                    //},
                    .dhcp => {
                        self._thread_states.mutex.lock();
                        defer self._thread_states.mutex.unlock();
                        const rel_dhcp_state = self._thread_states.map.getEntry("rel_dhcp").?.value_ptr;
                        errdefer {
                            rel_dhcp_state.* = .ready;
                            self._state = .{ .conn = .init };
                        }
                        dhcpState: switch (rel_dhcp_state.*) {
                            .ready => {
                                const dhcp_info = self._dhcp_info orelse {
                                    disc_state.* = .ip;
                                    continue :discState disc_state.*;
                                };
                                log.debug("- Releasing DHCP...", .{});
                                rel_dhcp_state.* = .starting;
                                const rel_dhcp_thread = try Thread.spawn(
                                    .{},
                                    handleReleaseDHCP,
                                    .{
                                        self._thread_states,
                                        dhcp_info,
                                        conn_if.name,
                                        conn_if.index,
                                        conn_if.mac,
                                    },
                                );
                                rel_dhcp_thread.detach();
                                continue :dhcpState rel_dhcp_state.*;
                            },
                            .starting => {},
                            .working => |*work| working: {
                                if (@divFloor(work.timer.read(), time.ns_per_ms) < self.thread_timeout) break :working;
                                rel_dhcp_state.* = .{ .err = error.DHCPThreadTimeout };
                                continue :dhcpState rel_dhcp_state.*;
                            },
                            .err => |err| {
                                log.warn("- Unable to release DHCP for '{s}' on '{s}': {t}", .{ conn_if.name, self.ssid, err });
                                rel_dhcp_state.* = .ready;
                                disc_state.* = .ip;
                                continue :discState disc_state.*;
                            },
                            .done => {
                                log.info("- Released DHCP for '{s}' on '{s}'.", .{ conn_if.name, self.ssid });
                                rel_dhcp_state.* = .ready;
                                disc_state.* = .ip;
                                continue :discState disc_state.*;
                            },
                        }
                    },
                    .ip => {
                        const dhcp_info = self._dhcp_info orelse {
                            disc_state.* = .disassoc;
                            continue :discState disc_state.*;
                        };
                        log.debug("- Removing IPs...", .{});
                        const ip = dhcp_info.assigned_ip;
                        const cidr = netdata.address.cidrFromSubnet(dhcp_info.subnet_mask);
                        nlState: switch (self._nl_state) {
                            .ready, .request => {
                                nl.route.requestDeleteIP(
                                    core_ctx.alloc,
                                    &self._rtnetlink_req_ctx,
                                    conn_if.index,
                                    ip,
                                    cidr,
                                ) catch |err| {
                                    log.warn("- Could not remove IP '{f}': {t}", .{ IPF{ .bytes = ip[0..] }, err });
                                    self._nl_state = .request;
                                    disc_state.* = .disassoc;
                                    continue :discState disc_state.*;
                                };
                                self._nl_state = .await_response;
                                continue :nlState self._nl_state;
                            },
                            .await_response => {
                                if (!self._rtnetlink_req_ctx.checkResponse()) return;
                                self._nl_state = .parse;
                                continue :nlState self._nl_state;
                            },
                            .parse => {
                                const ip_del_resp = self._rtnetlink_req_ctx.getResponse().?;
                                if (ip_del_resp) |ip_del_data| {
                                    core_ctx.alloc.free(ip_del_data);
                                    log.info("- Removed IP '{f}/{d}'", .{ IPF{ .bytes = ip[0..] }, cidr });
                                }
                                else |err| 
                                    log.warn("- Could not remove IP '{f}': {t}", .{ IPF{ .bytes = ip[0..] }, err });
                                disc_state.* = .disassoc;
                                continue :discState disc_state.*;
                            },
                        }
                    },
                    .disassoc => {
                        log.debug("- Disassociating from '{s}'...", .{ self.ssid });
                        self._nl80211_req_ctx.nextSeqID();
                        nl._80211.requestDisassociate(
                            core_ctx.alloc,
                            &self._nl80211_req_ctx,
                            conn_if.index,
                            self.bssid,
                        ) catch {};
                        log.debug("- Sent Dissasociation Request to '{s}'.", .{ self.ssid });
                        disc_state.* = .deauth;
                        continue :discState disc_state.*;
                    },
                    .deauth => {
                        log.debug("- Deauthenticating from '{s}'...", .{ self.ssid });
                        self._nl80211_req_ctx.nextSeqID();
                        nl._80211.requestDeauthenticate(
                            core_ctx.alloc,
                            &self._nl80211_req_ctx,
                            conn_if.index,
                            self.bssid,
                        ) catch {};
                        log.debug("- Sent Deauthentication Request to '{s}'.", .{ self.ssid });
                        disc_state.* = .disc;
                        continue :discState disc_state.*;
                    },
                    .disc => {
                        log.info("Cleaned Connection (ssid: {s}, if: {s}).", .{ self.ssid, conn_if.name });
                        log.info("Disconnected from '{s}'.", .{ self.ssid });
                        for (core_ctx.conn_ctx._candidates.items, 0..) |candidate, idx| {
                            if ( //
                                !mem.eql(u8, candidate.bssid[0..], self.bssid[0..]) or //
                                !mem.eql(u8, candidate.conn_if[0..], conn_if.og_mac[0..])
                            ) continue;
                            log.debug("Removed old Candidate for '{s}'", .{ self.ssid });
                            _ = core_ctx.conn_ctx._candidates.orderedRemove(idx);
                            break;
                        }
                        self.deinit(core_ctx.alloc);
                        conn_if.usage = .available;
                    }
                }
            },
            else => {},
        }
    }

    /// Handle the 4-way Handshake via EAPoL
    fn handle4WHS(
        states: *ThreadHashMap([]const u8, ThreadState),
        eapol_keys: *?nl._80211.EAPoLKeys,
        if_index: i32,
        pmk: [32]u8,
        m2_data: []const u8,
        security: nl._80211.SecurityType,
    ) void {
        states.mutex.lock();
        var state = states.map.getEntry("eapol").?.value_ptr;
        state.* = .{
            .working = .{
                .timer = time.Timer.start() catch |err| {
                    state.* = .{ .err = err };
                    states.mutex.unlock();
                    return;
                },
                .id = Thread.getCurrentId(),
            },
        };
        states.mutex.unlock();
        eapol_keys.* = proto.wpa.handle4WHS(
            if_index,
            pmk,
            m2_data,
            security,
        ) catch |err| {
            states.mutex.lock();
            defer states.mutex.unlock();
            state = states.map.getEntry("eapol").?.value_ptr;
            if (state.* != .working or state.working.id != Thread.getCurrentId()) //
                return;
            state.* = .{ .err = err };
            return;
        };
        states.mutex.lock();
        defer states.mutex.unlock();
        state = states.map.getEntry("eapol").?.value_ptr;
        if (state.* != .working or state.working.id != Thread.getCurrentId()) //
            return;
        state.* = .done;
    }

    /// Handle DHCP
    fn handleDHCP(
        states: *ThreadHashMap([]const u8, ThreadState),
        dhcp_info: *?proto.dhcp.Info,
        if_name: []const u8,
        if_index: i32,
        if_mac: [6]u8,
        dhcp_config: proto.dhcp.LeaseConfig,
    ) void {
        states.mutex.lock();
        var state = states.map.getEntry("dhcp").?.value_ptr;
        state.* = .{
            .working = .{
                .timer = time.Timer.start() catch |err| {
                    state.* = .{ .err = err };
                    states.mutex.unlock();
                    return;
                },
                .id = Thread.getCurrentId(),
            },
        };
        states.mutex.unlock();
        dhcp_info.* = proto.dhcp.handleDHCP(
            if_name,
            if_index,
            if_mac,
            dhcp_config,
        ) catch |err| {
            states.mutex.lock();
            defer states.mutex.unlock();
            state = states.map.getEntry("dhcp").?.value_ptr;
            if (state.* != .working or state.working.id != Thread.getCurrentId()) //
                return;
            state.* = .{ .err = err };
            return;
        };
        states.mutex.lock();
        defer states.mutex.unlock();
        state = states.map.getEntry("dhcp").?.value_ptr;
        if (state.* != .working or state.working.id != Thread.getCurrentId()) //
            return;
        state.* = .done;
    }

    /// Handle Release DHCP
    fn handleReleaseDHCP(
        states: *ThreadHashMap([]const u8, ThreadState),
        dhcp_info: proto.dhcp.Info,
        if_name: []const u8,
        if_index: i32,
        if_mac: [6]u8,
    ) void {
        states.mutex.lock();
        var state = states.map.getEntry("rel_dhcp").?.value_ptr;
        state.* = .{
            .working = .{
                .timer = time.Timer.start() catch |err| {
                    state.* = .{ .err = err };
                    states.mutex.unlock();
                    return;
                },
                .id = Thread.getCurrentId(),
            },
        };
        states.mutex.unlock();
        proto.dhcp.releaseDHCP(
            if_name,
            if_index,
            if_mac,
            dhcp_info.server_id,
            dhcp_info.assigned_ip,
        ) catch |err| {
            states.mutex.lock();
            defer states.mutex.unlock();
            state = states.map.getEntry("rel_dhcp").?.value_ptr;
            if (state.* != .working or state.working.id != Thread.getCurrentId()) //
                return;
            state.* = .{ .err = err };
            return;
        };
        states.mutex.lock();
        defer states.mutex.unlock();
        state = states.map.getEntry("rel_dhcp").?.value_ptr;
        if (state.* != .working or state.working.id != Thread.getCurrentId()) //
            return;
        state.* = .done;
    }

    /// Handle DNS
    fn handleDNS(states: *ThreadHashMap([]const u8, ThreadState), dns_config: dns.DNSConfig) void {
        states.mutex.lock();
        var state = states.map.getEntry("dns").?.value_ptr;
        state.* = .{
            .working = .{
                .timer = time.Timer.start() catch |err| {
                    state.* = .{ .err = err };
                    states.mutex.unlock();
                    return;
                },
                .id = Thread.getCurrentId(),
            },
        };
        states.mutex.unlock();
        dns.updateDNS(dns_config) catch |err| {
            states.mutex.lock();
            defer states.mutex.unlock();
            state = states.map.getEntry("dns").?.value_ptr;
            if (state.* != .working or state.working.id != Thread.getCurrentId()) //
                return;
            state.* = .{ .err = err };
            return;
        };
        states.mutex.lock();
        defer states.mutex.unlock();
        state = states.map.getEntry("dns").?.value_ptr;
        if (state.* != .working or state.working.id != Thread.getCurrentId()) //
            return;
        state.* = .done;
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
};
