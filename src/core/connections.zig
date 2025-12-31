//! Connection Tracking

const std = @import("std");
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
const ies = netdata.l2.information_elements;
const wifi = netdata.l2.wifi;
const chs = wifi.channels;
const suites = wifi.suites;
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
const ansi = utils.ansi;
const c = utils.toStruct;
const HexF = utils.HexFormatter;
const SlicesF = utils.SliceFormatter;
const ThreadArrayList = utils.ThreadArrayList;
const ThreadHashMap = utils.ThreadHashMap;
const RSSI = core.devices.RSSI;


/// Config for All Connections.
pub const GlobalConfig = struct {
    /// The Max Age, in milliseconds, of a Network that's allowed for Connection attempts.
    max_network_age: usize = 60_000,
    /// The Max Age, in milliseconds, of an inactive Connection before it's dropped.
    max_inactive_age: usize = 900_000,
    /// The Max # of Retries that will be attempted on error before a Connection is dropped.
    max_retries: u8 = 3,
    /// DHCP Config.
    dhcp: ?proto.dhcp.LeaseConfig = null,
    /// Add a Default Route Gateway & DNS.
    add_gw: bool = false,
    /// Metric for Default Gateways
    gw_metric: ?u32 = null,
    /// Allow Multicast DNS (mDNS). Note, if the Global Policy in `/etc/systemd/resolved.conf` is set to `no`, this can't override it.
    allow_mdns: dns.ProtoSetting = .no,
    /// Allow Link-Local Multicast Name Resolution (LLMNR). Note, if the Global Policy in `/etc/systemd/resolved.conf` is set to `no`, this can't override it.
    allow_llmnr: dns.ProtoSetting = .no,
    /// The Delay, in milliseconds, between specifc socket operations.
    /// If this is left `null` a dynamic delay will be calculated based on RSSI.
    op_delay: ?usize = null,
};

/// Config for a Single Connection.
pub const Config = struct {
    /// Enable/Disable this Config
    enabled: bool = true,
    /// Interfaces that are allowed to Connect to the corresponding Network.
    /// If this is left empty, any Interface may connect to the Network.
    if_names: []const []const u8 = &.{},
    /// ID of the Network
    id: core.networks.Network.ID,
    /// Passphrase of the WEP, WPA2, WPA3T, or WPA3 Network
    passphrase: []const u8 = "",
    /// Security "Type" of the Network.
    /// If this is left `null` it will be derived from the Network's Beacon Frames.
    security: ?wifi.SecurityType = null,
    /// Authentication "Type" of the Network.
    /// If this is left `null` it will be derived from the Network's Beacon Frames.
    auth: ?wifi.AuthType = null,
    /// DHCP Config.
    dhcp: ?proto.dhcp.LeaseConfig = null,
    /// Add a Default Route Gateway & DNS.
    add_gw: ?bool = null,
    /// Metric for the Default Gateway
    gw_metric: ?u32 = null,
    /// Allow Multicast DNS (mDNS). Note, if the Global Policy in `/etc/systemd/resolved.conf` is set to `no`, this can't override it.
    allow_mdns: ?dns.ProtoSetting = null,
    /// Allow Link-Local Multicast Name Resolution (LLMNR). Note, if the Global Policy in `/etc/systemd/resolved.conf` is set to `no`, this can't override it.
    allow_llmnr: ?dns.ProtoSetting = null,

    pub fn deinit(self: *const @This(), alloc: mem.Allocator) void {
        for (self.if_names) |name|
            alloc.free(name);
        alloc.free(self.if_names);
        alloc.free(self.passphrase);
        self.id.deinit(alloc);
    }

    pub fn clone(self: *const @This(), alloc: mem.Allocator) mem.Allocator.Error!@This() {
        var new: @This() = self.*;
        var names_list: ArrayList([]const u8) = .empty;
        errdefer names_list.deinit(alloc);
        for (self.if_names) |name| {
            const dupe_name = try alloc.dupe(u8, name);
            errdefer alloc.free(dupe_name);
            try names_list.append(alloc, dupe_name);
        }
        new.if_names = try names_list.toOwnedSlice(alloc);
        new.passphrase = try alloc.dupe(u8, self.passphrase);
        new.id = try self.id.clone(alloc);
        return new;
    }
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
    /// Status of Active & Previous Connections.
    statuses: *ThreadArrayList(Status),
    /// Connection Configs
    configs: *ThreadArrayList(Config),


    /// Initialize all Maps.
    pub fn init(core_ctx: *core.Core) !@This() {
        var self: @This() = undefined;
        self.statuses = core_ctx.alloc.create(ThreadArrayList(Status)) catch @panic("OOM");
        self.statuses.* = .empty;
        self._candidates = core_ctx.alloc.create(ArrayList(Candidate)) catch @panic("OOM");
        self._candidates.* = .empty;
        self.configs = configs: {
            const configs = core_ctx.alloc.create(ThreadArrayList(Config)) catch @panic("OOM");
            configs.* = .empty;
            for (core_ctx.config.connect_configs) |config| {
                const put_conf = config.clone(core_ctx.alloc) catch @panic("OOM");
                configs.append(core_ctx.alloc, put_conf) catch @panic("OOM");
            }
            break :configs configs;
        };
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
        self.configs.mutex.lock();
        for (self.configs.list.items) |conf| //
            conf.deinit(alloc);
        self.configs.mutex.unlock();
        self.configs.deinit(alloc);
        alloc.destroy(self.configs);
        self.statuses.deinit(alloc);
        alloc.destroy(self.statuses);
        self._candidates.deinit(alloc);
        alloc.destroy(self._candidates);
    }

    /// Update Connections
    pub fn update(self: *@This()) !void {
        const core_ctx: *core.Core = @alignCast(@fieldParentPtr("conn_ctx", self));
        //const core_ctx: *core.Core = @fieldParentPtr("conn_ctx", self);
        //log.debug("Start Conn Update", .{});
        //defer log.debug("End Conn Update", .{});
        if (core_ctx.run_condition) |condition| {
            switch (condition) {
                .list_interfaces,
                .mod_interfaces,
                => return,
                else => {},
            }
        }
        try self.scoreCandidates();
        //log.debug("Candidates: {d}", .{ self._candidates.items.len });
        const statuses = self.statuses.items();
        defer self.statuses.mutex.unlock();
        core_ctx.if_ctx.interfaces.mutex.lock();
        defer core_ctx.if_ctx.interfaces.mutex.unlock();
        var if_iter = core_ctx.if_ctx.interfaces.map.iterator();
        //log.debug("Updating Active Connections...", .{});
        while (if_iter.next()) |conn_if_entry| {
            const conn_if = conn_if_entry.value_ptr;
            if (conn_if.usage != .connect) continue;
            //log.debug("Updating '{s}' Connection...", .{ conn_if.name });
            //defer log.debug("Updated '{s}' Connection.", .{ conn_if.name });
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
        //log.debug("Updated Active Connections.", .{});
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
            if (conn_if.usage != .active) continue;
            for (statuses) |status| {
                if (!mem.eql(u8, candidate.bssid[0..], status.bssid[0..])) continue;
                if (status.ended) |_| continue :connLoop;
            }
            //log.debug("Found Viable Connection: '{s}' | '{s}'", .{ candidate.network, conn_if.name });
            conn_if.usage = .{ .connect = try .start(core_ctx, candidate) };
        }
    }

    /// Score Candidate Networks
    fn scoreCandidates(self: *@This()) !void {
        const core_ctx: *core.Core = @alignCast(@fieldParentPtr("conn_ctx", self));
        //const core_ctx: *core.Core = @fieldParentPtr("conn_ctx", self);
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
                self.configs.mutex.lock();
                defer self.configs.mutex.unlock();
                for (self.configs.list.items) |conf| {
                    if (!conf.enabled) //
                        continue;
                    switch (conf.id) {
                        .ssid => |ssid| {
                            if (!mem.eql(u8, ssid, network.ssid)) //
                                continue;
                        },
                        .bssid => |bssid| {
                            if (!mem.eql(u8, bssid[0..], network.bssid[0..])) //
                                continue;
                        },
                    }
                    break :connConfig conf;
                }
                continue;
            };
            var net_meta_iter = network.net_meta.iterator();
            defer network.net_meta.mutex.unlock();
            while (net_meta_iter.next()) |net_meta_entry| {
                const net_meta = net_meta_entry.value_ptr;
                checkIF: {
                    if (config.if_names.len == 0) //
                        break :checkIF;
                    for (config.if_names) |if_name| {
                        if (mem.eql(u8, net_meta.seen_by, if_name)) //
                            break :checkIF;
                    }
                    continue;
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
                    .ssid = network.ssid,
                    .conn_if = net_meta_entry.key_ptr.*,
                    //.channel = network.channel,
                    .channel = try .fromCh(network.channel),
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
    ssid: []const u8,
    conn_if: [6]u8,
    channel: chs.Channel,
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
            \\- Channel: {f}
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
    security: wifi.SecurityType,
    auth: wifi.AuthType,
    dhcp_conf: ?proto.dhcp.LeaseConfig = null,
    add_gw: bool = false,
    gw_metric: ?u32 = null,
    allow_mdns: dns.ProtoSetting = .no,
    allow_llmnr: dns.ProtoSetting = .no,
    max_retries: u8,
    max_inactive_age: usize,
    handler_timeout: usize = 3_000,
    // Derived
    _if_index: ?i32 = null,
    _psk: [32]u8 = @splat(0),
    _bss: nl._80211.BasicServiceSet,
    _rsn_bytes: []const u8 = &.{},
    _dhcp_info: ?dhcp.Info = null,
    _station: ?nl._80211.Station = null,
    // State
    _state: State = .setup,
    _retries: u8 = 0,
    _nl_state: core.AsyncState = .ready,
    _nl80211_req_ctx: nl.io.RequestContext,
    _rtnetlink_req_ctx: nl.io.RequestContext,

    /// Simple Connection for Sharing
    pub const Simple = struct {
        // Network
        bssid: [6]u8,
        ssid: []const u8,
        passphrase: []const u8,
        signal: ?i8 = null,
        // Connection
        connected_time: ?u32 = null,
        inactive_time: ?u32 = null,
        // Interface
        if_mac: [6]u8,
        if_name: []const u8,
        channel: ?chs.Channel,


        /// Get a Simple Connection from the provided Connection (`from_conn`).
        /// Note, this function is intended for use by `core.requests`. It assusmes the `core_ctx.if_ctx` is locked.
        pub fn from(alloc: mem.Allocator, from_conn: Connection, core_ctx: *core.Core) @This() {
            const conn_if = core_ctx.if_ctx.interfaces.map.get(from_conn.if_mac).?;
            var self: @This() = .{
                .bssid = from_conn.bssid,
                .ssid = alloc.dupe(u8, from_conn.ssid) catch @panic("OOM"),
                .passphrase = alloc.dupe(u8, from_conn.passphrase) catch @panic("OOM"),
                .if_mac = from_conn.if_mac,
                .if_name = alloc.dupe(u8, conn_if.name) catch @panic("OOM"),
                .channel = conn_if.channel,
            };
            if (from_conn._station) |station| {
                self.signal = station.STA_INFO.SIGNAL;
                self.connected_time = station.STA_INFO.CONNECTED_TIME;
                self.inactive_time = station.STA_INFO.INACTIVE_TIME;
            }
            return self;
        }

        /// Deinitialize this Simple Connection
        pub fn deinit(self: *const @This(), alloc: mem.Allocator) void {
            alloc.free(self.ssid);
            alloc.free(self.passphrase);
            alloc.free(self.if_name);
        }

        /// Format this Connection
        pub fn format(self: @This(), writer: *Io.Writer) Io.Writer.Error!void {
            try self.formatGen(writer, false);
        }

        /// Format this Connection w/ ANSI Formatting
        pub fn formatANSI(self: @This(), writer: *Io.Writer) Io.Writer.Error!void {
            try self.formatGen(writer, true);
        }

        /// Format this Connection
        pub fn formatGen(self: @This(), writer: *Io.Writer, use_ansi: bool) Io.Writer.Error!void {
            // Setup Writer
            var filter_writer: ansi.FilterWriter = .init(writer);
            const w: *Io.Writer =
                if (use_ansi) writer
                else &filter_writer.io_writer;
            // ANSI Resets
            try w.print("{s}", .{ ansi.reset });
            defer w.print("{s}", .{ ansi.reset }) catch {};
            // Format
            const ssid: []const u8 = ssid: {
                if (//
                    self.ssid.len > 0 and //
                    !mem.eql(u8, self.ssid, &.{ 0 }) //
                ) break :ssid self.ssid;
                break :ssid "[HIDDEN NETWORK] (DisCo)";
            };
            try writer.print(
                \\
                \\ {s}{s}{s}
                \\ {s}BSSID{s}:     {f}
                \\ {s}Interface{s}: {s}
                \\ {s}Channel{s}:   {?f}
                \\ {s}Connected{s}: {d}s
                \\ {s}Inactive{s}:  {d}ms
                \\ {s}Signal{s}:    {f} dBm
                \\
                , .{
                    ansi.fmt.bold, ssid, ansi.reset,
                    ansi.fmt.underline, ansi.fmt.reset, MACF{ .bytes = self.bssid[0..] },
                    ansi.fmt.underline, ansi.fmt.reset, self.if_name,
                    ansi.fmt.underline, ansi.fmt.reset, self.channel,
                    ansi.fmt.underline, ansi.fmt.reset, self.connected_time orelse 0,
                    ansi.fmt.underline, ansi.fmt.reset, self.inactive_time orelse 99999,
                    ansi.fmt.underline, ansi.fmt.reset, RSSI{ .strength = self.signal orelse -127 },
                }
            );
        }
    };

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
        eapol: struct {
            handler: ?wpa.HandshakeHandler = null,
            key_idx: u8 = 0,
            keys: ?nl._80211.EAPoLKeys = null,
        },
        /// Requesting Routing Info via DHCP
        dhcp: struct {
            handler: ?dhcp.Handler = null,
            state: enum { dora, ip, gw, dns },
            info: ?dhcp.Info = null,
        },
        /// Updating DNS Settings
        dns: struct {
            handler: ?dns.Handler = null,
            servers: []const [4]u8 = &.{},
        },
        /// Connected to the Network
        conn: union(enum) { init, running: time.Timer },
        /// Disconnected from the Network
        disconn: enum {
            start,
            //thread,
            dhcp,
            ip,
            disassoc,
            deauth,
            keys,
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

    /// Start a new Connection
    pub fn start(core_ctx: *core.Core, candidate: Candidate) !@This() {
        defer core_ctx.network_ctx.networks.mutex.unlock();
        const network_entry = core_ctx.network_ctx.networks.getEntry(candidate.network) orelse return error.NetworkNotFound;
        const network = network_entry.value_ptr;
        const security = candidate.config.security orelse network.security;
        const auth = candidate.config.auth orelse network.auth;
        const psk = switch (security) {
            .wpa2 => wpa.genKey(security, candidate.ssid, candidate.config.passphrase) catch |err| {
                log.err("Key Generation Error: {t}", .{ err });
                return error.UnableToGenKey;
            },
            .open, .wpa3t, .wpa3 => @as([32]u8, @splat(0)),
            else => {
                log.err("Could not connect to '{s}' due to unimplemented Security Type '{t}'", .{ network.ssid, network.security });
                return error.UnimplementedSecurityType;
            },
        };
        //const scan_result = try nl.parse.clone(core_ctx.alloc, nl._80211.ScanResults, network.scan_result);
        //errdefer nl.parse.freeBytes(core_ctx.alloc, nl._80211.ScanResults, scan_result);
        const rsn_bytes = rsnBytes: {
            const bss_ies = network.bss.INFORMATION_ELEMENTS orelse return error.MissingIEs;
            var rsn = bss_ies.RSN orelse return error.MissingRSN;
            if (security == .wpa3t) {
                rsn.AKM_SUITES = &.{ .{ .OUI = [_]u8{ 0x00, 0x0F, 0xAC }, .TYPE = 0x08 } };
                rsn.AKM_SUITE_COUNT = 1;
            }
            const bytes = try nl.parse.toBytes(core_ctx.alloc, ies.InformationElements.RobustSecurityNetwork, rsn);
            var buf = ArrayList(u8).fromOwnedSlice(bytes);
            errdefer buf.deinit(core_ctx.alloc);
            buf.insert(core_ctx.alloc, 0, @intCast(bytes.len)) catch @panic("OOM");
            buf.insert(core_ctx.alloc, 0, c(ies.IE).RSN) catch @panic("OOM");
            break :rsnBytes buf.toOwnedSlice(core_ctx.alloc) catch @panic("OOM");
        };
        const ssid = core_ctx.alloc.dupe(u8, candidate.ssid) catch @panic("OOM");
        errdefer core_ctx.alloc.free(ssid);
        const passphrase = core_ctx.alloc.dupe(u8, candidate.config.passphrase) catch @panic("OOM");
        errdefer core_ctx.alloc.free(passphrase);
        const self: @This() = .{
            .if_mac = candidate.conn_if,
            .bssid = candidate.bssid,
            .ssid = ssid,
            .freq = network.freq,
            .passphrase = passphrase,
            .security = security,
            .auth = auth,
            .dhcp_conf = candidate.config.dhcp orelse core_ctx.config.global_connect_config.dhcp,
            .add_gw = candidate.config.add_gw orelse core_ctx.config.global_connect_config.add_gw,
            .gw_metric = candidate.config.gw_metric orelse core_ctx.config.global_connect_config.gw_metric,
            .allow_mdns = candidate.config.allow_mdns orelse core_ctx.config.global_connect_config.allow_mdns,
            .allow_llmnr = candidate.config.allow_llmnr orelse core_ctx.config.global_connect_config.allow_llmnr,
            .max_retries = core_ctx.config.global_connect_config.max_retries,
            .max_inactive_age = core_ctx.config.global_connect_config.max_inactive_age,
            ._psk = psk,
            ._bss = network.bss,
            ._rsn_bytes = rsn_bytes,
            ._nl80211_req_ctx = try .init(.{ .handler = .{ .handler = core_ctx.nl80211_handler } }),
            ._rtnetlink_req_ctx = try .init(.{ .handler = .{ .handler = core_ctx.rtnetlink_handler } }),
        };
        try self._nl80211_req_ctx.handler.?.trackCommand(c(nl._80211.CMD).AUTHENTICATE);
        log.debug("Starting connection to '{s}' w/ '{f}'...", .{ candidate.ssid, MACF{ .bytes = candidate.conn_if[0..] } });
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
            .disconn => |*disc| {
                for (0..50) |_| {
                    self.handle(core_ctx) catch break;
                    switch (disc.*) {
                        .ip => {
                            disc.* = .disassoc;
                            continue;
                        },
                        .disc => break,
                        else => {},
                    }
                    Thread.sleep(1 * time.ns_per_ms);
                }
            },
            else => {},//self.deinit(core_ctx.alloc),
        }
    }
    
    /// Deinitialize this Connection
    pub fn deinit (self: *@This(), alloc: mem.Allocator) void {
        if (self._station) |sta|
            nl.parse.freeBytes(alloc, nl._80211.Station, sta);
        //nl.parse.freeBytes(alloc, nl._80211.ScanResults, self._scan_result);
        if (self._rsn_bytes.len > 0) //
            alloc.free(self._rsn_bytes);
        switch (self._state) {
            .eapol => |*ctx| {
                if (ctx.handler) |*handler| //
                    handler.deinit(alloc);
            },
            .dhcp => |*ctx| {
                if (ctx.handler) |*handler| //
                    handler.deinit(alloc);
            },
            .dns => |*ctx| {
                if (ctx.handler) |*handler| //
                    handler.deinit(alloc);
            },
            else => {},
        }
        log.debug("Deinitialized Connection '{s}'", .{ self.ssid });
        alloc.free(self.ssid);
        alloc.free(self.passphrase);
    }

    /// Handle this Connection
    /// TODO: Implement all Security Protocols/Types
    pub fn handle(self: *@This(), core_ctx: *core.Core) !void {
        if (self._retries >= self.max_retries and self._state != .disconn) {
            self._state = .{ .disconn = .start };
            log.warn("Max Retries Reached for Connection '{s}'", .{ self.ssid });
        }
        //defer core_ctx.if_ctx.interfaces.mutex.unlock();
        const conn_if_entry = core_ctx.if_ctx.interfaces.map.getEntry(self.if_mac) orelse return error.InterfaceNotFound;
        const conn_if = conn_if_entry.value_ptr;
        if (conn_if.usage != .connect) //
            return error.InterfaceInUse;
        if (conn_if.checkPenalty() and self._state != .disconn) //
            return error.InterfaceUnderPenalty;
        errdefer {
            self._retries +%= 1;
            self._nl_state = .ready;
            conn_if.addPenalty();
        }
        if (self._if_index) |idx| idxCheck: {
            if (conn_if.index == idx) //
                break :idxCheck;
            log.warn("The Interface '{s}' was interrupted during the Connection to '{s}'.", .{ conn_if.name, self.ssid });
            self.deinit(core_ctx.alloc);
            conn_if.usage = .active;
            return error.InterfaceInterrupted;
        } //
        else {
            self._if_index = conn_if.index;
            log.info("Connecting to '{s}' w/ '{s}'...", .{ self.ssid, conn_if.name });
        }
        state: switch (self._state) {
            .setup => {
                nl_state: switch (self._nl_state) {
                    .ready, .request => {
                        self._nl_state = .ready;
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
                        self._state = .{ .auth = .{ .auth_timer = time.Timer.start() catch @panic("Time Issue") } };
                        continue :state self._state;
                    },
                }
            },
            .auth => |*auth_ctx| {
                errdefer {
                    self._nl_state = .request;
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
                                    self._bss,
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
                                        const sae_commit: [102]u8 = //
                                            // Commit
                                            mem.toBytes(@as(u32, 1)) ++ //
                                            // Group
                                            mem.toBytes(@as(u16, 19)) ++ //
                                            auth_ctx.sae_ctx.?.commit.scalar ++ //
                                            auth_ctx.sae_ctx.?.commit.element.x.toBytes(.big) ++ //
                                            auth_ctx.sae_ctx.?.commit.element.y.toBytes(.big);
                                        log.debug("SAE Commit Data:{f}\n", .{ HexF{ .bytes = sae_commit[0..] } });
                                        log.debug("WPA3 Auth SAE Commit...", .{});
                                        try nl._80211.requestAuthenticate(
                                            core_ctx.alloc,
                                            &self._nl80211_req_ctx,
                                            conn_if.index,
                                            self.ssid,
                                            self._bss,
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
                                            self._bss,
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
                                        if (sae_confirm_resp_data[0].FRAME.len < 64) {
                                            log.warn("Issue handling WPA3 SAE Confirm resonpse data: Response Too Short ({d}B/64B)", .{ sae_confirm_resp_data[0].FRAME.len });
                                            return error.ConfirmResponseTooShort;
                                        }
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
                                    self._bss,
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
                                        self._retries = 0;
                                        self._nl_state = .ready;
                                        self._state = .{ .eapol = .{} };
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
            .eapol => |*eapol_ctx| {
                // EAPoL Handshake
                const keys = eapol_ctx.keys orelse switch (self.security) {
                    .open => {
                        self._state = .{ .dhcp = .{ .state = .dora } };
                        continue :state self._state;
                    },
                    .wpa2, .wpa3t, .wpa3 => {
                        if (eapol_ctx.handler) |*handler| {
                            errdefer {
                                handler.deinit(core_ctx.alloc);
                                eapol_ctx.handler = null;
                            }
                            switch (handler.state) {
                                .end => {
                                    eapol_ctx.keys = .{ .ptk = handler.ctx.ptk, .gtk = handler.ctx.gtk };
                                    continue :state self._state;
                                },
                                else => {
                                    handler.step() catch |err| switch (err) {
                                        error.ReadFailed,
                                        //error.UnexpectedFlags,
                                        => {
                                            //log.debug("EAPoL Read Failed: {t}", .{ handler.state });
                                        },
                                        else => return err,
                                    };
                                    return;
                                },
                            }
                        } //
                        else {
                            log.debug("Connection {s} | {s}: Handling EAPoL ({t})", .{ self.ssid, conn_if.name, self.security });
                            eapol_ctx.handler = try .init(
                                core_ctx.alloc,
                                conn_if.index,
                                self.handler_timeout,
                                self._psk,
                                self._rsn_bytes,
                                self.security,
                            );
                            continue :state self._state;
                        }
                    },
                    else => return error.UnsupportedSecurityType,
                };
                // Apply Keys
                nlState: switch (self._nl_state) {
                    .ready, .request => {
                        log.debug("Applying PTK & GTK", .{});
                        self._nl80211_req_ctx.nextSeqID();
                        const key,
                        const bssid,
                        const seq = keyData: {
                            if (eapol_ctx.key_idx == 0) break :keyData .{
                                keys.ptk[32..],
                                self._bss.BSSID,
                                null,
                            };
                            break :keyData .{
                                keys.gtk[0..],
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
                                .CIPHER = c(suites.CIPHER).CCMP,
                                //.SEQ = if (idx == 0) null else .{ 2 } ++ .{ 0 } ** 5,
                                .SEQ = seq,
                                //.IDX = idx,
                                .IDX = eapol_ctx.key_idx,
                            },
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
                        const add_key_resp = self._nl80211_req_ctx.getResponse().?;
                        const add_key_resp_data = try add_key_resp;
                        defer core_ctx.alloc.free(add_key_resp_data);
                        self._nl_state = .ready;
                        if (eapol_ctx.key_idx == 0) {
                            eapol_ctx.key_idx = 1;
                            continue :nlState self._nl_state;
                        }
                        log.debug("Connection {s} | {s}: Finished EAPoL ({t})", .{ self.ssid, conn_if.name, self.security });
                        if (eapol_ctx.handler) |*handler| //
                            handler.deinit(core_ctx.alloc);
                        self._state = .{ .dhcp = .{ .state = .dora } };
                        continue :state self._state;
                    },
                }
            },
            .dhcp => |*dhcp_ctx| {
                // DHCP
                dhcpSetup: switch (dhcp_ctx.state) {
                    .dora => {
                        if (dhcp_ctx.info) |_| {
                            dhcp_ctx.handler.?.deinit(core_ctx.alloc);
                            dhcp_ctx.handler = null;
                            dhcp_ctx.state = .ip;
                            continue :dhcpSetup dhcp_ctx.state;
                        }
                        if (dhcp_ctx.handler) |*handler| {
                            errdefer {
                                handler.deinit(core_ctx.alloc);
                                dhcp_ctx.handler = null;
                            }
                            switch (handler.state) {
                                .end => |info| {
                                    dhcp_ctx.info = info;
                                    self._dhcp_info = info;
                                    continue :dhcpSetup dhcp_ctx.state;
                                },
                                else => {
                                    handler.step() catch |err| switch (err) {
                                        error.ReadFailed => {},
                                        else => return err,
                                    };
                                    return;
                                },
                            }
                        } //
                        else {
                            var dhcp_conf = self.dhcp_conf orelse {
                                self._state = .{ .conn = .init };
                                continue :state self._state;
                            };
                            if (core_ctx.config.profile.mask) |pro_mask| //
                                dhcp_conf.hostname = pro_mask.hostname;
                            log.debug("Connection {s} | {s}: Handling DHCP", .{ self.ssid, conn_if.name });
                            dhcp_ctx.handler = try .init(
                                core_ctx.alloc,
                                conn_if.name,
                                conn_if.index,
                                conn_if.mac,
                                self.handler_timeout,
                                dhcp_conf,
                            );
                            continue :dhcpSetup dhcp_ctx.state;
                        }
                    },
                    .ip => {
                        const dhcp_cidr = address.cidrFromSubnet(dhcp_ctx.info.?.subnet_mask);
                        nlState: switch (self._nl_state) {
                            .ready, .request => {
                                try nl.route.requestAddIP(
                                    core_ctx.alloc,
                                    &self._rtnetlink_req_ctx,
                                    conn_if.index,
                                    dhcp_ctx.info.?.assigned_ip,
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
                                        IPF{ .bytes = dhcp_ctx.info.?.assigned_ip[0..] },
                                        dhcp_cidr,
                                        conn_if.index,
                                        conn_if.name,
                                    });
                                    return err;
                                };
                                defer core_ctx.alloc.free(add_ip_data);
                                log.info("Added IP '{f}/{d}' to ({d}) {s}", .{
                                    IPF{ .bytes = dhcp_ctx.info.?.assigned_ip[0..] },
                                    dhcp_cidr,
                                    conn_if.index,
                                    conn_if.name,
                                });
                                if (self.add_gw) {
                                    dhcp_ctx.state = .gw;
                                    continue :dhcpSetup dhcp_ctx.state;
                                }
                                self._state = .{ .conn = .init };
                                continue :state self._state;
                            },
                        }
                    },
                    .gw => {
                        const dhcp_cidr = address.cidrFromSubnet(dhcp_ctx.info.?.subnet_mask);
                        nlState: switch (self._nl_state) {
                            .ready, .request => {
                                try nl.route.requestAddRoute(
                                    core_ctx.alloc,
                                    &self._rtnetlink_req_ctx,
                                    conn_if.index,
                                    address.IPv4.default.addr,
                                    .{
                                        .cidr = address.IPv4.default.cidr,
                                        //.cidr = dhcp_cidr,
                                        .gateway = dhcp_ctx.info.?.router,
                                        .metric = self.gw_metric,
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
                                        IPF{ .bytes = dhcp_ctx.info.?.router[0..] },
                                        dhcp_cidr,
                                        conn_if.index,
                                        conn_if.name,
                                        if (err == error.EXIST) "There's already a Default Gateway." //
                                        else @errorName(err),
                                    });
                                    if (err == error.EXIST) {
                                        dhcp_ctx.state = .ip;
                                        self._state = .{ .conn = .init };
                                        continue :state self._state;
                                    }
                                    return err;
                                };
                                defer core_ctx.alloc.free(add_gw_data);
                                log.info("Added Default Gateway '{f}/{d}' to ({d}) {s}", .{
                                    IPF{ .bytes = dhcp_ctx.info.?.router[0..] },
                                    dhcp_cidr,
                                    conn_if.index,
                                    conn_if.name,
                                });
                                dhcp_ctx.state = .dns;
                                continue :dhcpSetup dhcp_ctx.state;
                            },
                        }
                    },
                    .dns => {
                        if (dhcp_ctx.info.?.dns_ips.len == 0) {
                            self._state = .{ .conn = .init };
                            continue :state self._state;
                        }
                        var dns_ips_list: ArrayList([4]u8) = .empty;
                        //log.debug("DNS IPs: {s}", .{ if (dhcp_info.dns_ips[0]) |_| "" else "none" });
                        dnsLoop: for (dhcp_ctx.info.?.dns_ips) |dns_ip| {
                            const next_dns = dns_ip orelse break :dnsLoop;
                            for (dns_ips_list.items) |prev_dns| {
                                if (mem.eql(u8, prev_dns[0..], next_dns[0..])) //
                                    continue :dnsLoop;
                            }
                            //log.debug("- {f}", .{ IPF{ .bytes = next_dns[0..] } });
                            try dns_ips_list.append(core_ctx.alloc, next_dns);
                        }
                        self._state = .{ .dns = .{ .servers = try dns_ips_list.toOwnedSlice(core_ctx.alloc) } };
                    },
                }
            },
            .dns => |*dns_ctx| {
                var old_ctx: @TypeOf(dns_ctx.*) = dns_ctx.*;
                defer if (self._state != .dns) {
                    core_ctx.alloc.free(old_ctx.servers);
                    if (old_ctx.handler) |*handler| {
                        handler.deinit(core_ctx.alloc);
                        old_ctx.handler = null;
                    }
                };
                if (dns_ctx.servers.len == 0) {
                    self._state = .{ .conn = .init };
                    continue :state self._state;
                }
                if (dns_ctx.handler) |*handler| {
                    errdefer self._state = .{ .conn = .init };
                    switch (handler.state) {
                        .done => {
                            for (dns_ctx.servers) |server| //
                                log.info("Added DNS Server: {f}", .{ IPF{ .bytes = server[0..] } });
                            self._state = .{ .conn = .init };
                            continue :state self._state;
                        },
                        else => {
                            handler.step() catch |err| switch (err) {
                                error.ReadFailed,
                                error.WriteFailed,
                                => {
                                    //log.warn("DNS Read Failed: {t}", .{ handler.state });
                                },
                                else => {
                                    log.warn("DNS Handling Error: '{t}'. Could not finish setting DNS.", .{ err });
                                    return err;
                                },
                            };
                            return;
                        },
                    }
                } //
                else {
                    log.debug("Connection {s} | {s}: Handling DNS", .{ self.ssid, conn_if.name });
                    dns_ctx.handler = try .init(
                        core_ctx.alloc,
                        &core_ctx.dbus_conn,
                        self.handler_timeout,
                        .{
                            .if_index = conn_if.index,
                            .servers = dns_ctx.servers,
                        },
                    );
                    continue :state self._state;
                }
            },
            .conn => |*conn| {
                switch (conn.*) {
                    .init => {
                        log.info("Connected to '{s}' w/ '{s}'!", .{ self.ssid, conn_if.name });
                        self._retries = 0;
                        conn_if.subtractPenalty();
                        conn_if.penalty_time = null;
                        conn.* = .{ .running = time.Timer.start() catch @panic("Time Issue") };
                    },
                    .running => |*timer| {
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
                                if (timer.read() < time.ns_per_s) //
                                    break :nlState;
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
                                if (!self._nl80211_req_ctx.checkResponse()) //
                                    return;
                                self._nl_state = .parse;
                                continue :nlState self._nl_state;
                            },
                            .parse => {
                                defer timer.reset();
                                //log.debug("Received Station Info Response.", .{});
                                const station_resp = self._nl80211_req_ctx.getResponse() orelse error.NoStationInfo;
                                const station_data = station_resp catch |err| {
                                    log.warn("Could not update Station Status: {t}", .{ err });
                                    return err;
                                };
                                defer core_ctx.alloc.free(station_data);
                                //log.debug("Station Data Raw: {d}B", .{ station_data.len });
                                if (self._station) |sta| {
                                    nl.parse.freeBytes(core_ctx.alloc, nl._80211.Station, sta);
                                    self._station = null;
                                }
                                const stations = try nl._80211.handleStationBuf(core_ctx.alloc, station_data);
                                defer {
                                    if (stations.len > 1) {
                                        for (stations[1..]) |sta| //
                                            nl.parse.freeBytes(core_ctx.alloc, nl._80211.Station, sta);
                                    }
                                    core_ctx.alloc.free(stations);
                                }
                                if (stations.len > 0) {
                                    self._station = stations[0];
                                    const sta = self._station.?;
                                    const last_seen = sta.STA_INFO.INACTIVE_TIME orelse return error.IncompleteStation;
                                    if (last_seen >= self.max_inactive_age) {
                                        log.warn("The Connection to '{s}' has been inactive for too long ({d}s).", .{ self.ssid, @divFloor(self.max_inactive_age, 1_000) });
                                        self._retries = self.max_retries;
                                        return error.InactiveConnection;
                                    }
                                    //log.debug(
                                    //    \\
                                    //    \\ SSID:      {s}
                                    //    \\ Interface: {s}
                                    //    \\ Channel:   {f}
                                    //    \\ Connected: {d}s
                                    //    \\ Inactive:  {d}ms
                                    //    \\ Signal:    {d}dBm
                                    //    , .{
                                    //        self.ssid,
                                    //        conn_if.name,
                                    //        conn_if.channel.?,
                                    //        sta.STA_INFO.CONNECTED_TIME orelse 0,
                                    //        sta.STA_INFO.INACTIVE_TIME orelse 99999,
                                    //        @as(i16, sta.STA_INFO.SIGNAL orelse -999),
                                    //    }
                                    //);
                                }
                                self._nl_state = .request;
                                //continue :nlState self._nl_state; <-- This can lock up the entire program
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
                    .dhcp => {
                        const dhcp_info = self._dhcp_info orelse {
                            disc_state.* = .ip;
                            continue :discState disc_state.*;
                        };
                        log.debug("- Releasing DHCP...", .{});
                        dhcp.releaseDHCP(
                            conn_if.name,
                            conn_if.index,
                            conn_if.mac,
                            dhcp_info.server_id,
                            dhcp_info.assigned_ip,
                        ) catch |err| {
                            log.warn("- Unable to release DHCP for '{s}' on '{s}': {t}", .{ conn_if.name, self.ssid, err });
                            disc_state.* = .ip;
                            continue :discState disc_state.*;
                        };
                        log.info("- Released DHCP for '{s}' on '{s}'.", .{ conn_if.name, self.ssid });
                        disc_state.* = .ip;
                        continue :discState disc_state.*;
                    },
                    .ip => {
                        const dhcp_info = self._dhcp_info orelse {
                            disc_state.* = .disassoc;
                            continue :discState disc_state.*;
                        };
                        const ip = dhcp_info.assigned_ip;
                        const cidr = netdata.address.cidrFromSubnet(dhcp_info.subnet_mask);
                        nlState: switch (self._nl_state) {
                            .ready, .request => {
                                log.debug("- Removing IPs...", .{});
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
                                if (!self._rtnetlink_req_ctx.checkResponse()) //
                                    return;
                                self._nl_state = .parse;
                                continue :nlState self._nl_state;
                            },
                            .parse => {
                                const ip_del_resp = self._rtnetlink_req_ctx.getResponse().?;
                                if (ip_del_resp) |ip_del_data| {
                                    core_ctx.alloc.free(ip_del_data);
                                    log.info("- Removed IP '{f}/{d}'", .{ IPF{ .bytes = ip[0..] }, cidr });
                                } //
                                else |err| //
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
                        disc_state.* = .keys;
                        continue :discState disc_state.*;
                    },
                    .keys => {
                        log.debug("- Deleting Keys for '{s}'...", .{ self.ssid });
                        for (0..2) |idx| {
                            nl._80211.requestDelKey(
                                core_ctx.alloc,
                                &self._nl80211_req_ctx,
                                conn_if.index,
                                self.bssid,
                                @truncate(idx),
                            ) catch {};
                        }
                        log.debug("- Sent Key Deletion Requests to '{s}'.", .{ self.ssid });
                        disc_state.* = .disc;
                        continue :discState disc_state.*;
                    },
                    .disc => {
                        nl._80211.requestDisconnect(
                            core_ctx.alloc,
                            &self._nl80211_req_ctx,
                            conn_if.index,
                            self.bssid,
                        ) catch {};
                        log.info("Disconnected from '{s}'.", .{ self.ssid });
                        log.info("Cleaned Connection (ssid: {s}, if: {s}).", .{ self.ssid, conn_if.name });
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
                        conn_if.usage = .active;
                    }
                }
            },
            else => {},
        }
    }
};
