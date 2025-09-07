//! Interface Management

const std = @import("std");
const ascii = std.ascii;
const atomic = std.atomic;
const fmt = std.fmt;
const heap = std.heap;
const log = std.log.scoped(.interfaces);
const math = std.math;
const mem = std.mem;
const meta = std.meta;
const posix = std.posix;
const time = std.time;
const ArrayList = std.ArrayListUnmanaged;

const zeit = @import("zeit");

const core = @import("../core.zig");
const netdata = @import("../netdata.zig");
const address = netdata.address;
const MACF = address.MACFormatter;
const IPF = address.IPFormatter;
const nl = @import("../netlink.zig");
const protocols = @import("../protocols.zig");
const dns = protocols.dns;
const utils = @import("../utils.zig");
const c = utils.toStruct;
const ThreadHashMap = utils.ThreadHashMap;


/// Interface Info
pub const Interface = struct {
    // Meta
    _init: bool = false,
    penalty_time: ?zeit.Instant = null,
    penalty: usize = 0,
    min_penalty: usize = 100,
    max_penalty: usize = 6_000,
    raw_sock: ?posix.socket_t = null,
    usage: UsageState = .unavailable,
    last_upd: zeit.Instant,
    // Details
    index: i32,
    name: []const u8,
    phy_index: u32,
    phy_name: []const u8,
    og_mac: [6]u8,
    mac: [6]u8,
    state: u32,
    mtu: usize,
    ips: [10]?[4]u8 = @splat(null),
    cidrs: [10]?u8 = @splat(null),
    mode: u32,
    channel: ?u32 = null,
    ch_width: ?nl._80211.CHANNEL_WIDTH = null,
    ssid: ?[]const u8 = null,
    // Netlink Data
    wiphy: nl._80211.Wiphy,

    /// DisCo Usage State of an Interface
    pub const UsageState = union(enum) {
        err: anyerror,
        unavailable,
        modify: ArrayList(*ModifyContext),
        available,
        scan: core.networks.NetworkScanContext,
        connect: core.connections.Connection,
        remove,
    };

    /// Modify Field
    pub const ModifyField = union(enum) {
        //name: []const u8,
        mac: [6]u8,
        state: u32,
        add_ip: struct { addr: [4]u8, cidr: u8 },
        del_ip: struct { addr: [4]u8, cidr: u8 },
        mode: u32,
        channel: struct { ch: usize, width: nl._80211.CHANNEL_WIDTH },
    };

    /// Modify Context
    const ModifyContext = struct {
        req_ctx: nl.RequestContext,
        mod_field: ModifyField,
    };

    /// Interface State Formatter
    const IFStateF = struct {
        flags: u32,

        pub fn format(
            self: @This(),
            _: []const u8,
            _: fmt.FormatOptions,
            writer: anytype,
        ) !void {
            for (meta.tags(nl.route.IFF)) |tag| {
                const flag: u32 = @intFromEnum(tag);
                if (flag == 0) continue;
                if (flag == 1) {
                    const state = if (self.flags & 1 == 1) "UP" else "DOWN";
                    try writer.print("{s}", .{ state });
                    continue;
                }
                if (self.flags & flag == flag)
                try writer.print(", {s}", .{ @tagName(tag) });
            }
        }
    };

    /// Free the allocated portions of this Interface.
    pub fn deinit(self: *@This(), alloc: mem.Allocator) void {
        if (!self._init) return;
        switch (self.usage) {
            .modify => |*mods| {
                for (mods.items) |mod| alloc.destroy(mod);
                mods.deinit(alloc);
            },
            .connect => |*conn| conn.deinit(alloc),
            else => {},
        }
        alloc.free(self.name);
        alloc.free(self.phy_name);
        nl.parse.freeBytes(alloc, nl._80211.Wiphy, self.wiphy);
        //if (self.ssid) |ssid| alloc.free(ssid);
        self._init = false;
    }

    /// Check if the Interface is currently under a Penalty.
    pub fn checkPenalty(self: *@This()) bool {
        const last_penalty = self.penalty_time orelse return false;
        const cur_time = zeit.instant(.{}) catch @panic("Missing Time Source?");
        const under_penalty = @divFloor(cur_time.timestamp - last_penalty.timestamp, time.ns_per_ms) < self.penalty;
        //log.debug("Penalty Check: {d}/{d}", .{ @divFloor(cur_time.timestamp - last_penalty.timestamp, time.ns_per_ms), self.penalty });
        //defer if (!under_penalty) self.setPenalty(.down);
        return under_penalty;
    }

    /// Set the current Penalty of the Interface.
    pub fn setPenalty(self: *@This(), set: enum { up, down }) void {
        defer {
            if (self.penalty < self.min_penalty) self.penalty = self.min_penalty;
            if (self.penalty > self.max_penalty) self.penalty = self.max_penalty;
        }
        self.penalty = switch (set) {
            .up => if (self.penalty == 0) 1 else self.penalty * 5,
            .down => @divFloor(self.penalty, 5),
        };
    }

    /// Add a Penalty to the Interface.
    pub fn addPenalty(self: *@This()) void {
        self.penalty_time = zeit.instant(.{}) catch @panic("Missing Time Source?");
        self.setPenalty(.up);
    }

    /// Subtract a Penalty from the Interface.
    pub fn subtractPenalty(self: *@This()) void {
        self.setPenalty(.down);
        self.penalty_time = null;
    }

    /// Reset the Penalty of the Interface.
    pub fn resetPenalty(self: *@This()) void {
        self.penalty_time = null;
        self.penalty = 0;
    }

    /// Modify this Interface
    pub fn modify(self: *@This(), core_ctx: *core.Core, mod_field: ModifyField) !void {
        if (self.usage != .modify) self.usage = .{ .modify = .empty };
        const mod_ctx: *ModifyContext = modReq: {
            const req_handler: *nl.io.Handler = switch (mod_field) {
                .mode,
                .channel,
                => core_ctx.nl80211_handler,
                else => core_ctx.rtnetlink_handler,
            };
            const mod_ctx: *ModifyContext = core_ctx.alloc.create(ModifyContext) catch @panic("OOM");
            errdefer core_ctx.alloc.destroy(mod_ctx);
            mod_ctx.* = .{
                .req_ctx = try .init(.{ .handler = .{ .handler = req_handler } }),
                .mod_field = mod_field,
            };
            break :modReq mod_ctx;
        };
        switch (mod_field) {
            .mac => |mac| {
                try nl.route.requestSetMAC(
                    core_ctx.alloc,
                    &mod_ctx.req_ctx,
                    self.index,
                    mac,
                );
            },
            .state => |state| {
                try nl.route.requestSetState(
                    core_ctx.alloc,
                    &mod_ctx.req_ctx,
                    self.index,
                    state,
                );
            },
            .add_ip => |add_ip| {
                try nl.route.requestAddIP(
                    core_ctx.alloc,
                    &mod_ctx.req_ctx,
                    self.index,
                    add_ip.addr,
                    add_ip.cidr,
                );
            },
            .del_ip => |del_ip| {
                try nl.route.requestDeleteIP(
                    core_ctx.alloc,
                    &mod_ctx.req_ctx,
                    self.index,
                    del_ip.addr,
                    del_ip.cidr,
                );
            },
            .mode => |mode| {
                try nl._80211.requestSetMode(
                    core_ctx.alloc,
                    &mod_ctx.req_ctx,
                    self.index,
                    mode,
                );
            },
            .channel => |channel| {
                try nl._80211.requestSetFreq(
                    core_ctx.alloc,
                    &mod_ctx.req_ctx,
                    self.index,
                    try nl._80211.freqFromChannel(channel.ch),
                    channel.width,
                );
            },
        }
        self.usage.modify.append(core_ctx.alloc, mod_ctx) catch @panic("OOM");
        time.sleep(1 * time.ns_per_ms);
    }

    /// Restoration Kind
    pub const RestoreKind = enum {
        dns,
        ips,
        mac,
    };
    /// Restore the Interface.
    /// Note, this is blocking.
    pub fn restore(self: *@This(), alloc: mem.Allocator, kinds: []const RestoreKind) void {
        log.info("- Restoring Interface '{s}'...", .{ self.name });
        //if (self.usage == .connect) self.usage.connect.stop();
        const has_ip: bool = if (self.ips[0]) |_| true else false;
        for (kinds) |kind| {
            switch (kind) {
                .ips => {
                    for (self.ips, self.cidrs) |_ip, _cidr| {
                        const ip = _ip orelse continue;
                        const cidr = _cidr orelse 24;
                        nl.route.deleteIP(
                            alloc,
                            self.index,
                            ip,
                            cidr,
                        ) catch |err| {
                            switch (err) {
                                error.ADDRNOTAVAIL => {},
                                else => log.warn("-- Could not remove IP '{s}'!", .{ IPF{ .bytes = ip[0..] } }),
                            }
                            continue;
                        };
                        log.info("-- Removed IP '{s}/{d}'", .{ IPF{ .bytes = ip[0..] }, cidr });
                    }
                },
                .mac => resetMAC: {
                    if (mem.eql(u8, self.og_mac[0..], self.mac[0..])) break :resetMAC;
                    nl.route.setState(self.index, c(nl.route.IFF).DOWN) catch {};
                    time.sleep(time.ns_per_ms);
                    if (nl.route.setMAC(self.index, self.og_mac))
                        log.info("-- Restored Orignal MAC '{s}'.", .{ MACF{ .bytes = self.og_mac[0..] } })
                    else |_|
                        log.warn("-- Could not restore Interface '{s}' to its orignal MAC '{s}'.", .{ self.name, MACF{ .bytes = self.og_mac[0..] } });
                },
                .dns => resetDNS: {
                    if (!has_ip) break :resetDNS;
                    dns.updateDNS(.{ .if_index = self.index, .servers = &.{}, .set_route = false }) catch |err| {
                        log.err("-- Could not reset DNS: {s}", .{ @errorName(err) });
                        break :resetDNS;
                    };
                    log.info("-- Reset DNS.", .{});
                },
            }
        }
        //log.info("- Restored Interface '{s}'.", .{ self.name });
    }

    /// Free the allocated portions of this Interface and close the Raw Socket.
    pub fn stop(self: *@This(), alloc: mem.Allocator) void {
        //self.restore(alloc, .all);
        if (self.raw_sock) |sock| posix.close(sock);
        self.deinit(alloc);
    }

    pub fn format(
        self: @This(),
        _: []const u8,
        _: fmt.FormatOptions,
        writer: anytype,
    ) !void {
        var last_ts_buf: [50]u8 = undefined;
        const last_ts = try self.last_upd.time().bufPrint(last_ts_buf[0..], .rfc3339);
        try writer.print(
            \\({d}) {s} | {s}
            \\{s}
            \\- Phy:     ({d}) {s}
            \\- OG MAC:  {s} ({s})
            \\- MAC:     {s} ({s})
            \\- State:   {s}
            \\- Mode:    {s}
            \\- MTU:     {d}
            \\
            , .{
                self.index, self.name, @tagName(self.usage),
                last_ts,
                self.phy_index, self.phy_name,
                MACF{ .bytes = self.og_mac[0..] }, try netdata.oui.findOUI(.short, self.og_mac),
                MACF{ .bytes = self.mac[0..] }, try netdata.oui.findOUI(.short, self.mac),
                IFStateF{ .flags = self.state },
                @tagName(@as(nl._80211.IFTYPE, @enumFromInt(self.mode))),
                self.mtu,
            },
        );
        if (self.channel) |ch| {
            try writer.print("- Channel: {d} | {s}", .{ ch, if (self.ch_width) |width| @tagName(width) else "-" });
        }
        if (self.ips[0] == null) return;
        try writer.print("- IPs:\n", .{});
        for (self.ips, self.cidrs) |_ip, _cidr| {
            const ip = _ip orelse return;
            const cidr = _cidr orelse continue;
            try writer.print("  - {s}/{d}\n", .{ IPF{ .bytes = ip[0..] }, cidr });
        }
    }
};

/// Interfaces Context
pub const Context = struct {
    // INTERNAL USE
    /// Arena
    _arena: *heap.ArenaAllocator,
    /// Arena Allocator
    _a_alloc: mem.Allocator,
    /// WiFi Interfaces Request Context
    _req_wifi_ifs: nl.RequestContext,
    /// WiFi Physical Devices Request Context
    _req_wiphys: nl.RequestContext,
    /// Links Request Context
    _req_links: nl.RequestContext,
    /// Addresses Requeest Context
    _req_addrs: nl.RequestContext,
    // EXTERNAL USE
    /// Netlink Async State
    state: core.AsyncState,
    /// Available Interfaces
    interfaces: *ThreadHashMap([6]u8, Interface),
    /// Interface Timeout
    if_timeout: usize = 5000,

    /// Initialize the Interface Context.
    pub fn init(core_ctx: *core.Core) !@This() {
        var self: @This() = undefined;
        self._arena = core_ctx.alloc.create(heap.ArenaAllocator) catch @panic("OOM");
        self._arena.* = .init(core_ctx.alloc);
        self._a_alloc = self._arena.allocator();
        self.state = .ready;
        self.interfaces = core_ctx.alloc.create(ThreadHashMap([6]u8, Interface)) catch @panic("OOM");
        self.interfaces.* = .empty;
        self._req_wifi_ifs = try .init(.{ .handler = .{ .handler = core_ctx.nl80211_handler } });
        self._req_wiphys = try .init(.{ .handler = .{ .handler = core_ctx.nl80211_handler } });
        self._req_links = try .init(.{ .handler = .{ .handler = core_ctx.rtnetlink_handler } });
        self._req_addrs = try .init(.{ .handler = .{ .handler = core_ctx.rtnetlink_handler } });
        return self;
    }

    /// Deinitialize the Interface Context.
    pub fn deinit(self: *@This(), alloc: mem.Allocator) void {
        var if_iter = self.interfaces.iterator();
        while (if_iter.next()) |if_entry| if_entry.value_ptr.stop(alloc);
        if_iter.unlock();
        self.interfaces.deinit(alloc);
        alloc.destroy(self.interfaces);
        self._arena.deinit();
        alloc.destroy(self._arena);
    }

    /// Restore All Interfaces to their Original MAC Addresses and remove any IP Addresses.
    pub fn restore(self: *@This(), alloc: mem.Allocator) void {
        if (self.interfaces.count() == 0) return;
        var if_iter = self.interfaces.iterator();
        defer if_iter.unlock();
        while (if_iter.next()) |if_entry| {
            const res_if = if_entry.value_ptr;
            if (res_if.usage == .unavailable or res_if.usage == .err) continue;
            res_if.restore(alloc, &.{ .ips, .mac, .dns });
        }
    }
    
    /// Update the status of all Interfaces
    pub fn update(self: *@This(), core_ctx: *core.Core) !void {
        //log.debug("Updating Interfaces: {s}", .{ @tagName(self.state) });
        ifState: switch (self.state) {
            .ready => {
                self.state = .request;
                continue :ifState self.state;
            },
            .request => {
                //log.debug("Requesting Interface Updates...", .{});
                self._req_wifi_ifs.nextSeqID();
                try nl._80211.requestAllInterfaces(core_ctx.alloc, &self._req_wifi_ifs);
                time.sleep(1 * time.ns_per_ms);
                self._req_wiphys.nextSeqID();
                try nl._80211.requestAllWIPHY(core_ctx.alloc, &self._req_wiphys);
                time.sleep(1 * time.ns_per_ms);
                self._req_links.nextSeqID();
                try nl.route.requestAllIFLinks(core_ctx.alloc, &self._req_links);
                time.sleep(1 * time.ns_per_ms);
                self._req_addrs.nextSeqID();
                try nl.route.requestAllIFAddrs(core_ctx.alloc, &self._req_addrs);
                time.sleep(1 * time.ns_per_ms);
                self.state = .await_response;
                //log.debug(
                //    \\
                //    \\ WiFi IFs: {d}
                //    \\ WIPHYs:   {d}
                //    \\ Links:    {d}
                //    \\ Addrs:    {d}
                //    \\
                //    , .{
                //        self._req_wifi_ifs.seq_id,
                //        self._req_wiphys.seq_id,
                //        self._req_links.seq_id,
                //        self._req_addrs.seq_id,
                //    },
                //);
            },
            .await_response => {
                //log.debug(
                //    \\ Awaiting Responses
                //    \\-----------
                //    \\ WiFi IFs: {}
                //    \\ WIPHYs:   {}
                //    \\ Links:    {}
                //    \\ Addrs:    {}
                //    \\
                //    , .{
                //        self._req_wifi_ifs.checkResponse(),
                //        self._req_wiphys.checkResponse(),
                //        self._req_links.checkResponse(),
                //        self._req_addrs.checkResponse(),
                //    },
                //);
                // Ensure all requests have either gotten a response or timed out
                if (
                    self._req_wifi_ifs.checkResponse() and
                    self._req_wiphys.checkResponse() and
                    self._req_links.checkResponse() and
                    self._req_addrs.checkResponse()
                ) {
                    self.state = .parse;
                    continue :ifState self.state;
                }
            },
            .parse => {
                defer self.state = .request;
                //log.debug("Parsing Interface Updates...", .{});
                // Ensure all requests got a successful response
                const wifi_if_data: []const u8 = self._req_wifi_ifs.getResponse().? catch |err| {
                    log.debug("Issue w/ WiFi IF Data: {s}", .{ @errorName(err) });
                    self.state = .request;
                    continue :ifState self.state;
                };
                defer core_ctx.alloc.free(wifi_if_data);
                //log.debug("Wifi IF Data:\n{s}", .{ utils.HexFormatter{ .bytes = wifi_if_data[0..] } });
                const wiphy_data: []const u8 = self._req_wiphys.getResponse().? catch |err| {
                    log.debug("Issue w/ WIPHY Data: {s}", .{ @errorName(err) });
                    self.state = .request;
                    continue :ifState self.state;
                };
                defer core_ctx.alloc.free(wiphy_data);
                const link_data: []const u8 = self._req_links.getResponse().? catch |err| {
                    log.debug("Issue w/ Link Data: {s}", .{ @errorName(err) });
                    self.state = .request;
                    continue :ifState self.state;
                };
                defer core_ctx.alloc.free(link_data);
                const addr_data: []const u8 = self._req_addrs.getResponse().? catch |err| {
                    log.debug("Issue w/ Addr Data: {s}", .{ @errorName(err) });
                    self.state = .request;
                    continue :ifState self.state;
                };
                defer core_ctx.alloc.free(addr_data);
                //log.debug(
                //    \\Interface Update Data
                //    \\----------------
                //    \\ WiFi IFs: {d}B
                //    \\ WIPHYs:   {d}B
                //    \\ Links:    {d}B
                //    \\ Addrs:    {d}B
                //    \\
                //    , .{
                //        wifi_if_data.len,
                //        wiphy_data.len,
                //        link_data.len,
                //        addr_data.len,
                //    },
                //);
                // Parse each Interface element
                defer _ = self._arena.reset(.retain_capacity);
                //const wifi_if_arena = self._a_alloc.dupe(u8, wifi_if_data) catch @panic("OOM");
                const nl_wifi_ifs = try nl._80211.handleInterfaceBuf(self._a_alloc, wifi_if_data); 
                const nl_wiphys = try nl._80211.handleWIPHYBuf(self._a_alloc, wiphy_data); 
                const nl_links = try nl.route.handleIFLinksBuf(self._a_alloc, link_data); 
                const nl_addrs = try nl.route.handleIFAddrsBuf(self._a_alloc, addr_data); 
                // Update WiFi Interfaces Netlink Status
                updateIfs: for (nl_wifi_ifs) |wifi_if| {
                    var valid: bool = false;
                    const wiphy: nl._80211.Wiphy = nlWiphy: {
                        for (nl_wiphys) |nl_wiphy| {
                            if (wifi_if.WIPHY != nl_wiphy.WIPHY) continue;
                            break :nlWiphy nl_wiphy;
                        }
                        else continue :updateIfs;
                    };
                    const link: nl.route.IFInfoAndLink = nlLink: {
                        for (nl_links) |nl_link| {
                            if (wifi_if.IFINDEX != nl_link.info.index) continue;
                            break :nlLink nl_link;
                        }
                        else continue :updateIfs;
                    };
                    const if_name = core_ctx.alloc.dupe(u8, wifi_if.IFNAME[0..(wifi_if.IFNAME.len - 1)]) catch @panic("OOM");
                    const phy_name = core_ctx.alloc.dupe(u8, wiphy.WIPHY_NAME) catch @panic("OOM");
                    defer if (!valid) {
                        core_ctx.alloc.free(if_name);
                        core_ctx.alloc.free(phy_name);
                    };
                    const ips, const cidrs = ipAddrs: {
                        var ips: [10]?[4]u8 = .{ null } ** 10;
                        var cidrs: [10]?u8 = .{ null } ** 10;
                        var idx: u8 = 0;
                        for (nl_addrs) |addr| {
                            if (addr.info.index != wifi_if.IFINDEX) continue;
                            const ip = addr.addr.ADDRESS orelse continue;
                            const cidr = addr.info.prefix_len;
                            ips[idx] = ip;
                            cidrs[idx] = cidr;
                            idx += 1;
                        }
                        break :ipAddrs .{ ips, cidrs };
                    };
                    const channel: ?u32 = channel: {
                        const freq = wifi_if.WIPHY_FREQ orelse break :channel null;
                        break :channel @as(u32, @intCast(nl._80211.channelFromFreq(freq) catch break :channel null));
                    };
                    const ch_width: ?nl._80211.CHANNEL_WIDTH = chWidth: {
                        const raw_width = wifi_if.CHANNEL_WIDTH orelse break :chWidth null;
                        break :chWidth @enumFromInt(raw_width);
                    };
                    var add_if: Interface = .{
                        .index = @intCast(wifi_if.IFINDEX),
                        .name = if_name,
                        .mac = wifi_if.MAC,
                        .mode = wifi_if.IFTYPE orelse continue :updateIfs,
                        .channel = channel,
                        .ch_width = ch_width,
                        .phy_index = wifi_if.WIPHY,
                        .phy_name = phy_name,
                        .og_mac = link.link.PERM_ADDRESS orelse continue :updateIfs,
                        .state = link.info.flags,
                        .mtu = link.link.MTU,
                        .ips = ips,
                        .cidrs = cidrs,
                        .ssid = wifi_if.SSID,
                        .wiphy = try nl.parse.clone(core_ctx.alloc, nl._80211.Wiphy, wiphy),
                        .last_upd = try zeit.instant(.{}),
                    };
                    self.interfaces.mutex.lock();
                    defer self.interfaces.mutex.unlock();
                    if (self.interfaces.map.getEntry(add_if.og_mac)) |upd_if_entry| updIf: {
                        const upd_if = upd_if_entry.value_ptr;
                        if (add_if.index != upd_if.index) {
                            log.debug("Interface '{s}' has a new Index: {d}", .{ add_if.name, add_if.index });
                            if (upd_if.usage == .err) {
                                log.debug("Reset interface '{s}' from errored state.", .{ add_if.name });
                                break :updIf;
                            }
                        }
                        add_if.usage = upd_if.usage;
                        add_if.penalty_time = upd_if.penalty_time;
                        add_if.penalty = upd_if.penalty;
                        add_if.min_penalty = upd_if.min_penalty;
                        add_if.max_penalty = upd_if.max_penalty;
                        core_ctx.alloc.free(upd_if.name);
                        core_ctx.alloc.free(upd_if.phy_name);
                        nl.parse.freeBytes(core_ctx.alloc, nl._80211.Wiphy, upd_if.wiphy);
                    }
                    else {
                        log.info("New Interface Seen: ({s}) {s}", .{ MACF{ .bytes = add_if.mac[0..] }, add_if.name });
                    }
                    valid = true;
                    add_if._init = true;
                    self.interfaces.map.put(core_ctx.alloc, add_if.og_mac, add_if) catch @panic("OOM");
                }
            },
        }
        var rm_macs: [50][6]u8 = undefined;
        var rm_count: u8 = 0;
        var if_iter = self.interfaces.iterator();
        defer if_iter.unlock();
        while (if_iter.next()) |net_if_entry| {
            const net_if = net_if_entry.value_ptr;
            //log.debug("Working on IF '{s}'", .{ net_if.name });
            switch (net_if.usage) {
                // Check for new WiFi Interface
                .unavailable => {
                    for (core_ctx.config.avail_if_names) |avail_if_name| {
                        //log.debug("- Check name: {s} ({d}B) vs {s} ({d}B)", .{ net_if.name, net_if.name.len, avail_if_name, avail_if_name.len });
                        if (!mem.eql(u8, net_if.name, avail_if_name)) continue;
                        net_if.usage = .available;
                        log.info("Available Interface Found:\n{s}", .{ net_if });
                        if (core_ctx.config.profile.mask) |pro_mask| {
                            var mask_mac: [6]u8 = netdata.address.getRandomMAC(.ll);
                            if (pro_mask.oui) |mask_oui| @memcpy(mask_mac[0..3], mask_oui[0..]);
                            if (net_if.state & c(nl.route.IFF).UP != c(nl.route.IFF).DOWN) 
                                try net_if.modify(core_ctx, .{ .state = c(nl.route.IFF).DOWN });
                            if (mem.eql(u8, net_if.mac[0..], net_if.og_mac[0..]))
                                try net_if.modify(core_ctx, .{ .mac = mask_mac });
                            try net_if.modify(core_ctx, .{ .state = c(nl.route.IFF).UP });
                        }
                        break;
                    }
                },
                // Check for old WiFi Interface
                .available,
                .err,
                .connect,
                .scan,
                => {
                    const now = try zeit.instant(.{});
                    const since_upd = @divFloor((now.timestamp -| net_if.last_upd.timestamp), @as(i128, time.ns_per_ms));
                    if (since_upd < 5000) continue;
                    log.warn("Interface '{s}' is no longer available.", .{ net_if.name });
                    net_if.deinit(core_ctx.alloc);
                    rm_macs[rm_count] = net_if_entry.key_ptr.*;
                    rm_count +|= 1;
                },
                // Check for complete Modifications of the WiFi Interface
                .modify => |*mod_list| {
                    var seq_list: ArrayList(u32) = .empty;
                    defer seq_list.deinit(core_ctx.alloc);
                    for (mod_list.items) |mod| {
                        const mod_resp = mod.req_ctx.getResponse() orelse continue;
                        defer if (mod_resp) |resp_data| core_ctx.alloc.free(resp_data) else |_| {};
                        seq_list.append(core_ctx.alloc, mod.req_ctx.seq_id) catch @panic("OOM");
                        switch (mod.mod_field) {
                            .mac => |mac| {
                                if (mod_resp) |_|
                                    log.info("Changed MAC of '{s}' to '{s}'.", .{ net_if.name, MACF{ .bytes = mac[0..] } })
                                else |err|
                                    log.warn("Unable to change MAC of '{s}': {s}", .{ net_if.name, @errorName(err) });
                            },
                            .state => |state| {
                                if (mod_resp) |_|
                                    log.info("Changed State of '{s}' to '{s}'.", .{ net_if.name, Interface.IFStateF{ .flags = state } })
                                else |err|
                                    log.warn("Unable to change State of '{s}': {s}", .{ net_if.name, @errorName(err) });
                            },
                            .mode => |mode| {
                                if (mod_resp) |_|
                                    log.info("Changed Mode of '{s}' to '{s}'.", .{ net_if.name, @tagName(@as(nl._80211.IFTYPE, @enumFromInt(mode))) })
                                else |err|
                                    log.warn("Unable to change Mode of '{s}': {s}", .{ net_if.name, @errorName(err) });
                            },
                            .add_ip => |add_ip| {
                                if (mod_resp) |_|
                                    log.info("Added IP to '{s}': '{s}/{d}'", .{ net_if.name, IPF{ .bytes = add_ip.addr[0..] }, add_ip.cidr })
                                else |err|
                                    log.warn("Unable to add IP to '{s}': {s}", .{ net_if.name, @errorName(err) });
                            },
                            .del_ip => |del_ip| {
                                if (mod_resp) |_|
                                    log.info("Deleted IP from '{s}': '{s}/{d}'", .{ net_if.name, IPF{ .bytes = del_ip.addr[0..] }, del_ip.cidr })
                                else |err|
                                    log.warn("Unable to delete IP from '{s}': {s}", .{ net_if.name, @errorName(err) });
                            },
                            .channel => |ch| {
                                if (mod_resp) |_|
                                    log.info("Changed Channel of '{s}' to '{d} | {s}'", .{ net_if.name, ch.ch, @tagName(ch.width) })
                                else |err|
                                    log.warn("Unable to change channel of '{s}': {s}", .{ net_if.name, @errorName(err) });
                            },
                        }
                    }
                    for (seq_list.items) |seq| {
                        for (mod_list.items, 0..) |mod, idx| {
                            if (mod.req_ctx.seq_id != seq) continue;
                            core_ctx.alloc.destroy(mod);
                            _ = mod_list.orderedRemove(idx);
                            break;
                        }
                    }
                    if (mod_list.items.len == 0) {
                        mod_list.deinit(core_ctx.alloc);
                        net_if.usage = .available;
                    }
                },
                else => {},
            }
        }
        for (rm_macs[0..rm_count]) |mac| {
            _ = self.interfaces.map.remove(mac);
            log.warn("Removed Interface '{s}'.", .{ MACF{ .bytes = mac[0..] } });
        }
    }
};
