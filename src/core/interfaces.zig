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

const netdata = @import("../netdata.zig");
const address = netdata.address;
const MACF = address.MACFormatter;
const IPF = address.IPFormatter;
const core = @import("../core.zig");
const nl = @import("../netlink.zig");
const protocols = @import("../protocols.zig");
const dns = protocols.dns;
const utils = @import("../utils.zig");
const c = utils.toStruct;


/// Interface Info
pub const Interface = struct {
    // Meta
    _init: bool = false,
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

    /// DisCo Usage State of an Interface
    pub const UsageState = union(enum) {
        err: anyerror,
        unavailable,
        modify: ArrayList(*ModifyContext),
        available,
        scan,
        connect,
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

    /// Free the allocated portions of this Interface.
    pub fn deinit(self: *@This(), alloc: mem.Allocator) void {
        if (!self._init) return;
        alloc.free(self.name);
        alloc.free(self.phy_name);
        self._init = false;
    }

    /// Restoration Kind
    pub const RestoreKind = enum {
        dns,
        ips,
        mac,
    };
    /// Restore the Interface.
    pub fn restore(self: *@This(), alloc: mem.Allocator, kinds: []const RestoreKind) void {
        log.info("- Restoring Interface '{s}'...", .{ self.name });
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
    _arena: heap.ArenaAllocator,
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
    /// State
    state: State,
    /// Available Interfaces
    interfaces: utils.ThreadHashMap([6]u8, Interface),
    /// Interface Timeout
    if_timeout: usize = 5000,

    pub const State = enum {
        ready,
        request,
        await_response,
        parse,
    };

    /// Initialize the Interface Context.
    pub fn init(core_ctx: *core.Core) !@This() {
        var self: @This() = undefined;
        self._arena = .init(core_ctx.alloc);
        self._a_alloc = self._arena.allocator();
        self.state = .ready;
        self.interfaces = .empty;
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
        self._arena.deinit();
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
        log.debug("Updating Interfaces: {s}", .{ @tagName(self.state) });
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
                    var good: bool = false;
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
                    const if_name = core_ctx.alloc.dupe(u8, wifi_if.IFNAME) catch @panic("OOM");
                    const phy_name = core_ctx.alloc.dupe(u8, wiphy.WIPHY_NAME) catch @panic("OOM");
                    defer if (!good) {
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
                        .last_upd = try zeit.instant(.{}),
                    };
                    if (self.interfaces.get(add_if.og_mac)) |upd_if| updIf: {
                        if (add_if.index != upd_if.index) {
                            log.debug("Interface '{s}' has a new Index: {d}", .{ add_if.name, add_if.index });
                            if (upd_if.usage == .err) {
                                log.debug("Reset interface '{s}' from errored state.", .{ add_if.name });
                                break :updIf;
                            }
                        }
                        add_if.usage = upd_if.usage;
                    }
                    else {
                        log.info("New Interface Seen: ({s}) {s}", .{ MACF{ .bytes = add_if.mac[0..] }, add_if.name });
                    }
                    good = true;
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
                        if (!mem.eql(u8, net_if.name[0..(net_if.name.len - 1)], avail_if_name)) continue;
                        net_if.usage = .available;
                        log.info("Available Interface Found:\n{s}", .{ net_if });
                        if (core_ctx.config.profile.mask) |pro_mask| {
                            var mask_mac: [6]u8 = netdata.address.getRandomMAC(.ll);
                            if (pro_mask.oui) |mask_oui| @memcpy(mask_mac[0..3], mask_oui[0..]);
                            if (net_if.state & c(nl.route.IFF).UP != c(nl.route.IFF).DOWN) 
                                try net_if.modify(core_ctx, .{ .state = c(nl.route.IFF).DOWN });
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
                    //if_iter.unlock();
                },
                // Check for complete Modifications of the WiFi Interface
                .modify => |*mod_list| {
                    var idx_list: ArrayList(usize) = .empty;
                    defer idx_list.deinit(core_ctx.alloc);
                    for (mod_list.items, 0..) |mod, idx| {
                        const mod_resp = mod.req_ctx.getResponse() orelse continue;
                        idx_list.append(core_ctx.alloc, idx) catch @panic("OOM");
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
                    var idx = mod_list.items.len;
                    while (idx > 0) : (idx -= 1) {
                        if (mem.indexOfScalar(usize, idx_list.items, idx) == null)
                            continue;
                        core_ctx.alloc.destroy(mod_list.items[idx]);
                        _ = mod_list.swapRemove(idx);
                    }
                    net_if.usage = .available;
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

















// ==============================================================
/// PRE-ASYNC
// ==============================================================



/// Initialize Netlink Socket f/ the provided Interface (`if_index`).
pub fn initIFSock(
    if_index: i32,
    interval: *const usize,
) !posix.socket_t {
    const nl_sock = nlSock: {
        if (interval.* >= 1000 * time.ns_per_ms) {
            const timeout: i32 = @intCast(@divFloor(interval.*, time.ns_per_s));
            break :nlSock try nl.initSock(nl.NETLINK.GENERIC, .{ .sec = timeout, .usec = 0 });
        }
        const timeout: i32 = @intCast(@divFloor(interval.*, time.ns_per_us));
        break :nlSock try nl.initSock(nl.NETLINK.GENERIC, .{ .sec = 0, .usec = timeout });
    };
    errdefer posix.close(nl_sock);
    const info = nl._80211.ctrl_info orelse return error.NL80211ControlInfoNotInitialized;
    const scan_id = info.MCAST_GROUPS.get("scan").?;
    try posix.setsockopt(
        nl_sock,
        posix.SOL.NETLINK,
        nl.NETLINK_OPT.ADD_MEMBERSHIP,
        mem.toBytes(scan_id)[0..],
    );
    try posix.setsockopt(
        nl_sock,
        posix.SOL.SOCKET, 
        posix.SO.PRIORITY,
        mem.toBytes(@as(u32, math.maxInt(u32)))[0..],
    );
    try nl._80211.takeOwnership(nl_sock, if_index);
    return nl_sock;
}

/// Track Interfaces
pub fn trackInterfaces(
    alloc: mem.Allocator,
    active: *const atomic.Value(bool),
    interval: *const usize,
    if_ctx: *Context,
    config: *core.Core.Config,
) void {
    var track_count: u8 = 0;
    var err_count: usize = 0;
    const err_max: usize = 10;
    while (active.load(.acquire)) {
        defer {
            track_count +%= 1;
            if (track_count % err_max == 0) err_count -|= 1;
            if (err_count > err_max) @panic("Interface Tracking encountered too many errors to continue!");
            time.sleep(interval.*);
        }
        updInterfaces(
            alloc,
            if_ctx,
            config,
            interval,
        ) catch |err| {
            log.err("Interface Update Error: {s}", .{ @errorName(err) });
            err_count += 1;
            continue;
        };
    }
}

/// Update Interfaces
pub fn updInterfaces(
    alloc: mem.Allocator,
    if_ctx: *Context,
    config: *core.Core.Config,
    interval: *const usize,
) !void {
    trackWiFiIFs: {
        // Reset
        core.resetNLMap(
            alloc,
            i32,
            nl._80211.Interface,
            if_ctx.wifi_ifs,
        );
        // Parse
        const nl_wifi_ifs = nl._80211.getAllInterfaces(alloc) catch |err| {
            log.err("Could not parse Netlink WiFi Interfaces: {s}", .{ @errorName(err) });
            break :trackWiFiIFs;
        };
        errdefer for (nl_wifi_ifs) |wifi_if| nl.parse.freeBytes(alloc, nl._80211.Interface, wifi_if);
        defer alloc.free(nl_wifi_ifs);
        if (nl_wifi_ifs.len == 0) {
            log.warn("No Interfaces Found.", .{});
            break :trackWiFiIFs;
        }
        for (nl_wifi_ifs) |wifi_if| {
            //log.debug("WiFi IF: {d}", .{ wifi_if.IFINDEX });
            const _old = try if_ctx.wifi_ifs.fetchPut(alloc, @intCast(wifi_if.IFINDEX), wifi_if);
            if (_old) |old| nl.parse.freeBytes(alloc, nl._80211.Interface, old.value);
        }
    }
    // TODO Figure out if this can be done w/ `getAllWIPHY()`.
    trackWiphys: {
        // Reset
        core.resetNLMap(
            alloc,
            u32,
            nl._80211.Wiphy,
            if_ctx.wiphys,
        );
        // Parse
        //const nl_wiphys = nl._80211.getAllWIPHY(alloc) catch |err| {
        //    log.err("Could not parse Netlink WiFi Physical Devices: {s}", .{ @errorName(err) });
        //    break :trackWiphys;
        //};
        //errdefer for (nl_wiphys) |wiphy| nl.parse.freeBytes(alloc, nl._80211.Wiphy, wiphy);
        //defer alloc.free(nl_wiphys);
        //if (nl_wiphys.len == 0) {
        //    log.warn("No WiFi Physical Devices Found.", .{});
        //    break :trackWiphys;
        //}
        //for (nl_wiphys) |wiphy| {
        //    log.debug("WIPHY: ({d}) {s}", .{ wiphy.WIPHY, wiphy.WIPHY_NAME });
        //    var add_wiphy = wiphy;
        //    if (wiphy.WIPHY_BANDS == null) {
        //        nl.parse.freeBytes(alloc, nl._80211.Wiphy, wiphy);
        //        continue;
        //    }
        //    const _old = try if_ctx.wiphys.fetchPut(alloc, wiphy.WIPHY, wiphy);
        //    if (_old) |old| nl.parse.freeBytes(alloc, nl._80211.Wiphy, old.value);
        //}
        var if_iter = if_ctx.wifi_ifs.iterator();
        defer if_iter.unlock();
        while (if_iter.next()) |wifi_if| {
            const wiphy = nl._80211.getWIPHY(alloc, wifi_if.key_ptr.*, wifi_if.value_ptr.WIPHY) catch continue;
            const _old = try if_ctx.wiphys.fetchPut(alloc, wiphy.WIPHY, wiphy);
            if (_old) |old| nl.parse.freeBytes(alloc, nl._80211.Wiphy, old.value);
        }
        break :trackWiphys;
    }
    trackLinks: {
        // Reset
        core.resetNLMap(
            alloc,
            i32,
            nl.route.IFInfoAndLink,
            if_ctx.links,
        );
        // Parse
        const nl_links = nl.route.getAllIFLinks(alloc) catch |err| {
            log.err("Could not parse Netlink Interface Links: {s}", .{ @errorName(err) });
            break :trackLinks;
        };
        errdefer for (nl_links) |link| nl.parse.freeBytes(alloc, nl.route.InterfaceLink, link.link);
        defer alloc.free(nl_links);
        if (nl_links.len == 0) {
            log.warn("No Interfaces Found.", .{});
            break :trackLinks;
        }
        for (nl_links) |nl_link| {
            //log.debug("Link: {d}", .{ nl_link.info.index });
            //if (
            //    nl_link.link.OPERSTATE == c(nl.route.IF_OPER).UNKNOWN or
            //    nl_link.link.OPERSTATE == c(nl.route.IF_OPER).NOTPRESENT
            //) {
            //    nl.parse.freeBytes(alloc, nl.route.IFInfoAndLink, nl_link);
            //    const _old = if_ctx.links.getEntry(nl_link.info.index);
            //    defer if_ctx.links.mutex.unlock();
            //    if (_old) |old| {
            //        nl.parse.freeBytes(alloc, nl.route.IFInfoAndLink, old.value_ptr.*);
            //        _ = if_ctx.links.map.remove(old.value_ptr.info.index);
            //    }
            //    continue;
            //}
            const _old = try if_ctx.links.fetchPut(alloc, nl_link.info.index, nl_link);
            if (_old) |old| nl.parse.freeBytes(alloc, nl.route.IFInfoAndLink, old.value);
        }
    }
    trackAddrs: {
        // Reset
        core.resetNLMap(
            alloc,
            [4]u8,
            nl.route.IFInfoAndAddr,
            if_ctx.addresses,
        );
        // Parse
        const nl_addrs = nl.route.getAllIFAddrs(alloc) catch |err| {
            log.err("Could not parse Netlink Interface Addresses: {s}", .{ @errorName(err) });
            break :trackAddrs;
        };
        errdefer for (nl_addrs) |nl_addr| nl.parse.freeBytes(alloc, nl.route.InterfaceAddress, nl_addr.addr);
        defer alloc.free(nl_addrs);
        if (nl_addrs.len == 0) {
            log.warn("No Interfaces Found.", .{});
            break :trackAddrs;
        }
        var links_iter = if_ctx.links.iterator();
        defer links_iter.unlock();
        nlAddrs: for (nl_addrs) |nl_addr| {
            defer links_iter._iter.index = 0;
            if (nl_addr.info.family != nl.AF.INET) {
                nl.parse.freeBytes(alloc, nl.route.IFInfoAndAddr, nl_addr);
                continue;
            }
            while (links_iter.next()) |link| {
                if (nl_addr.info.index != link.key_ptr.*) continue;
                const _old = try if_ctx.addresses.fetchPut(alloc, nl_addr.addr.ADDRESS orelse continue, nl_addr);
                if (_old) |old| nl.parse.freeBytes(alloc, nl.route.IFInfoAndAddr, old.value);
                continue :nlAddrs;
            }
            nl.parse.freeBytes(alloc, nl.route.IFInfoAndAddr, nl_addr);
        }
    }
    var wifi_ifs_iter = if_ctx.wifi_ifs.iterator();
    defer wifi_ifs_iter.unlock();
    //log.debug("Interfaces:", .{});
    while (wifi_ifs_iter.next()) |wifi_if| {
        if_ctx.interfaces.mutex.lock();
        defer {
            time.sleep(interval.*);
            if_ctx.interfaces.mutex.unlock();
        }
        var _last_if_entry = if_ctx.interfaces.map.getEntry(wifi_if.key_ptr.*);
        //if (_last_if_entry) |*last_if_entry| checkLink: {
        //    const last_if = last_if_entry.value_ptr;
        //    if (last_if.usage == .unavailable) break :checkLink;
        //    defer if_ctx.links.mutex.unlock();
        //    const link_info = if_ctx.links.getEntry(wifi_if.key_ptr.*) orelse {
        //        log.warn("Interface Index '{d}' is no longer available.", .{ wifi_if.key_ptr.* });
        //        last_if.usage = .unavailable;
        //        last_if.deinit(alloc);
        //        _ = if_ctx.interfaces.map.remove(wifi_if.key_ptr.*);
        //        continue;
        //    };
        //    const link = link_info.value_ptr.link;
        //    if (
        //        //link.OPERSTATE != c(nl.route.IF_OPER).UNKNOWN and 
        //        link.OPERSTATE != c(nl.route.IF_OPER).NOTPRESENT
        //    ) break :checkLink;
        //    log.warn("Interface Index '{d}' is no longer available.", .{ wifi_if.key_ptr.* });
        //    last_if.usage = .unavailable;
        //    last_if.deinit(alloc);
        //    _ = if_ctx.interfaces.map.remove(wifi_if.key_ptr.*);
        //    continue;
        //}
        //else
        if (_last_if_entry == null)
            log.info("New Interface Seen: ({d}) {s}", .{ wifi_if.key_ptr.*, wifi_if.value_ptr.IFNAME });
        var add_if: Interface = if (_last_if_entry) |li_entry| li_entry.value_ptr.* else undefined;
        add_if._init = false;
        add_if.nl_sock =
            if (_last_if_entry) |last_if_entry| last_if_entry.value_ptr.nl_sock
            else try initIFSock(wifi_if.key_ptr.*, interval);
        add_if.usage = usage: {
            if (_last_if_entry) |last_if_entry| break :usage last_if_entry.value_ptr.usage;
            for (config.avail_if_indexes) |avail_idx| {
                if (wifi_if.key_ptr.* != avail_idx) continue;
                break :usage .available;
            }
            for (config.avail_if_names) |avail_name| {
                const if_name = mem.trim(u8, wifi_if.value_ptr.IFNAME, ascii.whitespace[0..] ++ &[_]u8{ 0 });
                if (!mem.eql(u8, if_name, avail_name)) continue;
                //log.debug("Avail IF Name Match: ({d}) {s}", .{ wifi_if.key_ptr.*, avail_name });
                break :usage .available;
            }
            break :usage .unavailable;
        };
        add_if.index = wifi_if.key_ptr.*;
        add_if.last_upd = try zeit.instant(.{});
        add_if.name = alloc.dupe(u8, wifi_if.value_ptr.IFNAME) catch @panic("OOM");
        add_if.mac = wifi_if.value_ptr.MAC;
        add_if.mode = wifi_if.value_ptr.IFTYPE orelse {
            alloc.free(add_if.name);
            continue;
        };
        add_if.phy_index = wifi_if.value_ptr.WIPHY;
        wiphy: {
            const wiphy = if_ctx.wiphys.get(wifi_if.value_ptr.WIPHY) orelse {
                alloc.free(add_if.name);
                continue;
            };
            add_if.phy_name = alloc.dupe(u8, wiphy.WIPHY_NAME) catch @panic("OOM");
            break :wiphy;
        }
        defer if (!add_if._init) {
            alloc.free(add_if.name);
            alloc.free(add_if.phy_name);
        };
        link: {
            const link = if_ctx.links.get(add_if.index) orelse continue;
            add_if.state = link.info.flags;
            add_if.mtu = link.link.MTU;
            add_if.og_mac = link.link.PERM_ADDRESS orelse link.link.ADDRESS orelse continue;
            break :link;
        }
        addr: {
            add_if.ips = .{ null } ** 10;
            add_if.cidrs = .{ null } ** 10;
            var addrs_iter = if_ctx.addresses.iterator();
            defer addrs_iter.unlock();
            newIP: while (addrs_iter.next()) |addr| {
                const new_ip = addr.value_ptr.addr.ADDRESS orelse continue;
                if (addr.value_ptr.info.index != wifi_if.key_ptr.*) continue;
                for (add_if.ips[0..]) |*_ip| {
                    if (_ip.*) |ip| {
                        //log.debug("Existing IP: {s}. New IP: {s}", .{ IPF{ .bytes = ip[0..] }, IPF{ .bytes = new_ip[0..] } });
                        if (mem.eql(u8, ip[0..], new_ip[0..])) continue :newIP;
                        continue;
                    }
                    _ip.* = new_ip;
                    break;
                }
                const new_cidr = addr.value_ptr.info.prefix_len;
                for (add_if.cidrs[0..]) |*cidr| {
                    if (cidr.*) |_| continue;
                    cidr.* = new_cidr;
                    break;
                }
            }
            break :addr;
        }
        if (add_if.usage != .unavailable) setUpIF: {
            if (if_ctx.interfaces.map.get(add_if.index) == null) {
                log.info("Available Interface Found:\n{s}", .{ add_if });
                if (config.profile.mask) |pro_mask| {
                    var mask_mac: [6]u8 = netdata.address.getRandomMAC(.ll);
                    if (pro_mask.oui) |mask_oui| @memcpy(mask_mac[0..3], mask_oui[0..]);
                    nl.route.setMAC(add_if.index, mask_mac) catch {
                        add_if.usage = .errored;
                        break :setUpIF;
                    };
                    log.info("- Changed Interface '{s}' MAC to: {s}", .{ add_if.name, MACF{ .bytes = mask_mac[0..] } });
                }
            }
            if (add_if.state & c(nl.route.IFF).UP == c(nl.route.IFF).DOWN) {
                try nl.route.setState(add_if.index, c(nl.route.IFF).UP);
                log.info("- Set Interface '{d}' to Up.", .{ add_if.index });
            }
        }
        if (_last_if_entry) |*last_if_entry| last_if_entry.value_ptr.deinit(alloc);
        add_if._init = true;
        try if_ctx.interfaces.map.put(alloc, add_if.index, add_if);
    }
    const now = try zeit.instant(.{});
    var rm_idxs: [50]?i32 = .{ null } ** 50;
    var rm_count: u8 = 0;
    var if_iter = if_ctx.interfaces.iterator();
    errdefer if_iter.unlock();
    while (if_iter.next()) |net_if| {
        const since_upd = @divFloor((now.timestamp -| net_if.value_ptr.last_upd.timestamp), @as(i128, time.ns_per_ms));
        if (since_upd < 5000) continue;
        log.warn("Interface Index '{d}' is no longer available.", .{ net_if.key_ptr.* });
        net_if.value_ptr.deinit(alloc);
        rm_idxs[rm_count] = net_if.key_ptr.*;
        rm_count +|= 1;
    }
    if_iter.unlock();
    for (rm_idxs[0..rm_count]) |_idx| {
        const idx = _idx orelse break;
        _ = if_ctx.interfaces.remove(idx);
        log.warn("Removed Interface Index '{d}'.", .{ idx });
    }
}

