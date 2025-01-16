//! Interface Management

const std = @import("std");
const atomic = std.atomic;
const enums = std.enums;
const fmt = std.fmt;
const log = std.log.scoped(.interfaces);
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
const utils = @import("../utils.zig");
const c = utils.toStruct;

/// DisCo Usage State of an Interface
pub const UsageState = enum {
    unavailable,
    available,
    scanning,
    connecting,
    connected,
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

/// Interface Info
pub const Interface = struct {
    // Meta
    _init: bool = true,
    nl_sock: posix.socket_t,
    usage: UsageState = .unavailable,
    last_upd: zeit.Instant,
    // Details
    index: i32,
    name: []const u8,
    phy_index: u32,
    phy_name: []const u8,
    og_mac: [6]u8,
    mac: [6]u8,
    mode: u32,
    state: u32,
    mtu: usize,
    ips: [10]?[4]u8 = .{ null } ** 10,
    cidrs: [10]?u8 = .{ null } ** 10,

    pub fn format(
        self: @This(),
        _: []const u8,
        _: fmt.FormatOptions,
        writer: anytype,
    ) !void {
        var last_ts_buf: [50]u8 = .{ 0 } ** 50;
        const last_ts = try self.last_upd.time().bufPrint(last_ts_buf[0..], .rfc3339);
        try writer.print(
            \\({d}) {s} | {s}
            \\{s}
            \\- Phy:    ({d}) {s}
            \\- OG MAC: {s} ({s})
            \\- MAC:    {s} ({s})
            \\- Mode:   {s}
            \\- State:  {s}
            \\- MTU:    {d}
            \\
            , .{
                self.index, self.name, @tagName(self.usage),
                last_ts,
                self.phy_index, self.phy_name,
                MACF{ .bytes = self.og_mac[0..] }, try netdata.oui.findOUI(.short, self.og_mac),
                MACF{ .bytes = self.mac[0..] }, try netdata.oui.findOUI(.short, self.mac),
                @tagName(@as(nl._80211.IFTYPE, @enumFromInt(self.mode))),
                IFStateF{ .flags = self.state },
                self.mtu,
            }
        );
        if (self.ips[0] == null) return;
        try writer.print("- IPs:\n", .{});
        for (self.ips, self.cidrs) |_ip, _cidr| {
            const ip = _ip orelse return;
            const cidr = _cidr orelse continue;
            try writer.print("  - {s}/{d}\n", .{ IPF{ .bytes = ip[0..] }, cidr });
        }
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
        all,
        ips,
        mac,
    };
    /// Restore the Interface.
    pub fn restore(self: *@This(), alloc: mem.Allocator, kind: RestoreKind) void {
        log.info("- Restoring Interface '{s}'...", .{ self.name });
        if (kind == .ips or kind == .all) {
            for (self.ips, self.cidrs) |_ip, _cidr| {
                const ip = _ip orelse continue;
                const cidr = _cidr orelse 24;
                defer nl.route.deleteIP(
                    alloc,
                    self.index,
                    ip,
                    cidr,
                ) catch |err| switch (err) {
                    error.ADDRNOTAVAIL => {},
                    else => log.warn(" - Could not remove IP '{s}'!", .{ IPF{ .bytes = ip[0..] } }),
                };
                log.info(" - Removed IP '{s}/{d}'", .{ IPF{ .bytes = ip[0..] }, cidr });
            }
        }
        if (kind == .mac or kind == .all) {
            if (nl.route.setMAC(self.index, self.og_mac))
                log.info(" - Restored Orignal MAC '{s}'.", .{ MACF{ .bytes = self.og_mac[0..] } })
            else |_|
                log.warn(" - Could not restore Interface '{s}' to its orignal MAC '{s}'.", .{ self.name, MACF{ .bytes = self.og_mac[0..] } });
        }
        log.info("- Restored Interface '{s}'.", .{ self.name });
    }

    /// Free the allocated portions of this Interface and close the Netlink Socket.
    pub fn stop(self: *@This(), alloc: mem.Allocator) void {
        self.restore(alloc, .all);
        posix.close(self.nl_sock);
        self.deinit(alloc);
    }
};

/// Interfaces Context
pub const Context = struct {
    /// Available Interfaces
    interfaces: *core.ThreadHashMap(i32, Interface),
    /// WiFi Physical Devices (WIPHYs)
    wiphys: *core.ThreadHashMap(u32, nl._80211.Wiphy),
    /// WiFi Interfaces
    wifi_ifs: *core.ThreadHashMap(i32, nl._80211.Interface),
    /// Links
    links: *core.ThreadHashMap(i32, nl.route.IFInfoAndLink),
    /// Addresses
    addresses: *core.ThreadHashMap([4]u8, nl.route.IFInfoAndAddr),

    /// Initialize all Maps.
    pub fn init(alloc: mem.Allocator) !@This() {
        var self: @This() = undefined;
        inline for (meta.fields(@This())) |field| {
            switch (field.type) {
                inline else => |f_ptr_type| {
                    const f_type = @typeInfo(f_ptr_type).Pointer.child;
                    const ctx_field = try alloc.create(f_type);
                    ctx_field.* = f_type{};
                    @field(self, field.name) = ctx_field;
                }
            }
        }
        return self;
    }

    /// Restore All Interfaces to their Original MAC Addresses and remove any IP Addresses.
    pub fn restore(self: *@This(), alloc: mem.Allocator) void {
        if (self.interfaces.count() == 0) return;
        var if_iter = self.interfaces.iterator();
        defer if_iter.unlock();
        while (if_iter.next()) |if_entry| {
            const res_if = if_entry.value_ptr;
            if (res_if.usage == .unavailable) continue;
            res_if.restore(alloc, .all);
        }
    }

    /// Deinitialize all Maps.
    pub fn deinit(self: *@This(), alloc: mem.Allocator) void {
        var if_iter = self.interfaces.iterator();
        while (if_iter.next()) |if_entry| if_entry.value_ptr.stop(alloc);
        if_iter.unlock();
        self.interfaces.deinit(alloc);
        core.resetNLMap(alloc, u32, nl._80211.Wiphy, self.wiphys);
        self.wiphys.deinit(alloc);
        core.resetNLMap(alloc, i32, nl._80211.Interface, self.wifi_ifs);
        self.wifi_ifs.deinit(alloc);
        core.resetNLMap(alloc, i32, nl.route.IFInfoAndLink, self.links);
        self.links.deinit(alloc);
        core.resetNLMap(alloc, [4]u8, nl.route.IFInfoAndAddr, self.addresses);
        self.addresses.deinit(alloc);
    }
};

/// Initialize Netlink Socket f/ the provided Interface (`if_index`).
pub fn initIFSock(
    if_index: i32,
    interval: *const usize,
) !posix.socket_t {
    const info = nl._80211.ctrl_info orelse return error.NL80211ControlInfoNotInitialized;
    const group_id = info.MCAST_GROUPS.get("scan").?;
    const nl_addr: posix.sockaddr.nl = .{
        .pid = 0,
        .groups = @as(u32, 1) << @intCast(group_id - 1),
    };
    const nl_sock = nlSock: {
        if (interval.* >= 1000 * time.ns_per_ms) {
            const timeout: i32 = @intCast(@divFloor(interval.*, time.ns_per_s));
            break :nlSock try nl.initSock(nl.NETLINK.GENERIC, .{ .tv_sec = timeout, .tv_usec = 0 });
        }
        const timeout: i32 = @intCast(@divFloor(interval.*, time.ns_per_us));
        break :nlSock try nl.initSock(nl.NETLINK.GENERIC, .{ .tv_sec = 0, .tv_usec = timeout });
    };
    errdefer posix.close(nl_sock);
    try posix.bind(nl_sock, @ptrCast(&nl_addr), @sizeOf(posix.sockaddr.nl));
    try posix.setsockopt(
        nl_sock,
        posix.SOL.NETLINK,
        nl.NETLINK_OPT.ADD_MEMBERSHIP,
        mem.toBytes(group_id)[0..],
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
    if_maps: *Context,
    config: *core.Core.Config,
) void {
    var err_count: usize = 0;
    while (active.load(.acquire)) {
        defer {
            if (err_count > 10) @panic("Interface Tracking encountered too many errors to continue!");
            time.sleep(interval.* * 5);
        }
        updInterfaces(
            alloc,
            if_maps,
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
        defer if_ctx.interfaces.mutex.unlock();
        var _last_if = if_ctx.interfaces.map.get(wifi_if.key_ptr.*);
        if (_last_if == null)
            log.info("New Interface Found: ({d}) {s}", .{ wifi_if.key_ptr.*, wifi_if.value_ptr.IFNAME });
        var add_if: Interface = _last_if orelse undefined;
        add_if._init = false;
        add_if.nl_sock =
            if (_last_if) |last_if| last_if.nl_sock
            else try initIFSock(wifi_if.key_ptr.*, interval);
        add_if.usage = usage: {
            if (_last_if) |last_if| break :usage last_if.usage;
            const avail_ifs = config.available_ifs orelse break :usage .unavailable;
            for (avail_ifs) |avail_idx| {
                if (wifi_if.key_ptr.* != avail_idx) continue;
                break :usage .available;
            }
            const avail_if_names = config.avail_if_names orelse break :usage .unavailable;
            for (avail_if_names) |avail_name| {
                if (!mem.eql(u8, wifi_if.value_ptr.IFNAME, avail_name)) continue;
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
        if (add_if.usage != .unavailable) {
            if (if_ctx.interfaces.map.get(add_if.index) == null) newIF: {
                log.info("Available Interface Found:\n{s}", .{ add_if });
                if (!config.use_mask) break :newIF;
                var mask_mac: [6]u8 = netdata.address.getRandomMAC(.ll);
                if (config.profile_mask.oui) |mask_oui| @memcpy(mask_mac[0..3], mask_oui[0..]);
                try nl.route.setMAC(add_if.index, mask_mac);
                log.info("- Changed Interface '{s}' MAC to: {s}", .{ add_if.name, MACF{ .bytes = mask_mac[0..] } });
            }
            if (add_if.state & c(nl.route.IFF).UP == c(nl.route.IFF).DOWN) {
                try nl.route.setState(add_if.index, c(nl.route.IFF).UP);
                log.info("Available Interface '{d}' set to Down. Setting to Up.", .{ add_if.index });
            }
        }
        if (_last_if) |*last_if| last_if.deinit(alloc);
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
        net_if.value_ptr.deinit(alloc);
        rm_idxs[rm_count] = net_if.key_ptr.*;
        rm_count +|= 1;
    }
    if_iter.unlock();
    for (rm_idxs[0..rm_count]) |_idx| {
        const idx = _idx orelse break;
        _ = if_ctx.interfaces.remove(idx);
    }
}

