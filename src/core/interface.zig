//! Interface Management

const std = @import("std");
const fmt = std.fmt;
const log = std.log;
const mem = std.mem;
const time = std.time;

const zeit = @import("zeit");

const netdata = @import("../netdata.zig");
const address = netdata.address;
const MACF = address.MACFormatter;
const IPF = address.IPFormatter;
const core = @import("../core.zig");
const nl = @import("../nl.zig");


/// Interface Info
pub const Interface = struct {
    index: i32,
    last_upd: zeit.Instant,
    name: []const u8,
    phy_index: u32,
    phy_name: []const u8,
    mac: [6]u8,
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
            \\{s}
            \\({d}) {s}
            \\- Phy: ({d}) {s}
            \\- MAC: {s} ({s})
            \\- MTU: {d}
            \\
            , .{
                last_ts,
                self.index,
                self.name,
                self.phy_index,
                self.phy_name,
                MACF{ .bytes = self.mac[0..] },
                try netdata.oui.findOUI(.short, .station, self.mac),
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

    /// Free the allocated portions of this Interface
    pub fn deinit(self: @This(), alloc: mem.Allocator) void {
        alloc.free(self.name);
        alloc.free(self.phy_name);
    }
};

/// Interface Maps
pub const InterfaceMaps = struct {
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
};

/// Track Interfaces
pub fn trackInterfaces(
    alloc: mem.Allocator,
    active: *const bool,
    interval: *const usize,
    if_maps: *InterfaceMaps,
) !void {
    while (active.*) {
        try updInterfaces(
            alloc,
            if_maps,
        );
        time.sleep(interval.*);
    }
}

/// Update Interfaces
pub fn updInterfaces(
    alloc: mem.Allocator,
    if_maps: *InterfaceMaps,
) !void {
    trackWiFiIFs: {
        // Reset
        resetIFMap(
            alloc,
            i32,
            nl._80211.Interface,
            if_maps.wifi_ifs,
        );
        // Parse
        const nl_wifi_ifs = nl._80211.getAllInterfaces(alloc) catch |err| {
            log.err("Could not parse Netlink WiFi Interfaces: {s}", .{ @errorName(err) });
            break :trackWiFiIFs;
        };
        defer alloc.free(nl_wifi_ifs);
        if (nl_wifi_ifs.len == 0) {
            log.warn("No Interfaces Found.", .{});
            break :trackWiFiIFs;
        }
        for (nl_wifi_ifs) |wifi_if| {
            log.debug("WiFi IF: {d}", .{ wifi_if.IFINDEX });
            const _old = try if_maps.wifi_ifs.fetchPut(alloc, @intCast(wifi_if.IFINDEX), wifi_if);
            if (_old) |old| nl.parse.freeBytes(alloc, nl._80211.Interface, old.value);
        }
    }
    trackWiphys: {
        // Reset
        resetIFMap(
            alloc,
            u32,
            nl._80211.Wiphy,
            if_maps.wiphys,
        );
        // Parse
        const nl_wiphys = nl._80211.getAllWIPHY(alloc) catch |err| {
            log.err("Could not parse Netlink WiFi Physical Devices: {s}", .{ @errorName(err) });
            break :trackWiphys;
        };
        defer alloc.free(nl_wiphys);
        if (nl_wiphys.len == 0) {
            log.warn("No WiFi Physical Devices Found.", .{});
            break :trackWiphys;
        }
        for (nl_wiphys) |wiphy| {
            log.debug("WIPHY: ({d}) {s}", .{ wiphy.WIPHY, wiphy.WIPHY_NAME });
            const _old = try if_maps.wiphys.fetchPut(alloc, wiphy.WIPHY, wiphy);
            if (_old) |old| nl.parse.freeBytes(alloc, nl._80211.Wiphy, old.value);
        }
    }
    trackLinks: {
        // Reset
        resetIFMap(
            alloc,
            i32,
            nl.route.IFInfoAndLink,
            if_maps.links,
        );
        // Parse
        const nl_links = nl.route.getAllIFLinks(alloc) catch |err| {
            log.err("Could not parse Netlink Interface Links: {s}", .{ @errorName(err) });
            break :trackLinks;
        };
        defer alloc.free(nl_links);
        if (nl_links.len == 0) {
            log.warn("No Interfaces Found.", .{});
            break :trackLinks;
        }
        for (nl_links) |link| {
            log.debug("Link: {d}", .{ link.info.index });
            const _old = try if_maps.links.fetchPut(alloc, link.info.index, link);
            if (_old) |old| nl.parse.freeBytes(alloc, nl.route.IFInfoAndLink, old.value);
        }
    }
    trackAddrs: {
        // Reset
        resetIFMap(
            alloc,
            [4]u8,
            nl.route.IFInfoAndAddr,
            if_maps.addresses,
        );
        // Parse
        const nl_addrs = nl.route.getAllIFAddrs(alloc) catch |err| {
            log.err("Could not parse Netlink Interface Addresses: {s}", .{ @errorName(err) });
            break :trackAddrs;
        };
        defer alloc.free(nl_addrs);
        if (nl_addrs.len == 0) {
            log.warn("No Interfaces Found.", .{});
            break :trackAddrs;
        }
        var links_iter = if_maps.links.iterator();
        defer links_iter.unlock();
        while (links_iter.next()) |link| {
            log.debug("IF: {d}", .{ link.key_ptr.* });
            for (nl_addrs) |addr| {
                if (
                    addr.info.index != link.key_ptr.* or
                    addr.info.family != nl.AF.INET
                ) {
                    //nl.parse.freeBytes(alloc, nl.route.IFInfoAndAddr, addr);
                    continue;
                }
                const _old = try if_maps.addresses.fetchPut(alloc, addr.addr.ADDRESS orelse continue, addr);
                if (_old) |old| nl.parse.freeBytes(alloc, nl.route.IFInfoAndAddr, old.value);
            }
        }
    }
    var wifi_ifs_iter = if_maps.wifi_ifs.iterator();
    defer wifi_ifs_iter.unlock();
    log.debug("Interfaces:", .{});
    while (wifi_ifs_iter.next()) |wifi_if| {
        var add_if: Interface = undefined;
        add_if.index = wifi_if.key_ptr.*;
        add_if.last_upd = try zeit.instant(.{});
        add_if.name = alloc.dupe(u8, wifi_if.value_ptr.IFNAME) catch @panic("OOM");
        add_if.mac = wifi_if.value_ptr.MAC;
        add_if.phy_index = wifi_if.value_ptr.WIPHY;
        wiphy: {
            const wiphy = if_maps.wiphys.get(wifi_if.value_ptr.WIPHY) orelse continue;
            add_if.phy_name = alloc.dupe(u8, wiphy.WIPHY_NAME) catch @panic("OOM");
            break :wiphy;
        }
        link: {
            const link = if_maps.links.get(add_if.index) orelse continue;
            add_if.mtu = link.link.MTU;
            break :link;
        }
        addr: {
            add_if.ips = .{ null } ** 10;
            add_if.cidrs = .{ null } ** 10;
            var addrs_iter = if_maps.addresses.iterator();
            defer addrs_iter.unlock();
            newIP: while (addrs_iter.next()) |addr| {
                const new_ip = addr.value_ptr.addr.ADDRESS orelse continue;
                if (addr.value_ptr.info.index != wifi_if.key_ptr.*) continue;
                for (add_if.ips[0..]) |*_ip| {
                    if (_ip.*) |ip| {
                        log.debug("Existing IP: {s}. New IP: {s}", .{ IPF{ .bytes = ip[0..] }, IPF{ .bytes = new_ip[0..] } });
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
        try if_maps.interfaces.put(alloc, add_if.index, add_if);
        log.debug("\n{s}", .{ add_if });
    }
    const now = try zeit.instant(.{});
    var rm_idxs: [50]?i32 = .{ null } ** 50;
    var rm_count: u8 = 0;
    var if_iter = if_maps.interfaces.iterator();
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
        _ = if_maps.interfaces.remove(idx);
    }
}

/// Reset an Interface Map
pub fn resetIFMap(
    alloc: mem.Allocator,
    K: type,
    V: type,
    map: *core.ThreadHashMap(K, V),
) void {
    // Clean
    var map_iter = map.iterator();
    var rm_idxs: [50]?K = .{ null } ** 50;
    var rm_count: u8 = 0;
    while (map_iter.next()) |val| {
        nl.parse.freeBytes(alloc, V, val.value_ptr.*);
        rm_idxs[rm_count] = val.key_ptr.*;
        rm_count +|= 1;
    }
    map_iter.unlock();
    for (rm_idxs[0..rm_count]) |_idx| {
        const idx = _idx orelse break;
        _ = map.remove(idx);
    }
}
