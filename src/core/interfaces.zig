//! Interface Management

const std = @import("std");
const ascii = std.ascii;
const atomic = std.atomic;
const fmt = std.fmt;
const heap = std.heap;
const linux = std.os.linux;
const log = std.log.scoped(.interfaces);
const math = std.math;
const mem = std.mem;
const meta = std.meta;
const posix = std.posix;
const time = std.time;
const ArrayList = std.ArrayList;
const Io = std.Io;
const Thread = std.Thread;

const zeit = @import("zeit");

const core = @import("../core.zig");
const netdata = @import("../netdata.zig");
const address = netdata.address;
const wifi = netdata.l2.wifi;
const chs = wifi.channels;
const MACF = address.MACFormatter;
const IPF = address.IPFormatter;
const l2 = netdata.l2;
const nl = @import("../netlink.zig");
const protocols = @import("../protocols.zig");
const dns = protocols.dns;
const utils = @import("../utils.zig");
const ansi = utils.ansi;
const c = utils.toStruct;
const CSlice = utils.CSlice;
const SliceF = utils.SliceFormatter;
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
    usage: UsageState = .inactive,
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
    channel: ?chs.Channel = null,
    ssid: ?[]const u8 = null,
    supported_freqs: []u32 = &.{},
    supported_chans: []chs.Channel = &.{},
    // Netlink
    wiphy: nl._80211.Wiphy,
    mod_queue: []ModifyContext = &.{},
    // Virtual Interface
    vif_index: ?i32 = null,
    vif_name: ?[]const u8 = null,
    vif_sock: ?posix.socket_t = null,

    /// DisCo Usage State of an Interface
    pub const UsageState = union(enum) {
        err: anyerror,
        inactive,
        //modify: ArrayList(*ModifyContext),
        active,
        scan: core.networks.ScanContext,
        connect: core.connections.Connection,
        remove,
    };

    /// Modify Field
    pub const ModifyField = union(enum) {
        mac: [6]u8,
        state: u32,
        add_ip: struct { addr: [4]u8, cidr: u8 },
        del_ip: struct { addr: [4]u8, cidr: u8 },
        mode: u32,
        channel: chs.Channel,
    };

    /// Modify Context
    const ModifyContext = struct {
        req_ctx: nl.io.RequestContext,
        mod_field: ModifyField,
    };

    /// Interface State Formatter
    const IFStateF = struct {
        flags: u32,

        pub fn format(self: @This(), writer: *Io.Writer) Io.Writer.Error!void {
            for (meta.tags(nl.route.IFF)) |tag| {
                const flag: u32 = @intFromEnum(tag);
                if (flag == 0) //
                    continue;
                if (flag == 1) {
                    const state = if (self.flags & 1 == 1) "UP" else "DOWN";
                    try writer.print("{s}", .{ state });
                    continue;
                }
                if (self.flags & flag == flag) //
                    try writer.print(", {t}", .{ tag });
            }
        }
    };

    /// Simple Interface
    pub const Simple = struct {
        usage: @typeInfo(UsageState).@"union".tag_type.?,
        index: i32,
        name: []const u8,
        phy_index: u32,
        phy_name: []const u8,
        og_mac: [6]u8,
        mac: [6]u8,
        state: u32,
        mtu: usize,
        ips: []const [4]u8,
        cidrs: []const u8,
        mode: u32,
        channel: ?chs.Channel = null,
        ssid: []const u8,
        supported_freqs: []const u32,
        supported_chans: []const chs.Channel,

        pub fn from(alloc: mem.Allocator, from_if: Interface) @This() {
            return .{
                .usage = meta.activeTag(from_if.usage),
                .index = from_if.index,
                .name = alloc.dupe(u8, from_if.name) catch @panic("OOM"),
                .phy_index = from_if.phy_index,
                .phy_name = alloc.dupe(u8, from_if.phy_name) catch @panic("OOM"),
                .og_mac = from_if.og_mac,
                .mac = from_if.mac,
                .state = from_if.state,
                .mtu = from_if.mtu,
                .ips = ips: {
                    var ip_list: ArrayList([4]u8) = .empty;
                    errdefer ip_list.deinit(alloc);
                    var idx: u8 = 0;
                    while (idx < from_if.ips.len) : (idx += 1) //
                        ip_list.append(alloc, from_if.ips[idx] orelse break) catch @panic("OOM");
                    break :ips ip_list.toOwnedSlice(alloc) catch @panic("OOM");
                },
                .cidrs = cidrs: {
                    var cidr_list: ArrayList(u8) = .empty;
                    errdefer cidr_list.deinit(alloc);
                    var idx: u8 = 0;
                    while (idx < from_if.cidrs.len) : (idx += 1) //
                        cidr_list.append(alloc, from_if.cidrs[idx] orelse break) catch @panic("OOM");
                    break :cidrs cidr_list.toOwnedSlice(alloc) catch @panic("OOM");
                },
                .mode = from_if.mode,
                .channel = from_if.channel,
                .ssid = ssid: {
                    if (from_if.ssid) |ssid| {
                        if (ssid.len > 0) //
                            break :ssid alloc.dupe(u8, ssid) catch @panic("OOM");
                        break :ssid alloc.dupe(u8, "[HIDDEN_SSID (disco)]") catch @panic("OOM");
                    }
                    break :ssid "";
                },
                .supported_freqs = alloc.dupe(u32, from_if.supported_freqs) catch @panic("OOM"),
                .supported_chans = alloc.dupe(chs.Channel, from_if.supported_chans) catch @panic("OOM"),
            };
        }

        pub fn deinit(self: *const @This(), alloc: mem.Allocator) void {
            alloc.free(self.name);
            alloc.free(self.phy_name);
            alloc.free(self.ips);
            alloc.free(self.cidrs);
            alloc.free(self.ssid);
            alloc.free(self.supported_freqs);
            alloc.free(self.supported_chans);
        }

        pub fn format(self: @This(), writer: *Io.Writer) Io.Writer.Error!void {
            try formatGen(@This(), self, writer, false);
        }

        pub fn formatANSI(self: @This(), writer: *Io.Writer) Io.Writer.Error!void {
            try formatGen(@This(), self, writer, true);
        }
    };

    /// Free any resources held by this Interface.
    pub fn deinit(self: *@This(), alloc: mem.Allocator) void {
        if (!self._init) //
            return;
        switch (self.usage) {
            .connect => |*conn| conn.deinit(alloc),
            else => {},
        }
        self.cleanupVIF(alloc);
        alloc.free(self.mod_queue);
        alloc.free(self.name);
        alloc.free(self.phy_name);
        alloc.free(self.supported_freqs);
        alloc.free(self.supported_chans);
        nl.parse.freeBytes(alloc, nl._80211.Wiphy, self.wiphy);
        //if (self.ssid) |ssid| alloc.free(ssid);
        self._init = false;
    }

    /// Initialize a Raw Socket for this Interface
    pub fn initSock(self: *@This(), kind: enum { raw, vif }) !void {
        const if_index: i32,
        const sock_ptr: *?posix.socket_t = //
        switch (kind) {
            .raw => .{ self.index, &self.raw_sock },
            .vif => .{ self.vif_index orelse return error.NoVifIndex, &self.vif_sock },
        };
        if (sock_ptr.*) |sock| {
            posix.close(sock);
            sock_ptr.* = null;
        }
        const if_sock = try posix.socket(nl.AF.PACKET, nl.SOCK.RAW, mem.nativeToBig(u16, c(l2.Eth.ETH_P).ALL));
        const sock_addr: posix.sockaddr.ll = .{
            .ifindex = if_index,
            .protocol = mem.nativeToBig(u16, c(l2.Eth.ETH_P).ALL),
            .hatype = 0,
            .pkttype = 0,
            .halen = 6,
            .addr = @splat(0),
        };
        try posix.bind(if_sock, @ptrCast(&sock_addr), @sizeOf(posix.sockaddr.ll));
        try posix.setsockopt(
            if_sock,
            posix.SOL.SOCKET,
            posix.SO.RCVTIMEO,
            mem.toBytes(posix.timeval{ .sec = 0, .usec = 10_000 })[0..],
        );
        sock_ptr.* = if_sock;
        log.debug("Initialized '{t}' Socket for '{s}'", .{ kind, self.name });
        //TODO: Figure out Promiscuous mode?
        //try posix.setsockopt(if_sock, linux.SOL.PACKET, linux.PACKET.ADD_MEMBERSHIP, linux);
    }

    /// Cleanup the Virtual Interface (VIF) if one exists
    pub fn cleanupVIF(self: *@This(), alloc: mem.Allocator) void {
        if (self.vif_sock) |sock| {
            posix.close(sock);
            self.vif_sock = null;
        }
        if (self.vif_index) |vif_idx| {
            nl._80211.delInterface(alloc, vif_idx) catch |err| {
                log.warn("Unable to delete VIF '{?s}' (idx: {d}): {t}", .{ self.vif_name, vif_idx, err });
            };
            self.vif_index = null;
        }
        if (self.vif_name) |vif_name| {
            log.debug("Cleaned up VIF '{s}' for '{s}'", .{ vif_name, self.name });
            alloc.free(vif_name);
            self.vif_name = null;
        }
    }

    /// Check if this Interface supports a specific `command`
    pub fn checkCommand(self: *const @This(), command: nl._80211.CMD) bool {
        const commands = self.wiphy.SUPPORTED_COMMANDS orelse return false;
        return mem.indexOfScalar(u32, commands, @intFromEnum(command)) != null;
    }

    /// Check if this Interface has a specific `feature`
    pub fn checkFeature(self: *const @This(), feature: nl._80211.Wiphy.FEATURE_FLAG) bool {
        const features = self.wiphy.FEATURE_FLAGS orelse return false;
        return features & @intFromEnum(feature) == @intFromEnum(feature);
    }

    /// Check if this Interface supports a specific Interface Type (`if_type`)
    pub fn checkIFType(self: *const @This(), if_type: nl._80211.IFTYPE) bool {
        const if_types = self.wiphy.SUPPORTED_IFTYPES orelse return false;
        return if_types & @intFromEnum(if_type) == @intFromEnum(if_type);
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
            if (self.penalty < self.min_penalty) //
                self.penalty = self.min_penalty;
            if (self.penalty > self.max_penalty) //
                self.penalty = self.max_penalty;
        }
        self.penalty = switch (set) {
            .up => //
                if (self.penalty == 0) 1 //
                else self.penalty * 5,
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
    /// Note, while these Modifications are handled asynchronously, they're intended to be "fire and forget".
    /// If the status of the Modification needs to be tracked, prefer to use the equivalent Netlink Request.
    pub fn modify(self: *@This(), core_ctx: *core.Core, mod_field: ModifyField) !void {
        //if (self.usage != .modify) self.usage = .{ .modify = .empty };
        const mod_ctx: ModifyContext = modReq: {
            const req_handler: *nl.io.Handler = switch (mod_field) {
                .mode,
                .channel,
                => core_ctx.nl80211_handler,
                else => core_ctx.rtnetlink_handler,
            };
            break :modReq .{
                .req_ctx = try .init(.{ .handler = .{ .handler = req_handler } }),
                .mod_field = mod_field,
            };
        };
        var mod_list: ArrayList(ModifyContext) = .fromOwnedSlice(self.mod_queue);
        defer self.mod_queue = mod_list.toOwnedSlice(core_ctx.alloc) catch @panic("OOM");
        mod_list.append(core_ctx.alloc, mod_ctx) catch @panic("OOM");
        const mod_req_ctx = modReqCtx: {
            var mod = &mod_list.items[mod_list.items.len - 1];
            break :modReqCtx &mod.req_ctx;
        };
        switch (mod_field) {
            .mac => |mac| {
                try nl.route.requestSetMAC(
                    core_ctx.alloc,
                    mod_req_ctx,
                    self.index,
                    mac,
                );
            },
            .state => |state| {
                try nl.route.requestSetState(
                    core_ctx.alloc,
                    mod_req_ctx,
                    self.index,
                    state,
                );
            },
            .add_ip => |add_ip| {
                try nl.route.requestAddIP(
                    core_ctx.alloc,
                    mod_req_ctx,
                    self.index,
                    add_ip.addr,
                    add_ip.cidr,
                );
            },
            .del_ip => |del_ip| {
                try nl.route.requestDeleteIP(
                    core_ctx.alloc,
                    mod_req_ctx,
                    self.index,
                    del_ip.addr,
                    del_ip.cidr,
                );
            },
            .mode => |mode| {
                try nl._80211.requestSetMode(
                    core_ctx.alloc,
                    mod_req_ctx,
                    self.index,
                    mode,
                    &.{},
                );
            },
            .channel => |channel| {
                try nl._80211.requestSetFreq(
                    core_ctx.alloc,
                    mod_req_ctx,
                    self.index,
                    try channel.toFreq(),
                    nl._80211.CHANNEL_WIDTH.fromBW(channel.bw),
                );
            },
        }
        log.debug("Modify '{s}': {t}", .{ self.name, mod_field });
        //self.usage.modify.append(core_ctx.alloc, mod_ctx) catch @panic("OOM");
        Thread.sleep(1 * time.ns_per_ms);
    }

    /// Restoration Kind
    pub const RestoreKind = enum {
        mode,
        dns,
        ips,
        mac,
    };
    /// Restore the Interface.
    /// Note, this is blocking.
    pub fn restore(self: *@This(), core_ctx: *core.Core, kinds: []const RestoreKind) void {
        const alloc = core_ctx.alloc;
        log.info("- Restoring Interface '{s}'...", .{ self.name });
        const has_ip: bool = self.ips[0] != null;
        for (kinds) |kind| {
            switch (kind) {
                .mode => {
                    nl._80211.abortScan(alloc, self.index) catch {};
                    Thread.sleep(time.ns_per_ms);
                    nl.route.setState(self.index, c(nl.route.IFF).DOWN) catch |err| {
                        log.warn("Could not set the Interface Down: {t}", .{ err });
                    };
                    Thread.sleep(time.ns_per_ms);
                    if (nl._80211.setMode(core_ctx.alloc, self.index, c(nl._80211.IFTYPE).STATION, &.{})) //
                        log.info("-- Reset to Managed Mode.", .{}) //
                    else |err| //
                        log.warn("-- Could not set the Interface back to Managed Mode: {t}", .{ err });
                },
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
                                else => log.warn("-- Could not remove IP '{f}'!", .{ IPF{ .bytes = ip[0..] } }),
                            }
                            continue;
                        };
                        log.info("-- Removed IP '{f}/{d}'", .{ IPF{ .bytes = ip[0..] }, cidr });
                    }
                },
                .mac => resetMAC: {
                    if (mem.eql(u8, self.og_mac[0..], self.mac[0..])) //
                        break :resetMAC;
                    nl.route.setState(self.index, c(nl.route.IFF).DOWN) catch {};
                    Thread.sleep(time.ns_per_ms);
                    if (nl.route.setMAC(self.index, self.og_mac)) //
                        log.info("-- Restored Original MAC '{f}'.", .{ MACF{ .bytes = self.og_mac[0..] } }) //
                    else |_| //
                        log.warn("-- Could not restore Interface '{s}' to its original MAC '{f}'.", .{ self.name, MACF{ .bytes = self.og_mac[0..] } });
                },
                .dns => resetDNS: {
                    if (!has_ip) //
                        break :resetDNS;
                    dns.updateDNS(.{
                        .if_index = self.index,
                        .servers = &.{},
                        .set_route = false,
                        .allow_mdns = .inherit,
                        .allow_llmnr = .inherit,
                    }) catch |err| {
                        log.err("-- Could not reset DNS: {t}", .{ err });
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
        if (self.raw_sock) |sock| //
            posix.close(sock);
        self.deinit(alloc);
        self.usage = .inactive;
    }

    pub fn format(self: @This(), writer: *Io.Writer) Io.Writer.Error!void {
        try formatGen(@This(), self, writer, false);
    }

    pub fn formatANSI(self: @This(), writer: *Io.Writer) Io.Writer.Error!void {
        try formatGen(@This(), self, writer, true);
    }

    pub fn formatGen(T: type, self: T, writer: *Io.Writer, use_ansi: bool) Io.Writer.Error!void {
        // Setup Writer
        var filter_writer: ansi.FilterWriter = .init(writer);
        const w: *Io.Writer = //
            if (use_ansi) writer //
            else &filter_writer.io_writer;
        // ANSI Resets
        try w.print("{s}", .{ ansi.reset });
        defer w.print("{s}", .{ ansi.reset }) catch {};
        // Format Interface
        const usage_color: []const u8 = switch (self.usage) {
            .inactive => ansi.fg.gray,
            .err => ansi.fg.red,
            .active => ansi.fg.bright_green,
            else => ansi.fg.green,
        };
        try w.print(
            \\({d}) {s}{s}{s} | {s}{t}{s}
            \\
            , .{
                self.index,
                ansi.fmt.bold, self.name, ansi.fmt.reset,
                usage_color, self.usage, ansi.reset,
            },
        );
        if (T == @This()) {
            var last_ts_buf: [50]u8 = undefined;
            const last_ts = self.last_upd.time().bufPrint(last_ts_buf[0..], .rfc3339) catch "[Time Format Error]";
            try w.print(
                \\{s}
                \\
                , .{
                    last_ts,
                },
        );
        }
        try w.print(
            \\- {s}Phy{s}:    ({d}) {s}
            \\- {s}OG MAC{s}: {f} ({s})
            \\- {s}MAC{s}:    {f} ({s})
            \\- {s}State{s}:  {f}
            \\- {s}Mode{s}:   {t}
            \\- {s}MTU{s}:    {d}
            \\{s}
            , .{
                ansi.fmt.underline, ansi.reset, self.phy_index, self.phy_name,
                ansi.fmt.underline, ansi.reset, MACF{ .bytes = self.og_mac[0..] }, netdata.oui.findOUI(.short, self.og_mac) catch "OUI Unavailable",
                ansi.fmt.underline, ansi.reset, MACF{ .bytes = self.mac[0..] }, netdata.oui.findOUI(.short, self.mac) catch "OUI Unavailable",
                ansi.fmt.underline, ansi.reset, IFStateF{ .flags = self.state },
                ansi.fmt.underline, ansi.reset, @as(nl._80211.IFTYPE, @enumFromInt(self.mode)),
                ansi.fmt.underline, ansi.reset, self.mtu,
                ansi.reset,
            },
        );
        if (self.channel) |ch| {
            try w.print(
                "- {s}Channel{s}: {d} | {s}\n", 
                .{
                    ansi.fmt.underline,
                    ansi.reset,
                    ch.pri,
                    @tagName(ch.bw),
                }
            );
        }
        if (T == @This()) ips: {
            if (self.ips[0] == null)
                break :ips;
            try w.print("- {s}IPs{s}:\n", .{ ansi.fmt.underline, ansi.reset });
            for (self.ips, self.cidrs) |_ip, _cidr| {
                const ip = _ip orelse break :ips;
                const cidr = _cidr orelse continue;
                w.print("  - {f}/{d}\n", .{ IPF{ .bytes = ip[0..] }, cidr }) catch {};
            }
        } //
        else ips: {
            if (self.ips.len == 0)
                break :ips;
            try w.print("- {s}IPs{s}:\n", .{ ansi.fmt.underline, ansi.reset });
            for (self.ips, self.cidrs) |ip, cidr| {
                w.print("  - {f}/{d}\n", .{ IPF{ .bytes = ip[0..] }, cidr }) catch {};
            }
        }
        try w.print(
            \\- {s}Support{s}:
            //\\  - Channels: ({d} Channels)
            \\
            //, .{ self.supported_freqs.len }
            , .{
                ansi.fmt.underline, ansi.reset,
            },
        );
        var chans_2G: u8 = 0;
        var chans_5G: u8 = 0;
        var chans_6G: u8 = 0;
        for (self.supported_freqs) |freq| {
            if (mem.indexOfScalar(u32, chs.Frequencies.band_2G_20, @intCast(freq))) |_| {
                chans_2G += 1;
                continue;
            }
            if (mem.indexOfScalar(u32, chs.Frequencies.band_5G_20, @intCast(freq))) |_| {
                chans_5G += 1;
                continue;
            }
            if (mem.indexOfScalar(u32, chs.Frequencies.band_6G_20, @intCast(freq))) |_| {
                chans_6G += 1;
                continue;
            }
            //const ch = nl._80211.channelFromFreq(freq) catch {
            //    log.warn("Invalid Freq: {d}MHz", .{ freq });
            //    continue;
            //};
            //try writer.print("    - {d} ({d})MHz\n", .{ ch, freq });
        }
        if (chans_2G > 0 or chans_5G > 0) {
            try w.print("  - {s}Bands{s}:\n", .{ ansi.fmt.underline, ansi.reset });
            if (chans_2G > 0) //
                try w.print("    - 2G: {d} channels\n", .{ chans_2G });
            if (chans_5G > 0) //
                try w.print("    - 5G: {d} channels\n", .{ chans_5G });
            if (chans_6G > 0) //
                try w.print("    - 6G: {d} channels\n", .{ chans_6G });
            //try writer.print("\n", .{});
        }
        if (T == @This()) {
            commands: {
                try w.print("  - {s}Commands{s}:\n", .{ ansi.fmt.underline, ansi.reset });
                if (self.wiphy.SUPPORTED_COMMANDS == null) {
                    try w.print("    - None Reported", .{});
                    break :commands;
                }
                //try w.print("    - Command Count: {d}\n", .{ self.wiphy.SUPPORTED_COMMANDS.?.len });
                inline for (&.{
                    nl._80211.CMD.REMAIN_ON_CHANNEL,
                    nl._80211.CMD.START_SCHED_SCAN,
                    nl._80211.CMD.ROAM,
                    nl._80211.CMD.ADD_LINK,
                }) |command| {
                    const has_command = self.checkCommand(command);
                    try w.print("    - {t}: {}\n", .{ command, has_command });
                }
            }
            features: {
                try w.print("  - {s}Features{s}:\n", .{ ansi.fmt.underline, ansi.reset });
                if (self.wiphy.FEATURE_FLAGS == null) {
                    try w.print("    - None Reported", .{});
                    break :features;
                }
                inline for (&.{ 
                    nl._80211.Wiphy.FEATURE_FLAG.ACTIVE_MONITOR,
                    nl._80211.Wiphy.FEATURE_FLAG.AP_SCAN,
                    nl._80211.Wiphy.FEATURE_FLAG.LOW_PRIORITY_SCAN,
                    nl._80211.Wiphy.FEATURE_FLAG.SCAN_FLUSH,
                    nl._80211.Wiphy.FEATURE_FLAG.SAE,
                }) |feature| {
                    const has_feature = self.checkFeature(feature);
                    try w.print("    - {t}: {}\n", .{ feature, has_feature });
                }
            }
        }
    }
};

///// External Interface
//pub const ExternalInterface = extern struct {
//    index: i32,
//    name: CSlice(u8),
//    phy_index: u32,
//    phy_name: CSlice(u8),
//    og_mac: [6]u8,
//    mac: [6]u8,
//    state: u32,
//    mtu: usize,
//    ips: CSlice([4]u8),
//    cidrs: CSlice([4]u8),
//    mode: u32,
//    channel: chs.Channel = 0,
//    ssid: CSlice(u8),
//    supported_freqs: CSlice(u32),
//
//    pub fn from(alloc: mem.Allocator, from_if: Interface) @This() {
//        return .{
//            .index = from_if.index,
//            .name = .init(alloc, from_if.name) catch @panic("OOM"),
//            .phy_index = from_if.phy_index,
//            .og_mac = from_if.og_mac,
//            .mac = from_if.mac,
//            .state = from_if.state,
//            .mtu = from_if.mtu,
//            .ips = ips: {
//                const len = mem.indexOfScalar(?[4]u8, from_if.ips, null) orelse 0;
//                break :ips .init(alloc, from_if.ips[0..len]) catch @panic("OOM");
//            },
//            .cidrs = cidrs: {
//                const len = mem.indexOfScalar(?[4]u8, from_if.cidrs, null) orelse 0;
//                break :cidrs .init(alloc, from_if.cidrs[0..len]) catch @panic("OOM");
//            },
//            .mode = from_if.mode,
//            .channel = from_if.channel,
//            .ssid = .init(alloc, from_if.ssid) catch @panic("OOM"),
//            .supported_freqs = .init(alloc, from_if.supported_freqs) catch @panic("OOM"),
//        };
//    }
//};

/// Interfaces Context
pub const Context = struct {
    // INTERNAL USE
    /// Timer
    _timer: ?time.Timer,
    /// Arena
    _arena: *heap.ArenaAllocator,
    /// Arena Allocator
    _a_alloc: mem.Allocator,
    /// WiFi Interfaces Request Context
    _req_wifi_ifs: nl.io.RequestContext,
    /// WiFi Physical Devices Request Context
    _req_wiphys: nl.io.RequestContext,
    /// Links Request Context
    _req_links: nl.io.RequestContext,
    /// Addresses Requeest Context
    _req_addrs: nl.io.RequestContext,
    // EXTERNAL USE
    /// Netlink Async State
    state: core.AsyncState,
    /// Available Interface Names
    avail_if_names: *ThreadHashMap([]const u8, void),
    /// Available Interfaces
    interfaces: *ThreadHashMap([6]u8, Interface),
    /// Interface Timeout
    if_timeout: usize = 5000,

    /// Initialize the Interface Context.
    pub fn init(core_ctx: *core.Core) !@This() {
        var self: @This() = undefined;
        self._timer = null;
        self._arena = core_ctx.alloc.create(heap.ArenaAllocator) catch @panic("OOM");
        self._arena.* = .init(core_ctx.alloc);
        self._a_alloc = self._arena.allocator();
        self.state = .ready;
        self.avail_if_names = availNames: {
            log.debug("Adding {d} Interfaces to Active List...", .{ core_ctx.config.avail_if_names.len });
            const names = core_ctx.alloc.create(ThreadHashMap([]const u8, void)) catch @panic("OOM");
            names.* = .empty;
            for (core_ctx.config.avail_if_names) |name| {
                const dupe_name = core_ctx.alloc.dupe(u8, name) catch @panic("OOM");
                names.put(core_ctx.alloc, dupe_name, {}) catch @panic("OOM");
                log.debug("- Added '{s}'", .{ dupe_name });
            }
            break :availNames names;
        };
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
        var names_iter = self.avail_if_names.iterator();
        while (names_iter.next()) |name_entry| //
            alloc.free(name_entry.key_ptr.*);
        names_iter.unlock();
        self.avail_if_names.deinit(alloc);
        alloc.destroy(self.avail_if_names);
        var if_iter = self.interfaces.iterator();
        while (if_iter.next()) |if_entry| //
            if_entry.value_ptr.stop(alloc);
        if_iter.unlock();
        self.interfaces.deinit(alloc);
        alloc.destroy(self.interfaces);
        self._arena.deinit();
        alloc.destroy(self._arena);
    }

    /// Restore All Interfaces to their Original MAC Addresses and remove any IP Addresses.
    /// Intended for use at the end of execution during clean up.
    pub fn restore(self: *@This()) void {
        const core_ctx: *core.Core = @alignCast(@fieldParentPtr("if_ctx", self));
        //const core_ctx: *core.Core = @fieldParentPtr("if_ctx", self);
        if (self.interfaces.count() == 0) //
            return;
        var if_iter = self.interfaces.iterator();
        if_iter.unlock();
        while (if_iter.next()) |if_entry| {
            const res_if = if_entry.value_ptr;
            //if (res_if.usage == .unavailable or res_if.usage == .err) continue;
            switch (res_if.usage) {
                .inactive,
                .err,
                => continue,
                .connect => |*conn| {
                    conn.stop(core_ctx);
                },
                else => {},
            }
            res_if.restore(core_ctx, &.{ .mode, .ips, .mac, .dns });
        }
    }
    
    /// Update the status of all Interfaces
    pub fn update(self: *@This()) !void {
        const core_ctx: *core.Core = @alignCast(@fieldParentPtr("if_ctx", self));
        //const core_ctx: *core.Core = @fieldParentPtr("if_ctx", self);
        if (self._timer) |*timer| {
            const wait: u64 = wait: {
                const run_cond = core_ctx.run_condition orelse break :wait 500;
                break :wait switch (run_cond) {
                    .list_interfaces => 0,
                    else => 500,
                };
            };
            if (@divFloor(timer.read(), time.ns_per_ms) < wait) //
                return;
            timer.reset();
        }
        else self._timer = try .start();
        //var trace_timer: time.Timer = try .start();
        //defer {
        //    log.debug("IF Update Time: {d}ms", .{ @divFloor(trace_timer.read(), time.ns_per_ms) });
        //    trace_timer.reset();
        //}
        //log.debug("Updating Interfaces: {t}", .{ self.state });
        ifState: switch (self.state) {
            .ready => {
                self.state = .request;
                continue :ifState self.state;
            },
            .request => {
                //log.debug("Requesting Interface Updates...", .{});
                self._req_wifi_ifs.nextSeqID();
                try nl._80211.requestAllInterfaces(core_ctx.alloc, &self._req_wifi_ifs);
                Thread.sleep(1 * time.ns_per_ms);
                self._req_links.nextSeqID();
                try nl.route.requestAllIFLinks(core_ctx.alloc, &self._req_links);
                Thread.sleep(1 * time.ns_per_ms);
                self._req_addrs.nextSeqID();
                try nl.route.requestAllIFAddrs(core_ctx.alloc, &self._req_addrs);
                Thread.sleep(1 * time.ns_per_ms);
                self._req_wiphys.nextSeqID();
                try nl._80211.requestAllWIPHY(core_ctx.alloc, &self._req_wiphys);
                Thread.sleep(1 * time.ns_per_ms);
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
                if ( //
                    self._req_wifi_ifs.checkResponse() and //
                    self._req_wiphys.checkResponse() and //
                    self._req_links.checkResponse() and //
                    self._req_addrs.checkResponse() //
                ) {
                    self.state = .parse;
                    continue :ifState self.state;
                }
            },
            .parse => {
                defer if (core_ctx.run_condition) |*condition| {
                    switch (condition.*) {
                        .list_interfaces => |*list| list.updated = true,
                        .mod_interfaces => |*mod| {
                            var if_iter = self.interfaces.iterator();
                            defer self.interfaces.mutex.unlock();
                            mod.complete = modified: {
                                while (if_iter.next()) |mod_if_entry| {
                                    const mod_if = mod_if_entry.value_ptr;
                                    if (mod_if.mod_queue.len > 0) //
                                        break :modified false;
                                }
                                break :modified true;
                            };
                        },
                        else => {},
                    }
                };
                defer self.state = .request;
                //log.debug("Parsing Interface Updates...", .{});
                // Ensure all requests got a successful response
                const wifi_if_data: []const u8 = self._req_wifi_ifs.getResponse().? catch |err| {
                    log.debug("Issue w/ WiFi IF Data: {t}", .{ err });
                    self.state = .request;
                    continue :ifState self.state;
                };
                defer core_ctx.alloc.free(wifi_if_data);
                //log.debug("Wifi IF Data:\n{f}", .{ utils.HexFormatter{ .bytes = wifi_if_data[0..] } });
                const wiphy_data: []const u8 = self._req_wiphys.getResponse().? catch |err| {
                    log.debug("Issue w/ WIPHY Data: {t}", .{ err });
                    self.state = .request;
                    continue :ifState self.state;
                };
                defer core_ctx.alloc.free(wiphy_data);
                const link_data: []const u8 = self._req_links.getResponse().? catch |err| {
                    log.debug("Issue w/ Link Data: {t}", .{ err });
                    self.state = .request;
                    continue :ifState self.state;
                };
                defer core_ctx.alloc.free(link_data);
                const addr_data: []const u8 = self._req_addrs.getResponse().? catch |err| {
                    log.debug("Issue w/ Addr Data: {t}", .{ err });
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
                    const wifi_if_idx = wifi_if.IFINDEX orelse continue;
                    const wifi_if_name = wifi_if.IFNAME orelse continue;
                    if (mem.endsWith(u8, wifi_if_name, "_mon\x00") or mem.endsWith(u8, wifi_if_name, "_mon"))
                        continue :updateIfs;
                    var valid: bool = false;
                    const wiphy: nl._80211.Wiphy = nlWiphy: {
                        for (nl_wiphys) |nl_wiphy| {
                            if (wifi_if.WIPHY != nl_wiphy.WIPHY) //
                                continue;
                            break :nlWiphy nl_wiphy;
                        }
                        else continue :updateIfs;
                    };
                    const link: nl.route.IFInfoAndLink = nlLink: {
                        for (nl_links) |nl_link| {
                            if (wifi_if_idx != nl_link.info.index) //
                                continue;
                            break :nlLink nl_link;
                        }
                        else continue :updateIfs;
                    };
                    const if_name = core_ctx.alloc.dupe(u8, wifi_if_name[0..(wifi_if_name.len - 1)]) catch @panic("OOM");
                    const phy_name = core_ctx.alloc.dupe(u8, wiphy.WIPHY_NAME) catch @panic("OOM");
                    defer if (!valid) {
                        core_ctx.alloc.free(if_name);
                        core_ctx.alloc.free(phy_name);
                    };
                    const ips, const cidrs = ipAddrs: {
                        var ips: [10]?[4]u8 = @splat(null);
                        var cidrs: [10]?u8 = @splat(null);
                        var idx: u8 = 0;
                        for (nl_addrs) |addr| {
                            if (addr.info.index != wifi_if_idx) //
                                continue;
                            const ip = addr.addr.ADDRESS orelse continue;
                            const cidr = addr.info.prefix_len;
                            ips[idx] = ip;
                            cidrs[idx] = cidr;
                            idx += 1;
                        }
                        break :ipAddrs .{ ips, cidrs };
                    };
                    const channel: ?chs.Channel = channel: {
                        const freq = wifi_if.WIPHY_FREQ orelse break :channel null;
                        const raw_width: nl._80211.CHANNEL_WIDTH = @enumFromInt(wifi_if.CHANNEL_WIDTH orelse break :channel null);
                        const bw = raw_width.toBW() catch break :channel null;
                        break :channel chs.Channel.fromFreqBW(freq, bw) catch null;
                    };
                    //const wiphy_clone = nl.parse.clone(core_ctx.alloc, nl._80211.Wiphy, wiphy) catch |err| {
                    //    log.debug("Couldn't clone `wiphy`: {t}", .{ err });
                    //    return err;
                    //};
                    var add_if: Interface = .{
                        .index = @intCast(wifi_if_idx),
                        .name = if_name,
                        .mac = wifi_if.MAC,
                        .mode = wifi_if.IFTYPE orelse continue :updateIfs,
                        .channel = channel,
                        .phy_index = wifi_if.WIPHY,
                        .phy_name = phy_name,
                        .og_mac = link.link.PERM_ADDRESS orelse continue :updateIfs,
                        .state = link.info.flags,
                        .mtu = link.link.MTU,
                        .ips = ips,
                        .cidrs = cidrs,
                        .ssid = wifi_if.SSID,
                        //.wiphy = try nl.parse.clone(core_ctx.alloc, nl._80211.Wiphy, wiphy),
                        .wiphy = undefined,
                        .last_upd = try zeit.instant(.{}),
                    };
                    self.interfaces.mutex.lock();
                    defer self.interfaces.mutex.unlock();
                    if (self.interfaces.map.getEntry(add_if.og_mac)) |upd_if_entry| updIf: {
                        const upd_if = upd_if_entry.value_ptr;
                        if (add_if.index != upd_if.index) {
                            log.debug("Interface '{s}' has a new Index: {d}", .{ add_if.name, add_if.index });
                            try add_if.initSock(.raw);
                            if (upd_if.usage == .err) {
                                log.debug("Reset interface '{s}' from errored state.", .{ add_if.name });
                                break :updIf;
                            }
                        }
                        add_if.usage = upd_if.usage;
                        add_if.raw_sock = upd_if.raw_sock;
                        add_if.penalty_time = upd_if.penalty_time;
                        add_if.penalty = upd_if.penalty;
                        add_if.min_penalty = upd_if.min_penalty;
                        add_if.max_penalty = upd_if.max_penalty;
                        add_if.supported_freqs = upd_if.supported_freqs;
                        add_if.supported_chans = upd_if.supported_chans;
                        add_if.mod_queue = upd_if.mod_queue;
                        add_if.wiphy = upd_if.wiphy;
                        if (add_if.usage == .inactive and add_if._init) //
                            add_if.stop(core_ctx.alloc);
                        add_if.vif_index = upd_if.vif_index;
                        add_if.vif_name = upd_if.vif_name;
                        add_if.vif_sock = upd_if.vif_sock;
                        core_ctx.alloc.free(upd_if.name);
                        core_ctx.alloc.free(upd_if.phy_name);
                        //nl.parse.freeBytes(core_ctx.alloc, nl._80211.Wiphy, upd_if.wiphy);
                    } //
                    else newIFMsg: {
                        add_if.wiphy = try nl.parse.clone(core_ctx.alloc, nl._80211.Wiphy, wiphy);
                        //log.debug("Field Check '{s}':", .{ add_if.name });
                        //inline for (@typeInfo(nl._80211.Wiphy).@"struct".fields) |field| cont: {
                        //    const has_field = hasField: {
                        //        if (@typeInfo(field.type) != .optional) //
                        //            break :hasField true;
                        //        break :hasField @field(add_if.wiphy, field.name) != null;
                        //    };
                        //    if (!has_field)
                        //        break :cont;
                        //    const enum_tag = meta.stringToEnum(nl._80211.ATTR, field.name);
                        //    const enum_val =
                        //        if (enum_tag) |tag| @intFromEnum(tag)
                        //        else null;
                        //    log.debug("- {s} ({?d}): {}", .{ field.name, enum_val, has_field });
                        //}
                        const bands = wiphy.WIPHY_BANDS orelse {
                            log.warn("The Interface '{s}' did not provide Band/Frequency Info, so it can't be used.", .{ add_if.name });
                            continue :updateIfs;
                        };
                        var freqs_list: ArrayList(u32) = .empty;
                        errdefer freqs_list.deinit(core_ctx.alloc);
                        var chans_list: ArrayList(chs.Channel) = .empty;
                        errdefer chans_list.deinit(core_ctx.alloc);
                        for (bands) |band| {
                            const freqs = band.FREQS orelse continue;
                            for (freqs) |freq| {
                                try freqs_list.append(core_ctx.alloc, freq.FREQ);
                                // TODO: Add support for non-20MHz Bandwidths
                                const chan: chs.Channel = chs.Channel.fromFreqBW(freq.FREQ, .bw20) catch continue;
                                try chans_list.append(core_ctx.alloc, chan);
                            }
                        }
                        add_if.supported_freqs = try freqs_list.toOwnedSlice(core_ctx.alloc);
                        add_if.supported_chans = try chans_list.toOwnedSlice(core_ctx.alloc);
                        if (add_if.supported_freqs.len == 0) {
                            core_ctx.alloc.free(add_if.supported_freqs);
                            log.debug("The Interface '{s}' did not report any available Channels.", .{ add_if.name });
                        }
                        if (core_ctx.run_condition) |condition| {
                            switch (condition) {
                                .list_interfaces,
                                .mod_interfaces,
                                    => break :newIFMsg,
                                else => {},
                            }
                        }
                        log.info("New Interface Seen: ({f}) {s}", .{ MACF{ .bytes = add_if.mac[0..] }, add_if.name });
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
                .inactive => {
                    var names_iter = self.avail_if_names.iterator();
                    defer names_iter.unlock();
                    while (names_iter.next()) |name_entry| {
                        const avail_if_name = name_entry.key_ptr.*;
                        //log.debug("- Check name: {s} ({d}B) vs {s} ({d}B)", .{ net_if.name, net_if.name.len, avail_if_name, avail_if_name.len });
                        if (!mem.eql(u8, net_if.name, avail_if_name)) //
                            continue;
                        net_if.usage = .active;
                        if (core_ctx.run_condition) |condition| {
                            switch (condition) {
                                .list_interfaces,
                                .mod_interfaces,
                                    => continue,
                                else => {},
                            }
                        }
                        log.info("Available Interface Found:\n{f}", .{ net_if });
                        try net_if.initSock(.raw);
                        core_ctx.network_ctx.nl_scan_configs.mutex.lock();
                        defer core_ctx.network_ctx.nl_scan_configs.mutex.unlock();
                        if (core_ctx.network_ctx.nl_scan_configs.map.getEntry(net_if.name)) |scan_cfg_entry| scanCfg: {
                            const scan_config = scan_cfg_entry.value_ptr;
                            const freqs = scan_config.freqs orelse break :scanCfg;
                            var scan_list: ArrayList(u32) = .empty;
                            errdefer scan_list.deinit(core_ctx.alloc);
                            for (freqs) |freq| {
                                if (mem.indexOfScalar(u32, net_if.supported_freqs, freq) == null) //
                                    continue;
                                scan_list.append(core_ctx.alloc, freq) catch @panic("OOM");
                            }
                            if (scan_list.items.len == 0) {
                                log.warn("The provided Channels for '{s}' are not supported by the Interface. Defaulting to supported Channels.", .{ net_if.name });
                                scan_config.freqs = null;
                                break :scanCfg;
                            }
                            if (scan_config.freqs) |old_freqs| //
                                core_ctx.alloc.free(old_freqs);
                            scan_config.freqs = scan_list.toOwnedSlice(core_ctx.alloc) catch @panic("OOM");
                        }
                        if (net_if.state & c(nl.route.IFF).UP != c(nl.route.IFF).DOWN) //
                            try net_if.modify(core_ctx, .{ .state = c(nl.route.IFF).DOWN });
                        if (net_if.mode != c(nl._80211.IFTYPE).STATION) //
                            try net_if.modify(core_ctx, .{ .mode = c(nl._80211.IFTYPE).STATION });
                        if (core_ctx.config.profile.mask) |pro_mask| {
                            var mask_mac: [6]u8 = netdata.address.getRandomMAC(.ll);
                            if (pro_mask.oui) |mask_oui| //
                                @memcpy(mask_mac[0..3], mask_oui[0..]);
                            if (mem.eql(u8, net_if.mac[0..], net_if.og_mac[0..])) //
                                try net_if.modify(core_ctx, .{ .mac = mask_mac });
                        }
                        try net_if.modify(core_ctx, .{ .state = c(nl.route.IFF).UP });
                        break;
                    }
                },
                // Check for old WiFi Interface
                .active,
                .connect,
                .scan,
                .err,
                => oldCheck: {
                    if (net_if.usage == .err) if (net_if.raw_sock) |sock| {
                        posix.close(sock);
                        net_if.raw_sock = null;
                    };
                    const now = try zeit.instant(.{});
                    const since_upd = @divFloor(now.timestamp -| net_if.last_upd.timestamp, @as(i128, time.ns_per_ms));
                    if (since_upd < 15_000) //
                        break :oldCheck;
                    log.warn("Interface '{s}' is no longer available. Last seen {d}s ago", .{ net_if.name, @divFloor(since_upd, 1_000) });
                    net_if.deinit(core_ctx.alloc);
                    rm_macs[rm_count] = net_if_entry.key_ptr.*;
                    rm_count +|= 1;
                },
                else => {},
            }
            // Check for complete Modifications of the WiFi Interface
            var seq_list: ArrayList(u32) = .empty;
            defer seq_list.deinit(core_ctx.alloc);
            for (net_if.mod_queue) |mod| {
                const mod_resp = mod.req_ctx.getResponse() orelse continue;
                defer if (mod_resp) |resp_data| //
                    core_ctx.alloc.free(resp_data) //
                else |_| {};
                seq_list.append(core_ctx.alloc, mod.req_ctx.seq_id) catch @panic("OOM");
                switch (mod.mod_field) {
                    .mac => |mac| {
                        if (mod_resp) |_| {
                            net_if.mac = mac;
                            log.info("Changed MAC of '{s}' to '{f}'.", .{ net_if.name, MACF{ .bytes = mac[0..] } });
                        } //
                        else |err| //
                            log.warn("Unable to change MAC of '{s}': {t}", .{ net_if.name, err });
                    },
                    .state => |state| {
                        if (mod_resp) |_| {
                            net_if.state = state;
                            log.info("Changed State of '{s}' to '{f}'.", .{ net_if.name, Interface.IFStateF{ .flags = state } });
                        } //
                        else |err| //
                            log.warn("Unable to change State of '{s}': {t}", .{ net_if.name, err });
                    },
                    .mode => |mode| {
                        if (mod_resp) |_| {
                            net_if.mode = mode;
                            log.info("Changed Mode of '{s}' to '{t}'.", .{ net_if.name, @as(nl._80211.IFTYPE, @enumFromInt(mode)) });
                        } //
                        else |err| //
                            log.warn("Unable to change Mode of '{s}': {t}", .{ net_if.name, err });
                    },
                    .add_ip => |add_ip| {
                        if (mod_resp) |_| //
                            log.info("Added IP to '{s}': '{f}/{d}'", .{ net_if.name, IPF{ .bytes = add_ip.addr[0..] }, add_ip.cidr }) //
                        else |err| //
                            log.warn("Unable to add IP to '{s}': {t}", .{ net_if.name, err });
                    },
                    .del_ip => |del_ip| {
                        if (mod_resp) |_| //
                            log.info("Deleted IP from '{s}': '{f}/{d}'", .{ net_if.name, IPF{ .bytes = del_ip.addr[0..] }, del_ip.cidr }) //
                        else |err| //
                            log.warn("Unable to delete IP from '{s}': {t}", .{ net_if.name, err });
                    },
                    .channel => |ch| {
                        if (mod_resp) |_| {
                            net_if.channel = ch;
                            log.info("Changed Channel of '{s}' to '{f}'", .{ net_if.name, ch });
                        } //
                        else |err| //
                            log.warn("Unable to change channel of '{s}': {t}", .{ net_if.name, err });
                    },
                }
            }
            var mod_list: ArrayList(Interface.ModifyContext) = .fromOwnedSlice(net_if.mod_queue);
            for (seq_list.items) |seq| {
                for (mod_list.items, 0..) |mod, idx| {
                    if (mod.req_ctx.seq_id != seq) //
                        continue;
                    _ = mod_list.orderedRemove(idx);
                    break;
                }
            }
            if (mod_list.items.len == 0) {
                mod_list.deinit(core_ctx.alloc);
                net_if.mod_queue = &.{};
            } //
            else //
                net_if.mod_queue = mod_list.toOwnedSlice(core_ctx.alloc) catch @panic("OOM");
        }
        for (rm_macs[0..rm_count]) |mac| {
            _ = self.interfaces.map.remove(mac);
            log.warn("Removed Interface '{f}'.", .{ MACF{ .bytes = mac[0..] } });
        }
    }
};

