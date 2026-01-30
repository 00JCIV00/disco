//! Device Tracking

const builtin = @import("builtin");
const std = @import("std");
const atomic = std.atomic;
const enums = std.enums;
const fmt = std.fmt;
const heap = std.heap;
const linux = std.os.linux;
const log = std.log.scoped(.devices);
const math = std.math;
const mem = std.mem;
const meta = std.meta;
const posix = std.posix;
const time = std.time;
const ArrayList = std.ArrayList;
const Io = std.Io;
const Thread = std.Thread;

const zeit = @import("zeit");

const netdata = @import("../netdata.zig");
const address = netdata.address;
const MACF = address.MACFormatter;
const IPF = address.IPFormatter;
const chs = netdata.l2.wifi.channels;
const ies = netdata.l2.information_elements;
const wifi = netdata.l2.wifi;
const radiotap = wifi.radiotap;
const core = @import("../core.zig");
const nl = @import("../netlink.zig");
const proto = @import("../protocols.zig");
const wpa = proto.wpa;
const utils = @import("../utils.zig");
const ansi = utils.ansi;
const c = utils.toStruct;
const ThreadHashMap = utils.ThreadHashMap;
const ThreadMAL = utils.ThreadMultiArrayList;
const ThreadHashMAL = utils.ThreadHashMAL;

/// WiFi Device
pub const Device = struct {
    mac: [6]u8,
    kind: Kind,
    channel: chs.Channel,
    ssid: ?[]const u8 = null,
    bss: ?nl._80211.BasicServiceSet = null,

    pub const Kind = enum(u8) {
        ap,
        sta,
        mesh,
    };

    /// Extracts the SSID or Mesh ID of this Device.
    /// This will always return `null` for Stations.
    pub fn id(self: @This()) ?[]const u8 {
        return switch (self.kind) {
            .ap => ssid: {
                const bss = self.bss orelse break :ssid null;
                const dev_ies = bss.INFORMATION_ELEMENTS orelse break :ssid null;
                const ssid = dev_ies.SSID orelse break :ssid null;
                if (ssid.len > 0 and !mem.eql(u8, ssid, &.{ 0 })) //
                    break :ssid ssid;
                break :ssid null;
            },
            .mesh => meshID: {
                const bss = self.bss orelse break :meshID null;
                const dev_ies = bss.INFORMATION_ELEMENTS orelse break :meshID null;
                break :meshID dev_ies.MESH_ID;
            },
            else => null,
        };
    }

    /// Format
    pub fn format(self: @This(), writer: *Io.Writer) Io.Writer.Error!void {
        try formatGen(self, writer, false);
    }
    /// Format w/ ANSI
    pub fn formatANSI(self: @This(), writer: *Io.Writer) Io.Writer.Error!void {
        try formatGen(self, writer, true);
    }
    /// Generate a Format Method
    fn formatGen(
        self: @This(),
        writer: *Io.Writer,
        use_ansi: bool,
    ) Io.Writer.Error!void {
        // Setup Writer
        var filter_writer: ansi.FilterWriter = .init(writer);
        const w: *Io.Writer = //
            if (use_ansi) writer //
            else &filter_writer.io_writer;
        // ANSI Resets
        try w.print("{s}", .{ ansi.reset });
        defer w.print("{s}", .{ ansi.reset }) catch {};
        // Format
        switch (self.kind) {
            .ap => {
                const security_info: ?wifi.SecurityInfo = sec: {
                    const bss = self.bss orelse break :sec null;
                    break :sec bss.getSecurityInfo() catch break :sec null;
                };
                try w.print(
                    \\{s}{s}{s}
                    \\- {s}BSSID{s}:    {f} ({s})
                    \\- {s}Channel{s}:  {f}
                    \\
                    , .{
                        ansi.fmt.bold, self.id() orelse "[HIDDEN NETWORK] (DisCo)", ansi.reset,
                        ansi.fmt.underline, ansi.reset, MACF{ .bytes = self.mac[0..] }, netdata.oui.findOUI(.short, self.mac) catch "[UNKNOWN]",
                        ansi.fmt.underline, ansi.reset, self.channel,
                    },
                );
                if (security_info) |sec| {
                    try w.print(
                        \\- {s}Security{s}: {t}
                        \\- {s}Auth{s}:     {t}
                        \\
                        , .{
                            ansi.fmt.underline, ansi.reset, sec.type,
                            ansi.fmt.underline, ansi.reset, sec.auth,
                        },
                    );
                }
            },
            .sta => {
                try w.print(
                    \\{s}Station{s}
                    \\- {s}MAC{s}:     {f} ({s})
                    \\- {s}Channel{s}: {f}
                    \\
                    , .{
                        ansi.fmt.bold, ansi.reset,
                        ansi.fmt.underline, ansi.reset, MACF{ .bytes = self.mac[0..] }, netdata.oui.findOUI(.short, self.mac) catch "[UNKNOWN]",
                        ansi.fmt.underline, ansi.reset, self.channel,
                    },
                );
            },
            .mesh => {
                try w.print(
                    \\{s}{s}{s} (Mesh)
                    \\- {s}MAC{s}:     {f} ({s})
                    \\- {s}Channel{s}: {f}
                    \\
                    , .{
                        ansi.fmt.bold, self.id() orelse "[HIDDEN MESH NETWORK] (DisCo", ansi.reset,
                        ansi.fmt.underline, ansi.reset, MACF{ .bytes = self.mac[0..] }, netdata.oui.findOUI(.short, self.mac) catch "[UNKNOWN]",
                        ansi.fmt.underline, ansi.reset, self.channel,
                    },
                );
            },
        }
    }

    pub fn key(dev: @This()) [6]u8 {
        return dev.mac;
    }
};

/// Meta Information about how a Device was Seen
pub const Meta = struct {
    if_mac: [6]u8,
    mac: [6]u8,
    last_seen: zeit.Instant,
    rssi: i32,
    frame_nums: [32]u16 = @splat(0),
    frame_nums_idx: u8 = 0,

    pub const Key = struct {
        if_mac: [6]u8,
        mac: [6]u8,
    };

    pub fn addSeqNum(self: *@This(), seq_num: u16) void {
        self.frame_nums[self.frame_nums_idx] = seq_num;
        self.frame_nums_idx = (self.frame_nums_idx + 1) % 32;
    }

    pub fn calcRxQual(self: *const @This()) usize {
        const count: u16 = @truncate(32 - mem.count(u16, self.frame_nums[0..], &.{ 0 }));
        if (count < 2) //
            return 0;
        const oldest_idx: u8 = //
            if (count < 32) 0 //
            else self.frame_nums_idx;
        const newest_idx: u8 = (self.frame_nums_idx + 31) % 32;
        const oldest = self.frame_nums[oldest_idx];
        const newest = self.frame_nums[newest_idx];
        const span: u16 = //
            if (newest >= oldest) newest - oldest //
            else (4096 - oldest) + newest;
        if (span == 0) //
            return 100;
        return @intFromFloat(@min(100, @as(f32, @floatFromInt(count)) / @as(f32, @floatFromInt(span)) * 100));
    }

    pub fn key(dev_meta: @This()) Key {
        return .{ .if_mac = dev_meta.if_mac, .mac = dev_meta.mac };
    }

    pub fn format(self: @This(), writer: *Io.Writer) Io.Writer.Error!void {
        var last_ts_buf: [50]u8 = undefined;
        const last_ts = self.last_seen.time().bufPrint(last_ts_buf[0..], .rfc3339) catch "[Time Format Error]";
        try writer.print(
            \\- {s}Interface{s}: {f}
            \\- {s}Device{s}:    {f}
            \\- {s}RSSI{s}:      {f}{s} dBm
            \\- {s}Rx Qual{s}:   {d}%
            \\- {s}Last Seen{s}: {s}
            \\
            , .{
                ansi.fmt.underline, ansi.reset, MACF{ .bytes = self.if_mac[0..] },
                ansi.fmt.underline, ansi.reset, MACF{ .bytes = self.mac[0..] },
                ansi.fmt.underline, ansi.reset, RSSI{ .strength = self.rssi }, ansi.reset,
                ansi.fmt.underline, ansi.reset, self.calcRxQual(),
                ansi.fmt.underline, ansi.reset, last_ts,
            },
        );
    }
};

/// WiFi Devices Context
pub const Context = struct {
    /// Arena
    _arena: *heap.ArenaAllocator,
    /// Arena Allocator
    _a_alloc: mem.Allocator,
    /// Frame Arena
    _frame_arena: *heap.ArenaAllocator,
    /// Frame Arena Allocator
    _frame_alloc: mem.Allocator,
    /// Device MultiArrayList
    dev_mal: *ThreadHashMAL([6]u8, Device, Device.key),
    /// Meta MultiArrayList
    meta_mal: *ThreadHashMAL(Meta.Key, Meta, Meta.key),
    //freqs_seen: *ArrayList(u16),
    //frames_seen: *ArrayList(wifi.Header.FrameType),
    frame_trace_times: *ArrayList(u64),
    ie_trace_times: *ArrayList(u64),

    /// Initialize the Devices Context.
    pub fn init(core_ctx: *core.Core) !@This() {
        var self: @This() = undefined;
        self._arena = core_ctx.alloc.create(heap.ArenaAllocator) catch @panic("OOM");
        self._arena.* = .init(core_ctx.alloc);
        self._a_alloc = self._arena.allocator();
        self._frame_arena = core_ctx.alloc.create(heap.ArenaAllocator) catch @panic("OOM");
        self._frame_arena.* = .init(core_ctx.alloc);
        self._frame_alloc = self._frame_arena.allocator();
        self.dev_mal = self._a_alloc.create(ThreadHashMAL([6]u8, Device, Device.key)) catch @panic("OOM");
        self.dev_mal.* = .empty;
        self.meta_mal = self._a_alloc.create(ThreadHashMAL(Meta.Key, Meta, Meta.key)) catch @panic("OOM");
        self.meta_mal.* = .empty;
        self.frame_trace_times = self._a_alloc.create(ArrayList(u64)) catch @panic("OOM");
        self.frame_trace_times.* = .empty;
        self.ie_trace_times = self._a_alloc.create(ArrayList(u64)) catch @panic("OOM");
        self.ie_trace_times.* = .empty;
        return self;
    }

    /// Deinitialize the Devices Context
    pub fn deinit(self: *@This(), alloc: mem.Allocator) void {
        self._frame_arena.deinit();
        alloc.destroy(self._frame_arena);
        defer {
            self._arena.deinit();
            alloc.destroy(self._arena);
        }
        if (builtin.mode != .Debug or self.dev_mal.mal.len == 0) //
            return;
        self.dev_mal.mutex.lock();
        self.meta_mal.mutex.lock();
        defer {
            self.dev_mal.mutex.unlock();
            //self.dev_mal.deinit(alloc);
            self.meta_mal.mutex.unlock();
            //self.meta_mal.deinit(alloc);
        }
        chans: {
            log.debug("Channels Seen:", .{});
            const chans_seen = self.dev_mal.mal.items(.channel);
            if (chans_seen.len == 0) {
                log.debug("- None Seen", .{});
                break :chans;
            }
            for (chs.Channels.all_20) |chan| {
                var count: usize = 0;
                for (chans_seen) |ch_s| {
                    if (meta.eql(chan, ch_s)) //
                        count += 1;
                }
                if (count > 0) //
                    log.debug("- {f}: {d}", .{ chan, count });
            }
        }
        devs: {
            log.debug("Devices Seen:", .{});
            const kinds_seen = self.dev_mal.mal.items(.kind);
            if (kinds_seen.len == 0) {
                log.debug("- None Seen", .{});
                break :devs;
            }
            for (enums.values(Device.Kind)) |kind| {
                var count: usize = 0;
                for (kinds_seen) |ch_s| {
                    if (meta.eql(kind, ch_s)) //
                        count += 1;
                }
                if (count > 0) //
                    log.debug("- {t}: {d}", .{ kind, count });
            }
        }
        frame_time: {
            if (self.frame_trace_times.items.len == 0) {
                log.debug("- None Seen", .{});
                break :frame_time;
            }
            var trace_total: u2096 = 0;
            for (self.frame_trace_times.items) |trace_time| //
                trace_total += trace_time;
            const trace_avg: u64 = @truncate(@divFloor(trace_total, self.frame_trace_times.items.len));
            log.debug("Frame Trace Average: {d}ns | {d}us", .{ trace_avg, @divFloor(trace_avg, time.ns_per_us) });
        }
        ie_time: {
            if (self.ie_trace_times.items.len == 0) {
                log.debug("- None Seen", .{});
                break :ie_time;
            }
            var trace_total: u2096 = 0;
            for (self.ie_trace_times.items) |trace_time| //
                trace_total += trace_time;
            const trace_avg: u64 = @truncate(@divFloor(trace_total, self.ie_trace_times.items.len));
            log.debug("IE Trace Average: {d}ns | {d}us", .{ trace_avg, @divFloor(trace_avg, time.ns_per_us) });
        }
    }

    /// Parse Frames for Device Info
    pub fn parseFrames(self_ptr: *anyopaque, frames: []const []const u8, parse_ctx: core.sockets.Parser.Context) !void {
        //_ = parse_ctx;
        if (frames.len == 0) //
            return;
        var self: *@This() = @ptrCast(@alignCast(self_ptr));
        //const core_ctx: *core.Core = @alignCast(@fieldParentPtr("dev_ctx", self));
        var trace_timer: time.Timer = time.Timer.start() catch @panic("Time Issue");
        _ = self._frame_arena.reset(.retain_capacity);
        frameLoop: for (frames) |frame| {
            defer self.frame_trace_times.append(self._a_alloc, trace_timer.lap()) catch @panic("OOM");
            if (frame.len < 18) //
                continue :frameLoop;
            // Reset Frame Reader
            var frame_r: Io.Reader = .fixed(frame);
            // Parse Radiotap Header
            const rt_hdr = frame_r.takeStruct(radiotap.Header, .little) catch |err| {
                log.warn("Frame Parsing Issue: {t}", .{ err });
                continue;
            };
            if (frame.len <= rt_hdr.it_len) //
                continue :frameLoop;
            var present_list: ArrayList(u32) = .empty;
            defer present_list.deinit(self._frame_alloc);
            present_list.append(self._frame_alloc, rt_hdr.it_present) catch @panic("OOM");
            while (present_list.items[present_list.items.len - 1] & @as(u32, 1) << @truncate(c(radiotap.DefinedFields).EXT) != 0) {
                const word = frame_r.takeInt(u32, .little) catch |err| {
                    log.warn("Radiotap Header Parsing Issue: {t}", .{ err });
                    continue;
                };
                present_list.append(self._frame_alloc, word) catch @panic("OOM");
            }
            // Parse Radiotap Data
            var rt_data: radiotap.Data = .{};
            for (present_list.items, 0..) |word, idx| {
                const base: u8 = @truncate(32 * idx);
                for (0..30) |bit| {
                    if (word & @as(u32, 1) << @truncate(bit) == 0) //
                        continue;
                    const field_tag = enums.fromInt(radiotap.DefinedFields, @as(u32, @truncate(bit + base))) orelse continue;
                    switch (field_tag) {
                        .EXT,
                        .RadiotapNamespace,
                            => continue,
                        inline else => |tag| {
                            const FieldT = @typeInfo(@FieldType(radiotap.Data, @tagName(tag))).optional.child;
                            switch (@typeInfo(FieldT)) {
                                .int => {
                                    const data = frame_r.takeInt(FieldT, .little) catch |err| {
                                        log.warn("Radiotap Data Parsing Issue: {t}", .{ err });
                                        continue :frameLoop;
                                    };
                                    @field(rt_data, @tagName(tag)) = data;
                                },
                                .@"struct" => {
                                    const data = frame_r.takeStruct(FieldT, .little) catch |err| {
                                        log.warn("Radiotap Data Parsing Issue: {t}", .{ err });
                                        continue :frameLoop;
                                    };
                                    @field(rt_data, @tagName(tag)) = data;
                                },
                                else => unreachable,
                            }
                        },
                    }
                }
            }
            //if (rt_data.Channel) |ch| //
            //    self.freqs_seen.append(self._a_alloc, ch.freq) catch @panic("OOM");
            if (frame_r.seek < rt_hdr.it_len) //
                frame_r.toss(rt_hdr.it_len - frame_r.seek);
            // Parse 802.11 Header Prefix
            const wifi_prefix = frame_r.takeStruct(wifi.Header.Prefix, .little) catch |err| {
                log.warn("802.11 Header Parsing Issue: {t}", .{ err });
                continue :frameLoop;
            };
            var wifi_hdr: wifi.Header = .{
                .frame_control = @bitCast(wifi_prefix.frame_control),
                .duration = wifi_prefix.duration,
            };
            //self.frames_seen.append(self._a_alloc, wifi_hdr.frame_control.frame_type) catch @panic("OOM");
            var dev: ?Device = null;
            switch (wifi_hdr.frame_control.frame_type) {
                .management,
                .data,
                => |frame_type| {
                    inline for (&.{
                        &wifi_hdr.addr_1,
                        &wifi_hdr.addr_2,
                        &wifi_hdr.addr_3,
                    }) |addr| {
                        addr.* = (frame_r.takeArray(6) catch |err| {
                            log.warn("Management/Data Frame Address Parsing Issue: {t}", .{ err });
                            continue :frameLoop;
                        }).*;
                    }
                    wifi_hdr.seq_control = frame_r.takeInt(u16, .little) catch |err| {
                        log.warn("Management/Data Frame Sequence Parsing Issue: {t}", .{ err });
                        continue :frameLoop;
                    };
                    // Update Meta for this device
                    updateMeta: {
                        const device_mac = wifi_hdr.addr_2 orelse break :updateMeta;
                        const seq_num: u16 = (wifi_hdr.seq_control orelse break :updateMeta) >> 4;
                        var new_meta: Meta = .{
                            .if_mac = parse_ctx.if_mac,
                            .mac = device_mac,
                            .last_seen = zeit.instant(.{}) catch break :updateMeta,
                            .rssi = rt_data.AntSignal orelse 0,
                        };
                        const meta_key: Meta.Key = .{
                            .if_mac = parse_ctx.if_mac,
                            .mac = device_mac,
                        };
                        const existing_idx: ?usize = self.meta_mal.getIndex(meta_key, false);
                        if (existing_idx) |idx| {
                            new_meta.frame_nums = self.meta_mal.mal.items(.frame_nums)[idx];
                            new_meta.frame_nums_idx = self.meta_mal.mal.items(.frame_nums_idx)[idx];
                        }
                        new_meta.addSeqNum(seq_num);
                        if (existing_idx) |idx| //
                            self.meta_mal.set(idx, new_meta) //
                        else //
                            self.meta_mal.append(self._a_alloc, new_meta) catch @panic("OOM");
                        //log.debug("{f}", .{ new_meta });
                    }
                    switch (frame_type) {
                        .management => {
                            const addr_2 = wifi_hdr.addr_2 orelse continue :frameLoop;
                            if (self.dev_mal.getIndex(addr_2, false)) |_|
                                continue :frameLoop;
                            const rt_ch = rt_data.Channel orelse continue :frameLoop;
                            //const addr_3 = wifi_hdr.addr_3 orelse continue :frameLoop;
                            const fixed_params = fixedParams: switch (wifi_hdr.frame_control.frame_subtype.management) {
                                inline else => |subtype| {
                                    const SubT = @FieldType(wifi.Header.ManagementFixed, @tagName(subtype));
                                    switch (@typeInfo(SubT)) {
                                        .@"struct" => {
                                            const in_struct = frame_r.takeStruct(SubT, .little) catch |err| {
                                                log.warn("Management Frame Fixed Parameter Parsing Issue: {t}", .{ err });
                                                continue :frameLoop;
                                            };
                                            break :fixedParams @unionInit(wifi.Header.ManagementFixed, @tagName(subtype), in_struct);
                                        },
                                        .void => break :fixedParams @unionInit(wifi.Header.ManagementFixed, @tagName(subtype), {}),
                                        else => {
                                            log.warn("Management Frame Fixed Parameter Parsing Issue: Unknown Type ({s})", .{ @typeName(SubT) });
                                            continue :frameLoop;
                                        },
                                    }
                                }
                            };
                            const tagged_params: ?ies.InformationElements = taggedParams: switch (wifi_hdr.frame_control.frame_subtype.management) {
                                .beacon,
                                .probe_request,
                                .probe_response,
                                .association_request,
                                .association_response,
                                .reassociation_request,
                                .reassociation_response,
                                .timing_advertisement,
                                => {
                                    const ie_start = trace_timer.read();
                                    defer {
                                        const ie_stop = trace_timer.read();
                                        defer self.ie_trace_times.append(self._a_alloc, ie_stop -| ie_start) catch @panic("OOM");
                                    }
                                    break :taggedParams nl.parse.fromBytes(self._a_alloc, ies.InformationElements, frame_r.buffered()) catch |err| {
                                        log.warn("Management Frame Tagged Parameter Parsing Issue: {t}", .{ err });
                                        continue :frameLoop;
                                    };
                                },
                                else => break :taggedParams null,
                            };
                            dev = .{
                                .mac = addr_2,
                                .channel = ch: {
                                    const bw: chs.Bandwidth = bw: {
                                        if (rt_data.VHT) |vht| switch (vht.bandwidth) {
                                            1...3 => break :bw .bw40,
                                            4...10 => break :bw .bw80,
                                            11...25 => break :bw .bw160,
                                            else => break :bw .bw20,
                                        };
                                        break :bw .bw20;
                                    };
                                    break :ch chs.Channel.fromFreqBW(rt_ch.freq, bw) catch |err| {
                                        log.warn("Management Frame Channel Parsing Issue: {t}", .{ err });
                                        continue :frameLoop;
                                    };
                                },
                                .kind = kind: {
                                    if (tagged_params) |tps| {
                                        if (tps.MESH_ID) |_| //
                                            break :kind .mesh;
                                    }
                                    break :kind switch (wifi_hdr.frame_control.frame_subtype.management) {
                                        .beacon,
                                        .probe_response,
                                        .association_response,
                                        .reassociation_response,
                                        => .ap,
                                        else => .sta,
                                    };
                                },
                                .bss = bss: {
                                    switch (wifi_hdr.frame_control.frame_subtype.management) {
                                        .beacon,
                                        .probe_response,
                                        .association_response,
                                        .reassociation_response,
                                        => {},
                                        else => break :bss null,
                                    }
                                    const tps = tagged_params orelse break :bss null;
                                    break :bss .{
                                        .BSSID = addr_2,
                                        .FREQUENCY = rt_ch.freq,
                                        .INFORMATION_ELEMENTS = tps,
                                        .TSF = switch (fixed_params) {
                                            .beacon, .probe_response => |b| b.timestamp,
                                            else => null,
                                        },
                                        .BEACON_INTERVAL = switch (fixed_params) {
                                            .beacon, .probe_response => |b| b.beacon_interval,
                                            else => null,
                                        },
                                        .CAPABILITY = switch (fixed_params) {
                                            .beacon, .probe_response => |b| b.capability_info,
                                            else => null,
                                        },
                                        .SIGNAL_MBM = if (rt_data.AntSignal) |s| @as(i32, s) * 100 else null,
                                    };
                                },
                            };
                        },
                        .data => {
                            if (wifi_hdr.frame_control.to_DS and wifi_hdr.frame_control.from_DS) {
                                wifi_hdr.addr_4 = (frame_r.takeArray(6) catch |err| {
                                    log.warn("Data Frame Address Parsing Issue: {t}", .{ err });
                                    continue :frameLoop;
                                }).*;
                            }
                            switch (wifi_hdr.frame_control.frame_subtype.data) {
                                .qos_data,
                                .qos_data_cf_ack,
                                .qos_data_cf_poll,
                                .qos_data_cf_ack_cf_poll,
                                .qos_null,
                                .qos_cf_poll,
                                .qos_cf_ack_cf_poll,
                                => {
                                    wifi_hdr.qos_control = frame_r.takeInt(u16, .little) catch |err| {
                                        log.warn("Data Frame QoS Parsing Issue: {t}", .{ err });
                                        continue :frameLoop;
                                    };
                                },
                                else => {},
                            }
                        },
                        else => unreachable,
                    }
                },
                .control => switch (wifi_hdr.frame_control.frame_subtype.control) {
                    else => {},
                },
                .extension => continue :frameLoop,
            }
            if (dev) |_dev| {
                //if (self.dev_mal.getIndex(.mac, _dev.mac, false)) |dev_idx| //
                //    self.dev_mal.mal.set(dev_idx, _dev) //
                //else //
                //    self.dev_mal.mal.append(self._a_alloc, _dev) catch @panic("OOM");
                self.dev_mal.append(self._a_alloc, _dev) catch @panic("OOM");
                //log.debug("{f}", .{ fmt.alt(_dev, .formatANSI) });
            }
        }
    }

    /// Start Parsing
    pub fn start(self: *@This()) void {
        const core_ctx: *core.Core = @alignCast(@fieldParentPtr("dev_ctx", self));
        core_ctx.sock_event_loop.handlers.put(
            core_ctx.alloc,
            "devices",
            .{
                .ctx = &core_ctx.dev_ctx,
                .wifi_handle_fn = parseFrames,
            },
        ) catch @panic("OOM");
        log.debug("Started Parsing Frames for Device Info.", .{});
    }

    /// Satisfy the `Io.Reader` Interface.
    pub fn frameStream(_: *Io.Reader, _: *Io.Writer, _: Io.Limit) Io.Reader.StreamError!usize {
        return 0;
    }

};

/// Received Signal Stength Index (RSSI)
pub const RSSI = struct {
    /// Signal Strength in dBm
    strength: i32,

    pub fn format(self: @This(), writer: *Io.Writer) Io.Writer.Error!void {
        const rssi_color: []const u8 = switch (self.strength) {
            -40...100 => ansi.fg.green,
            -70...-41 => ansi.fg.yellow,
            else => ansi.fg.red,
        };
        try writer.print("{s}{d}{s}", .{ rssi_color, self.strength, ansi.fg.reset });
    }
};
