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

/// WiFi Device
pub const Device = struct {
    mac: [6]u8,
    channel: chs.Channel,
    ssid: ?[]const u8,
    kind: Kind,

    pub const Kind = enum(u8) {
        ap,
        sta,
        mesh,
    };

    pub fn format(self: @This(), writer: *Io.Writer) Io.Writer.Error!void {
        try writer.print(
            \\{f}
            \\- {t}
            \\- Ch:   {f}
            \\- SSID: {?s}
            \\
            , .{
                MACF{ .bytes = self.mac[0..] },
                self.kind,
                self.channel,
                self.ssid,
            },
        );
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
    dev_mal: *ThreadMAL(Device),
    /// Meta MultiArrayList
    meta_mal: *ThreadMAL(Meta),
    //freqs_seen: *ArrayList(u16),
    //frames_seen: *ArrayList(wifi.Header.FrameType),
    trace_times: *ArrayList(u64),

    /// Initialize the Devices Context.
    pub fn init(core_ctx: *core.Core) !@This() {
        var self: @This() = undefined;
        self._arena = core_ctx.alloc.create(heap.ArenaAllocator) catch @panic("OOM");
        self._arena.* = .init(core_ctx.alloc);
        self._a_alloc = self._arena.allocator();
        self._frame_arena = core_ctx.alloc.create(heap.ArenaAllocator) catch @panic("OOM");
        self._frame_arena.* = .init(core_ctx.alloc);
        self._frame_alloc = self._frame_arena.allocator();
        self.dev_mal = self._a_alloc.create(ThreadMAL(Device)) catch @panic("OOM");
        self.dev_mal.* = .empty;
        self.meta_mal = self._a_alloc.create(ThreadMAL(Meta)) catch @panic("OOM");
        self.meta_mal.* = .empty;
        self.trace_times = self._a_alloc.create(ArrayList(u64)) catch @panic("OOM");
        self.trace_times.* = .empty;
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
        time: {
            if (self.trace_times.items.len == 0) {
                log.debug("- None Seen", .{});
                break :time;
            }
            var trace_total: u2096 = 0;
            for (self.trace_times.items) |trace_time| //
                trace_total += trace_time;
            const trace_avg: u64 = @truncate(@divFloor(trace_total, self.trace_times.items.len));
            log.debug("Frame Trace Average: {d}ns | {d}us", .{ trace_avg, @divFloor(trace_avg, time.ns_per_us) });
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
            defer self.trace_times.append(self._a_alloc, trace_timer.lap()) catch @panic("OOM");
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
                        const metas = self.meta_mal.mal.items(.mac);
                        const if_macs = self.meta_mal.mal.items(.if_mac);
                        const existing_idx: ?usize = existingIdx: {
                            for (metas, if_macs, 0..) |mac, if_mac, idx| {
                                if (!mem.eql(u8, mac[0..], device_mac[0..])) //
                                    continue;
                                if (!mem.eql(u8, if_mac[0..], parse_ctx.if_mac[0..])) //
                                    continue;
                                new_meta.frame_nums = self.meta_mal.mal.items(.frame_nums)[idx];
                                new_meta.frame_nums_idx = self.meta_mal.mal.items(.frame_nums_idx)[idx];
                                break :existingIdx idx;
                            }
                            break :existingIdx null;
                        };
                        new_meta.addSeqNum(seq_num);
                        if (existing_idx) |idx| //
                            self.meta_mal.mal.set(idx, new_meta) //
                        else //
                            self.meta_mal.mal.append(self._a_alloc, new_meta) catch @panic("OOM");
                        //log.debug("{f}", .{ new_meta });
                    }
                    switch (frame_type) {
                        .management => {
                            const addr_2 = wifi_hdr.addr_2 orelse continue :frameLoop;
                            if (self.dev_mal.getIndex(.mac, addr_2, false)) |_|
                                continue :frameLoop;
                            const addr_3 = wifi_hdr.addr_3 orelse continue :frameLoop;
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
                            _ = fixed_params;
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
                                    break :taggedParams nl.parse.fromBytes(self._frame_alloc, ies.InformationElements, frame_r.buffered()) catch |err| {
                                        log.warn("Management Frame Tagged Parameter Parsing Issue: {t}", .{ err });
                                        continue :frameLoop;
                                    };
                                },
                                else => break :taggedParams null,
                            };
                            dev = .{
                                .channel = ch: {
                                    const ch = rt_data.Channel orelse continue;
                                    const bw: chs.Bandwidth = bw: {
                                        if (rt_data.VHT) |vht| switch (vht.bandwidth) {
                                            1...3 => break :bw .bw40,
                                            4...10 => break :bw .bw80,
                                            11...25 => break :bw .bw160,
                                            else => break :bw .bw20,
                                        };
                                        break :bw .bw20;
                                    };
                                    break :ch chs.Channel.fromFreqBW(ch.freq, bw) catch |err| {
                                        log.warn("Management Frame Channel Parsing Issue: {t}", .{ err });
                                        continue :frameLoop;
                                    };
                                },
                                .kind = //
                                    if (mem.eql(u8, addr_2[0..], addr_3[0..])) //
                                        .ap //
                                    else //
                                        .sta,
                                .mac = addr_2,
                                .ssid = ssid: {
                                    const tps = tagged_params orelse break :ssid null;
                                    const ssid = tps.SSID orelse break :ssid null;
                                    break :ssid self._a_alloc.dupe(u8, ssid) catch @panic("OOM");
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
                self.dev_mal.mal.append(self._a_alloc, _dev) catch @panic("OOM");
                //log.debug("{f}", .{ _dev });
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
