//! Frame Parsing

const builtin = @import("builtin");
const std = @import("std");
const atomic = std.atomic;
const enums = std.enums;
const fmt = std.fmt;
const heap = std.heap;
const linux = std.os.linux;
const log = std.log.scoped(.frames);
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
const networks = @import("networks.zig");
const nl = @import("../netlink.zig");
const proto = @import("../protocols.zig");
const wpa = proto.wpa;
const utils = @import("../utils.zig");
const ansi = utils.ansi;
const c = utils.toStruct;
const ThreadHashMap = utils.ThreadHashMap;
const ThreadMAL = utils.ThreadMultiArrayList;
const ThreadHashMAL = utils.ThreadHashMAL;

const Device = networks.Device;
const Meta = networks.Meta;

/// Frame Parsing Context
pub const Context = struct {
    /// Frame Arena
    _frame_arena: *heap.ArenaAllocator,
    /// Frame Arena Allocator
    _frame_alloc: mem.Allocator,
    //freqs_seen: *ArrayList(u16),
    //frames_seen: *ArrayList(wifi.Header.FrameType),
    frame_trace_times: *ArrayList(u64),
    ie_trace_times: *ArrayList(u64),

    /// Initialize the Frames Context.
    pub fn init(core_ctx: *core.Core) !@This() {
        var self: @This() = undefined;
        self._frame_arena = core_ctx.alloc.create(heap.ArenaAllocator) catch @panic("OOM");
        self._frame_arena.* = .init(core_ctx.alloc);
        self._frame_alloc = self._frame_arena.allocator();
        self.frame_trace_times = core_ctx.a_alloc.create(ArrayList(u64)) catch @panic("OOM");
        self.frame_trace_times.* = .empty;
        self.ie_trace_times = core_ctx.a_alloc.create(ArrayList(u64)) catch @panic("OOM");
        self.ie_trace_times.* = .empty;
        return self;
    }

    /// Deinitialize the Frames Context
    pub fn deinit(self: *@This(), alloc: mem.Allocator) void {
        self._frame_arena.deinit();
        alloc.destroy(self._frame_arena);
        const core_ctx: *core.Core = @alignCast(@fieldParentPtr("frames_ctx", self));
        if (builtin.mode != .Debug or core_ctx.network_ctx.dev_mal.mal.len == 0) //
            return;
        core_ctx.network_ctx.dev_mal.mutex.lock();
        core_ctx.network_ctx.meta_mal.mutex.lock();
        defer {
            core_ctx.network_ctx.dev_mal.mutex.unlock();
            core_ctx.network_ctx.meta_mal.mutex.unlock();
        }
        chans: {
            log.debug("Channels Seen:", .{});
            const chans_seen = core_ctx.network_ctx.dev_mal.mal.items(.channel);
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
            const kinds_seen = core_ctx.network_ctx.dev_mal.mal.items(.kind);
            if (kinds_seen.len == 0) {
                log.debug("- None Seen", .{});
                break :devs;
            }
            for (enums.values(@typeInfo(Device.Kind).@"union".tag_type.?)) |kind| {
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
                log.debug("No Frame Trace Average", .{});
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
                log.debug("No IE Trace Average", .{});
                break :ie_time;
            }
            var trace_total: u2096 = 0;
            for (self.ie_trace_times.items) |trace_time| //
                trace_total += trace_time;
            const trace_avg: u64 = @truncate(@divFloor(trace_total, self.ie_trace_times.items.len));
            log.debug("IE Trace Average: {d}ns | {d}us", .{ trace_avg, @divFloor(trace_avg, time.ns_per_us) });
        }
    }

    /// Parse Frames 
    pub fn parse(self_ptr: *anyopaque, frames: []const []const u8, parse_ctx: core.sockets.Parser.Context) !void {
        if (frames.len == 0) //
            return;
        var self: *@This() = @ptrCast(@alignCast(self_ptr));
        const core_ctx: *core.Core = @alignCast(@fieldParentPtr("frames_ctx", self));
        var trace_timer: time.Timer = time.Timer.start() catch @panic("Time Issue");
        _ = self._frame_arena.reset(.retain_capacity);
        frameLoop: for (frames) |frame| {
            defer self.frame_trace_times.append(core_ctx.a_alloc, trace_timer.lap()) catch @panic("OOM");
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
                        const existing_idx: ?usize = core_ctx.network_ctx.meta_mal.getIndex(meta_key, false);
                        if (existing_idx) |idx| {
                            new_meta.frame_nums = core_ctx.network_ctx.meta_mal.mal.items(.frame_nums)[idx];
                            new_meta.frame_nums_idx = core_ctx.network_ctx.meta_mal.mal.items(.frame_nums_idx)[idx];
                        }
                        new_meta.addSeqNum(seq_num);
                        if (existing_idx) |idx| //
                            core_ctx.network_ctx.meta_mal.set(idx, new_meta) //
                        else //
                            core_ctx.network_ctx.meta_mal.append(core_ctx.a_alloc, new_meta) catch @panic("OOM");
                    }
                    switch (frame_type) {
                        .management => {
                            const addr_2 = wifi_hdr.addr_2 orelse continue :frameLoop;
                            if (core_ctx.network_ctx.dev_mal.getIndex(addr_2, false)) |_|
                                continue :frameLoop;
                            const rt_ch = rt_data.Channel orelse continue :frameLoop;
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
                                        defer self.ie_trace_times.append(core_ctx.a_alloc, ie_stop -| ie_start) catch @panic("OOM");
                                    }
                                    break :taggedParams nl.parse.fromBytes(core_ctx.a_alloc, ies.InformationElements, frame_r.buffered()) catch |err| {
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
                                        const bss: nl._80211.BasicServiceSet = .{
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
                                        if (tps.MESH_ID) |_| //
                                            break :kind .{ .mesh = bss };
                                        break :kind switch (wifi_hdr.frame_control.frame_subtype.management) {
                                            .beacon,
                                            .probe_response,
                                            .association_response,
                                            .reassociation_response,
                                            => .{ .ap = bss },
                                            else => .sta,
                                        };
                                    }
                                    break :kind .sta;
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
            if (dev) |_dev| //
                core_ctx.network_ctx.dev_mal.append(core_ctx.a_alloc, _dev) catch @panic("OOM");
        }
    }

    /// Start Parsing
    pub fn start(self: *@This()) void {
        const core_ctx: *core.Core = @alignCast(@fieldParentPtr("frames_ctx", self));
        core_ctx.sock_event_loop.handlers.put(
            core_ctx.alloc,
            "frames",
            .{
                .ctx = &core_ctx.frames_ctx,
                .wifi_handle_fn = parse,
            },
        ) catch @panic("OOM");
        log.debug("Started Parsing Frames for Device Info.", .{});
    }

    /// Satisfy the `Io.Reader` Interface.
    pub fn frameStream(_: *Io.Reader, _: *Io.Writer, _: Io.Limit) Io.Reader.StreamError!usize {
        return 0;
    }
};
