//! Device Tracking

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
const wifi = netdata.l2.wifi;
const chs = netdata.l2.wifi.channels;
const radiotap = wifi.radiotap;
const core = @import("../core.zig");
const nl = @import("../netlink.zig");
const proto = @import("../protocols.zig");
const wpa = proto.wpa;
const utils = @import("../utils.zig");
const ansi = utils.ansi;
const c = utils.toStruct;
const ThreadHashMap = utils.ThreadHashMap;


/// Devices Context
pub const Context = struct {
    /// Arena
    _arena: *heap.ArenaAllocator,
    /// Arena Allocator
    _a_alloc: mem.Allocator,
    /// List of all Networks seen
    networks: *ThreadHashMap([6]u8, core.networks.Network),
    freqs_seen: *ArrayList(u16),
    trace_times: *ArrayList(u64),

    /// Initialize the Devices Context.
    pub fn init(core_ctx: *core.Core) !@This() {
        var self: @This() = undefined;
        self._arena = core_ctx.alloc.create(heap.ArenaAllocator) catch @panic("OOM");
        self._arena.* = .init(core_ctx.alloc);
        self._a_alloc = self._arena.allocator();
        self.networks = core_ctx.alloc.create(ThreadHashMap([6]u8, core.networks.Network)) catch @panic("OOM");
        self.networks.* = .empty;
        self.freqs_seen = core_ctx.alloc.create(ArrayList(u16)) catch @panic("OOM");
        self.freqs_seen.* = .empty;
        self.trace_times = core_ctx.alloc.create(ArrayList(u64)) catch @panic("OOM");
        self.trace_times.* = .empty;
        return self;
    }

    /// Deinitialize the Devices Context
    pub fn deinit(self: *@This(), alloc: mem.Allocator) void {
        var nw_iter = self.networks.iterator();
        while (nw_iter.next()) |nw_entry| //
            nw_entry.value_ptr.deinit(alloc);
        nw_iter.unlock();
        self.networks.deinit(alloc);
        alloc.destroy(self.networks);
        self._arena.deinit();
        alloc.destroy(self._arena);
        freqs: {
            defer {
                self.freqs_seen.deinit(alloc);
                alloc.destroy(self.freqs_seen);
            }
            log.debug("Frequencies:", .{});
            if (self.freqs_seen.items.len == 0) {
                log.debug("- None Seen", .{});
                break :freqs;
            }
            for (chs.Frequencies.all_20) |freq| {
                const count = mem.count(u16, self.freqs_seen.items, &.{ @truncate(freq) });
                log.debug("- {d}MHz: {d}", .{ freq, count });
            }
        }
        time: {
            defer {
                self.trace_times.deinit(alloc);
                alloc.destroy(self.trace_times);
            }
            if (self.trace_times.items.len == 0) {
                log.debug("- None Seen", .{});
                break :time;
            }
            var trace_total: u2096 = 0;
            for (self.trace_times.items) |trace_time| //
                trace_total += trace_time;
            const trace_avg: u64 = @truncate(@divFloor(trace_total, self.trace_times.items.len));
            log.debug("Frame Trace Average: {d}ns | {d}ms", .{ trace_avg, @divFloor(trace_avg, time.ns_per_ms) });
        }
    }

    /// Parse Frames for Device Info
    pub fn parseFrames(self_ptr: *anyopaque, frames: []const []const u8, _: core.sockets.Parser.Context) !void {
        if (frames.len == 0) //
            return;
        var self: *@This() = @ptrCast(@alignCast(self_ptr));
        const core_ctx: *core.Core = @alignCast(@fieldParentPtr("dev_ctx", self));
        var trace_timer: time.Timer = time.Timer.start() catch @panic("Time Issue");
        _ = self._arena.reset(.retain_capacity);
        for (frames) |frame| {
            defer self.trace_times.append(core_ctx.alloc, trace_timer.lap()) catch @panic("OOM");
            // Reset Frame Reader
            var frame_r: Io.Reader = .fixed(frame);
            // Parse Radiotap Header
            const rt_hdr = frame_r.takeStruct(radiotap.Header, .little) catch |err| {
                log.warn("Frame Parsing Issue: {t}", .{ err });
                continue;
            };
            var present_list: ArrayList(u32) = .empty;
            defer present_list.deinit(self._a_alloc);
            present_list.append(self._a_alloc, rt_hdr.it_present) catch @panic("OOM");
            while (present_list.items[present_list.items.len - 1] & @as(u32, 1) << @truncate(c(radiotap.DefinedFields).EXT) != 0) {
                const word = frame_r.takeInt(u32, .little) catch |err| {
                    log.warn("Radiotap Header Parsing Issue: {t}", .{ err });
                    continue;
                };
                present_list.append(core_ctx.alloc, word) catch @panic("OOM");
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
                                        continue;
                                    };
                                    @field(rt_data, @tagName(tag)) = data;
                                },
                                .@"struct" => {
                                    const data = frame_r.takeStruct(FieldT, .little) catch |err| {
                                        log.warn("Radiotap Data Parsing Issue: {t}", .{ err });
                                        continue;
                                    };
                                    @field(rt_data, @tagName(tag)) = data;
                                },
                                else => unreachable,
                            }
                        },
                    }
                }
            }
            if (rt_data.Channel) |ch| //
                self.freqs_seen.append(core_ctx.alloc, ch.freq) catch @panic("OOM");
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
