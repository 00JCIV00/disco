//! Packet Captures
//! [IETF Draft](https://www.ietf.org/archive/id/draft-tuexen-opsawg-pcapng-05.html#name-enhanced-packet-block)
//! [pcapng.com](https://pcapng.com)

const std = @import("std");
const atomic = std.atomic;
const fs = std.fs;
const log = std.log.scoped(.pcap);
const math = std.math;
const mem = std.mem;
const posix = std.posix;
const time = std.time;
const Io = std.Io;
const Thread = std.Thread;

const zeit = @import("zeit");

const core = @import("../core.zig");
const netdata = @import("../netdata.zig");
const pcap = netdata.pcap;
const MACF = netdata.address.MACFormatter;
const utils = @import("../utils.zig");
const HexF = utils.HexFormatter;
const ThreadArrayList = utils.ThreadArrayList;
const ThreadHashMap = utils.ThreadHashMap;

pub const Config = struct {
    /// Directory to write PCAP-NG files to.
    dir: []const u8 = ".",
    /// Prefix for PCAP-NG files.
    prefix: []const u8 = "disco_",
    /// Suffix for PCAP-NG files.
    suffix: []const u8 = ".pcapng",
};

pub const IDBPair = struct {
    /// Monitor Mode ID
    monitor: u32,
    /// Managed Mode ID
    managed: u32,
};

/// PCAP-NG Writer
pub const Writer = struct {
    /// Section Header Block
    shb: pcap.SectionHeaderBlock,
    /// Section Header Block Options
    shb_opts: ThreadArrayList(pcap.OptionHeader) = .empty,
    /// Interface Description Blocks
    idbs: ThreadArrayList(pcap.InterfaceDescriptionBlock) = .empty,
    /// Interface Description Block Options
    idb_opts: ThreadHashMap(usize, []const pcap.OptionHeader) = .empty,
    /// Current Interface IDs for Interfaces
    cur_if_ids: ThreadHashMap([6]u8, IDBPair) = .empty,
    /// PCAP File
    file: fs.File,
    /// PCAP Filename
    filename: []const u8,
    /// Frame Writer
    frame_writer: Io.Writer,
    /// Current Parser Context for writing Frames
    parser_ctx: ?core.sockets.Parser.Context = null,


    /// Initialize the PCAP-NG Writer
    pub fn init(core_ctx: *core.Core) !@This() {
        const config = &core_ctx.config.pcap_config;
        const cwd = fs.cwd();
        var pcap_dir = cwd.openDir(config.dir, .{}) catch |err| switch (err) {
            error.FileNotFound => pcapDir: {
                log.warn("Unable to find '{s}'. Writing to the Current Directory instead.", .{ config.dir });
                config.dir = ".";
                break :pcapDir cwd;
            },
            else => return err,
        };
        defer if (!mem.eql(u8, ".", config.dir)) //
            pcap_dir.close();
        const filename: []const u8 = fileName: {
            var fn_w: Io.Writer.Allocating = .init(core_ctx.alloc);
            var fn_writer = &fn_w.writer;
            errdefer fn_w.deinit();
            //try fn_writer.print("{s}/{s}", .{ config.dir, config.prefix });
            _ = try fn_writer.write(config.prefix);
            const cur_ts = zeit.instant(.{}) catch @panic("Time Source Issue!");
            try cur_ts.time().strftime(fn_writer, "%Y%m%dT%H%M%S");
            _ = try fn_writer.write(config.suffix);
            break :fileName try fn_w.toOwnedSlice();
        };
        errdefer core_ctx.alloc.free(filename);
        const file = try pcap_dir.createFile(filename, .{ .read = true });
        errdefer file.close();
        const self: @This() = .{
            .shb = .{
                .block_total_len = @sizeOf(pcap.SectionHeaderBlock) + 4,
                .section_len = 0,
            },
            .file = file,
            .filename = filename,
            .frame_writer = .{
                .vtable = &.{
                    .drain = frame_drain,
                },
                .buffer = &.{},
            },
        };
        //log.debug("SHB Hex: {f}", .{ HexF{ .bytes = mem.asBytes(&self.shb)} });
        var file_w = self.file.writer(&.{});
        const file_writer = &file_w.interface;
        _ = try file_writer.writeStruct(self.shb, .little);
        _ = try file_writer.writeInt(u32, self.shb.block_total_len, .little);
        try file_writer.flush();
        return self;
    }

    /// Deinitialize the PCAP-NG Writer
    pub fn deinit(self: *@This(), core_ctx: *core.Core) void {
        self.finalize(core_ctx) catch |err| {
            log.warn("There was a problem saving the PCAP file: {t}", .{ err });
        };
        log.info("Wrote PCAP file to '{s}'.", .{ self.filename });
        self.file.close();
        core_ctx.alloc.free(self.filename);
        self.shb_opts.deinit(core_ctx.alloc);
        self.idbs.deinit(core_ctx.alloc);
        var idb_opts_iter = self.idb_opts.iterator();
        while (idb_opts_iter.next()) |opts_entry| {
            const opts = opts_entry.value_ptr.*;
            core_ctx.alloc.free(opts);
        }
        self.idb_opts.map.deinit(core_ctx.alloc);
        self.cur_if_ids.deinit(core_ctx.alloc);
    }

    /// Update the PCAP-NG Writer
    pub fn update(self: *@This(), core_ctx: *core.Core) !void {
        if (core_ctx.if_ctx.interfaces.count() == self.cur_if_ids.count()) return;
        //defer self.cur_if_ids.mutex.unlock();
        defer core_ctx.if_ctx.interfaces.mutex.unlock();
        var if_iter = core_ctx.if_ctx.interfaces.iterator();
        while (if_iter.next()) |sock_if_entry| {
            const if_mac = sock_if_entry.key_ptr.*;
            const sock_if = sock_if_entry.value_ptr;
            switch (sock_if.usage) {
                .unavailable,
                .err,
                => continue,
                else => {},
            }
            if (self.cur_if_ids.map.get(if_mac) != null) continue;
            self.idbs.appendSlice(
                core_ctx.alloc,
                &.{
                    .{
                        // Ethernet
                        .link_type = 1,
                        .snap_len = math.maxInt(u16),
                        .block_total_len = @sizeOf(pcap.InterfaceDescriptionBlock) + 4,
                    },
                    .{
                        // 802.11
                        .link_type = 105,
                        .snap_len = math.maxInt(u16),
                        .block_total_len = @sizeOf(pcap.InterfaceDescriptionBlock) + 4,
                    },
                },
            ) catch @panic("OOM");
            self.cur_if_ids.put(
                core_ctx.alloc,
                if_mac,
                .{
                    .managed = @truncate(self.idbs.list.items.len - 2),
                    .monitor = @truncate(self.idbs.list.items.len - 1),
                },
            ) catch @panic("OOM");
            log.debug("Tracking Interface '{s}' for PCAP Writing", .{ sock_if.name });
        }
        if (self.cur_if_ids.count() >= 1 and core_ctx.sock_event_loop.handlers.get("pcap") == null) {
            core_ctx.sock_event_loop.handlers.put(
                core_ctx.alloc,
                "pcap",
                .{
                    .ctx = self,
                    .eth_handle_fn = writeFrames,
                    .wifi_handle_fn = writeFrames,
                },
            ) catch @panic("OOM");
            log.debug("Started Writing Frames to PCAP File.", .{});
        }
    }

    /// Finalize the PCAP-NG File
    pub fn finalize(self: *@This(), core_ctx: *core.Core) !void {
        var opt_w: Io.Writer.Allocating = .init(core_ctx.alloc);
        errdefer opt_w.deinit();
        self.idb_opts.mutex.lock();
        defer {
            self.idbs.mutex.unlock();
            self.idb_opts.mutex.unlock();
        }
        var file_r = self.file.reader(&.{});
        const file_reader = &file_r.interface;
        const no_idb_buf = try file_reader.readAlloc(core_ctx.alloc, try self.file.getEndPos());
        defer core_ctx.alloc.free(no_idb_buf);
        const epb_buf = no_idb_buf[self.shb.block_total_len..];
        var file_w = self.file.writer(&.{});
        try file_w.seekTo(self.shb.block_total_len);
        const file_writer = &file_w.interface;
        for (self.idbs.items(), 0..) |*idb, idx| {
            const opt_bytes: []const u8 = optBytes: {
                const idb_opts = self.idb_opts.map.get(idx) orelse &.{};
                for (idb_opts) |opt| //
                    _ = try opt_w.writer.writeStruct(opt, .little);
                break :optBytes try opt_w.toOwnedSlice();
            };
            idb.block_total_len = @truncate(@sizeOf(pcap.InterfaceDescriptionBlock) + opt_bytes.len + 4);
            try file_writer.writeStruct(idb.*, .little);
            _ = try file_writer.write(opt_bytes);
            try file_writer.writeInt(u32, idb.block_total_len, .little);
            try file_writer.flush();
        }
        _ = try file_writer.write(epb_buf);
    }

    /// Satisfy the `Io.Writer` Interface.
    /// This will inject Enahanced Packet Block Headers for each Frame.
    fn frame_drain(self: *Io.Writer, data: []const []const u8, _: usize) Io.Writer.Error!usize {
        const pcap_writer: *@This() = @fieldParentPtr("frame_writer", self);
        const parser_ctx = pcap_writer.parser_ctx orelse return error.WriteFailed;
        const if_id = ifID: {
            const if_id_pair = pcap_writer.cur_if_ids.get(parser_ctx.if_mac) orelse {
                log.err("No Interface ID found for the Interface with MAC '{f}'.", .{ MACF{ .bytes = parser_ctx.if_mac[0..] }});
                return error.WriteFailed;
            };
            break :ifID switch (parser_ctx.mode) {
                .managed => if_id_pair.managed,
                .monitor => if_id_pair.monitor,
            };
        };
        var file_w = pcap_writer.file.writer(&.{});
        //file_w.end() catch return error.WriteFailed;
        file_w.seekTo(pcap_writer.file.getEndPos() catch return error.WriteFailed) catch return error.WriteFailed;
        const file_writer = &file_w.interface;
        self.end = 0;
        var n: usize = 0;
        if (self.buffered().len > 0) {
            const bytes = self.buffered();
            //log.debug("Frame Hex: {f}", .{ HexF{ .bytes = bytes } });
            const cap_len = mem.alignForward(u32, @truncate(bytes.len), 4);
            const epb_len: u32 = @sizeOf(pcap.EnhancedPacketBlock) + cap_len + 4;
            const epb_ts: Timestamp = .get();
            const epb_hdr: pcap.EnhancedPacketBlock = .{
                .block_total_len = epb_len,
                .interface_id = if_id,
                .ts_high = epb_ts.high,
                .ts_low = epb_ts.low,
                .cap_packet_len = cap_len,
                .og_packet_len = @truncate(bytes.len),
            };
            try file_writer.writeStruct(epb_hdr, .little);
            _ = try file_writer.write(bytes);
            const pad_bytes = mem.alignForward(usize, bytes.len, 4);
            for (0..pad_bytes) |_| //
                try file_writer.writeByte(0);
            try file_writer.writeInt(u32, epb_hdr.block_total_len, .little);
            n += bytes.len;
        }
        for (data) |bytes| {
            const cap_len: u32 = @truncate(bytes.len);
            const epb_len: u32 = @sizeOf(pcap.EnhancedPacketBlock) + cap_len + 4;
            const epb_ts: Timestamp = .get();
            const epb_hdr: pcap.EnhancedPacketBlock = .{
                .block_total_len = epb_len,
                .interface_id = if_id,
                .ts_high = epb_ts.high,
                .ts_low = epb_ts.low,
                .cap_packet_len = cap_len,
                .og_packet_len = cap_len,
            };
            try file_writer.writeStruct(epb_hdr, .little);
            //log.debug("EPB: Hdr {d}B | Len {d}B {f}", .{ @sizeOf(pcap.EnhancedPacketBlock), epb_hdr.block_total_len, HexF{ .bytes = mem.asBytes(&epb_hdr) } });
            n += try file_writer.write(bytes);
            //log.debug("Frame Hex: {d}B {f}", .{ bytes.len, HexF{ .bytes = bytes } });
            const pad_bytes = mem.alignForward(usize, bytes.len, 4) - bytes.len;
            for (0..pad_bytes) |_| {
                try file_writer.writeByte(0);
                n += 1;
            }
            try file_writer.writeInt(u32, epb_hdr.block_total_len, .little);
            //log.debug("EPB Footer:\n{X:0>8}", .{ epb_hdr.block_total_len });
            n += bytes.len;
        }
        try file_writer.flush();
        //log.debug("Wrote {d} Frames | {d}B", .{ data.len, n });
        return n;
    }

    /// Write Frames in PCAP-NG Format
    pub fn writeFrames(self_ptr: *anyopaque, frames: []const []const u8, parser_ctx: core.sockets.Parser.Context) !void {
        if (frames.len == 0) return;
        //log.debug("Writing {d} PCAP Frame(s)", .{ frames.len });
        var self: *@This() = @ptrCast(@alignCast(self_ptr));
        self.parser_ctx = parser_ctx;
        _ = try self.frame_writer.writeVec(frames);
        try self.frame_writer.flush();
        //log.debug("Wrote {d} PCAP Frame(s).", .{ frames.len });
    }
};

pub const Timestamp = struct {
    high: u32,
    low: u32,

    pub fn get() @This() {
        const cur_time: u64 = @intCast(time.microTimestamp());
        return .{
            .high = @intCast(cur_time >> 32),
            .low = @intCast(cur_time & 0xffff_ffff),
        };
    }
};
