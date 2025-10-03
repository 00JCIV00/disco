//! Packet Captures
//! [IETF Draft](https://www.ietf.org/archive/id/draft-tuexen-opsawg-pcapng-05.html#name-enhanced-packet-block)
//! [pcapng.com](https://pcapng.com)

const std = @import("std");
const atomic = std.atomic;
const fs = std.fs;
const log = std.log.scoped(.pcap);
const math = std.math;
const mem = std.mem;
const net = std.net;
const posix = std.posix;
const time = std.time;
const Io = std.Io;
const Thread = std.Thread;

const zeit = @import("zeit");

const core = @import("../core.zig");
const netdata = @import("../netdata.zig");
const address = netdata.address;
const pcap = netdata.pcap;
const IPF = address.IPFormatter;
const MACF = address.MACFormatter;
const utils = @import("../utils.zig");
const HexF = utils.HexFormatter;
const SocketWriter = utils.SocketWriter;
const ThreadArrayList = utils.ThreadArrayList;
const ThreadHashMap = utils.ThreadHashMap;

/// PCAP Config
pub const Config = struct {
    file: ?FileConfig = .{},
    tcp: ?TCPConfig = null,

    pub const FileConfig = struct {
        /// Directory to write PCAP-NG files to.
        dir: []const u8 = ".",
        /// Prefix for PCAP-NG files.
        prefix: []const u8 = "disco_",
        /// Suffix for PCAP-NG files.
        suffix: []const u8 = ".pcapng",
        /// Max File Size in Kilobytes (KB)
        max_filesize: usize = 10_000,
    };
    
    pub const TCPConfig = struct {
        /// IP & Port to host the TCP PCAP Stream on (Ex: 0.0.0.0:12345)
        ip_port: []const u8 = "0.0.0.0:12071",
        /// Max # of Connections
        max_conns: u8 = 10,
    };
};

/// File Context
pub const FileContext = struct {
    /// File Config
    config: Config.FileConfig,
    /// PCAP Directory
    dir: fs.Dir,
    /// PCAP File
    file: fs.File,
    /// PCAP Filename
    filename: []const u8 = "",
    /// PCAP Basename
    basename: []const u8 = "",
    /// Counter for File Splitting
    split_count: usize = 0,
};

/// TCP Context
pub const TCPContext = struct {
    /// TCP Config
    config: Config.TCPConfig,
    /// Accept Socket
    accept_sock: posix.socket_t,
    /// Connections List 
    conn_list: ThreadArrayList(Connection) = .empty,

    /// Connected Client
    pub const Connection = struct {
        sock: posix.socket_t,
        addr: posix.sockaddr.in,
        writer: SocketWriter,
    };
};

/// Interface Description Block (IDB) Pair for Managed & Monitor versions of an Interface
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
    /// File Context
    file_ctx: ?FileContext = null,
    /// PCAP TCP Stream Host Address
    tcp_ctx: ?TCPContext = null,
    /// Frame Writer
    frame_writer: Io.Writer,
    /// Current Parser Context for writing Frames
    parser_ctx: ?core.sockets.Parser.Context = null,


    /// Initialize the PCAP-NG Writer
    pub fn init(core_ctx: *core.Core) !@This() {
        const config = &core_ctx.config.pcap_config;
        var file_ctx: ?FileContext = fileCtx: {
            if (config.file) |*file_conf| {
                const cwd = fs.cwd();
                var pcap_dir = cwd.openDir(file_conf.dir, .{}) catch |err| switch (err) {
                    error.FileNotFound => pcapDir: {
                        log.warn("Unable to find '{s}'. Writing to the Current Directory instead.", .{ file_conf.dir });
                        file_conf.dir = ".";
                        break :pcapDir cwd;
                    },
                    else => return err,
                };
                var fn_w: Io.Writer.Allocating = .init(core_ctx.alloc);
                var fn_writer = &fn_w.writer;
                errdefer fn_w.deinit();
                //try fn_writer.print("{s}/{s}", .{ config.dir, config.prefix });
                const basename = baseName: {
                    const cur_ts = zeit.instant(.{}) catch @panic("Time Source Issue!");
                    try cur_ts.time().strftime(fn_writer, "%Y%m%dT%H%M%S");
                    break :baseName fn_w.toOwnedSlice() catch @panic("OOM");
                };
                try fn_writer.print("{s}{s}{s}", .{
                    file_conf.prefix,
                    basename,
                    file_conf.suffix,
                });
                const filename = try fn_w.toOwnedSlice();
                errdefer core_ctx.alloc.free(filename);
                const file = try pcap_dir.createFile(filename, .{ .read = true });
                break :fileCtx .{
                    .config = file_conf.*,
                    .file = file,
                    .filename = filename,
                    .basename = basename,
                    .dir = pcap_dir,
                };
            }
            break :fileCtx null;
        };
        errdefer if (file_ctx) |*f_ctx| {
            core_ctx.alloc.free(f_ctx.filename);
            core_ctx.alloc.free(f_ctx.basename);
            if (!mem.eql(u8, f_ctx.config.dir, ".")) //
                f_ctx.dir.close();
            f_ctx.file.close();
        };
        const tcp_ctx: ?TCPContext = tcpCtx: {
            if (config.tcp) |tcp_conf| {
                const tcp_addr = address.parseIPPort(tcp_conf.ip_port) catch |err| {
                    log.err("Could not parse IP/Port: {t}", .{ err });
                    break :tcpCtx null;
                };
                const tcp_sock = posix.socket(posix.AF.INET, posix.SOCK.STREAM, 0) catch |err| {
                    log.err("Could not create TCP Socket: {t}", .{ err });
                    break :tcpCtx null;
                };
                posix.bind(tcp_sock, &tcp_addr.any, tcp_addr.getOsSockLen()) catch |err| {
                    log.err("Could not bind to TCP Socket: {t}", .{ err });
                    break :tcpCtx null;
                };
                posix.listen(tcp_sock, 0) catch |err| {
                    log.err("Could not listen on TCP Socket: {t}", .{ err });
                    break :tcpCtx null;
                };
                break :tcpCtx .{
                    .config = tcp_conf,
                    .accept_sock = tcp_sock,
                };
            }
            break :tcpCtx null;
        };
        var self: @This() = .{
            .shb = .{
                .block_total_len = @sizeOf(pcap.SectionHeaderBlock) + 4,
                .section_len = 0,
            },
            .file_ctx = file_ctx,
            .tcp_ctx = tcp_ctx,
            .frame_writer = .{
                .vtable = &.{
                    .drain = frameDrain,
                },
                .buffer = &.{},
            },
        };
        //log.debug("SHB Hex: {f}", .{ HexF{ .bytes = mem.asBytes(&self.shb)} });
        if (self.file_ctx) |*f_ctx| {
            const pcap_file = &f_ctx.file;
            var file_w = pcap_file.writer(&.{});
            try self.writeSHB(&file_w.interface);
        }
        return self;
    }

    /// Deinitialize the PCAP-NG Writer
    pub fn deinit(self: *@This(), core_ctx: *core.Core) void {
        self.finalize(core_ctx) catch |err| {
            log.warn("There was a problem finalizing the PCAP file/stream: {t}", .{ err });
        };
        if (self.file_ctx) |*file_ctx| {
            log.info("Wrote PCAP file to '{s}'.", .{ file_ctx.filename });
            if (!mem.eql(u8, file_ctx.config.dir, ".")) //
                file_ctx.dir.close();
            file_ctx.file.close();
            core_ctx.alloc.free(file_ctx.filename);
            core_ctx.alloc.free(file_ctx.basename);
        }
        if (self.tcp_ctx) |*tcp_ctx| {
            posix.close(tcp_ctx.accept_sock);
            for (tcp_ctx.conn_list.items()) |conn| //
                posix.close(conn.sock);
            log.info("Closed {d} TCP Connections", .{ tcp_ctx.conn_list.list.items.len });
            tcp_ctx.conn_list.mutex.unlock();
            tcp_ctx.conn_list.deinit(core_ctx.alloc);
        }
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
        //log.debug("Start Capture Update", .{});
        // Check for Filesize Limit
        if (self.file_ctx) |*file_ctx| newFile: {
            const file = &file_ctx.file;
            const offset: usize = 500;
            //log.debug("File Roll Check: {d}kB / {d}kB", .{ @divFloor(try file.getEndPos() +| offset, 1_000), file_ctx.config.max_filesize });
            if (try file.getEndPos() +| offset < file_ctx.config.max_filesize * 1_000) //
                break :newFile;
            log.info("Rolling PCAP File. ({d}kB / {d}kB)", .{ @divFloor(try file.getEndPos(), 1_000), file_ctx.config.max_filesize });
            try self.finalize(core_ctx);
            file.close();
            const dir = file_ctx.dir;
            file_ctx.filename = fileName: {
                var fn_w: Io.Writer.Allocating = .init(core_ctx.alloc);
                var fn_writer = &fn_w.writer;
                errdefer fn_w.deinit();
                file_ctx.split_count +%= 1;
                fn_writer.print("{s}{s}-{d}{s}", .{
                    file_ctx.config.prefix,
                    file_ctx.basename,
                    file_ctx.split_count,
                    file_ctx.config.suffix,
                }) catch @panic("OOM?");
                core_ctx.alloc.free(file_ctx.filename);
                break :fileName fn_w.toOwnedSlice() catch @panic("OOM");
            };
            file.* = try dir.createFile(file_ctx.filename, .{ .read = true });
            var file_w = file.writer(&.{});
            try self.writeSHB(&file_w.interface);
        }
        // Check for TCP Connections
        if (self.tcp_ctx) |*tcp_ctx| newTCP: {
            if (tcp_ctx.conn_list.list.items.len >= tcp_ctx.config.max_conns) //
                break :newTCP;
            var poll_fd: [1]posix.pollfd = .{ .{
                .fd = tcp_ctx.accept_sock,
                .events = posix.POLL.IN,
                .revents = 0,
            } };
            const poll_resp = posix.poll(poll_fd[0..], 0) catch break :newTCP;
            if (poll_resp == 0 or poll_fd[0].revents & posix.POLL.IN == 0) //
                break :newTCP;
            var conn_addr: posix.sockaddr = undefined;
            var addr_size: u32 = @truncate(@sizeOf(posix.sockaddr.in));
            const conn_sock = posix.accept(
                tcp_ctx.accept_sock,
                &conn_addr,
                &addr_size,
                0,
            ) catch |err| {
                log.err("Could not accept new TCP Connection: {t}", .{ err });
                break :newTCP;
            };
            const conn_addr_in: *posix.sockaddr.in = @ptrCast(@alignCast(&conn_addr));
            const conn_ip = mem.asBytes(&conn_addr_in.addr);
            var conn_writer: SocketWriter = .init(conn_sock, &.{});
            self.writeSHB(&conn_writer.io_writer) catch |err| {
                log.err("Could not write Section Header Block to new TCP Connection at '{f}': {t}", .{ IPF{ .bytes = conn_ip }, err });
                break :newTCP;
            };
            self.writeIDBs(&conn_writer.io_writer) catch |err| {
                log.err("Could not write Interface Description Block to new TCP Connection at '{f}': {t}", .{ IPF{ .bytes = conn_ip }, err });
                break :newTCP;
            };
            tcp_ctx.conn_list.append(
                core_ctx.alloc,
                .{
                    .sock = conn_sock,
                    .addr = conn_addr_in.*,
                    .writer = conn_writer,
                },
            ) catch @panic("OOM");
            log.info("New TCP Connection from '{f}'", .{ IPF{ .bytes = conn_ip } });
        }
        // Update Interfaces
        if (core_ctx.if_ctx.interfaces.count() == self.cur_if_ids.count()) return;
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
                        .link_type = 127,
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
            log.debug("Tracking Interface '{s}' for PCAP.", .{ sock_if.name });
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
            log.debug("Started Handling Frames as PCAP.", .{});
        }
    }

    /// Finalize the current PCAP-NG File
    pub fn finalize(self: *@This(), core_ctx: *core.Core) !void {
        const file = if (self.file_ctx) |file_ctx| file_ctx.file else return;
        var file_r = file.reader(&.{});
        const file_reader = &file_r.interface;
        const no_idb_buf = try file_reader.readAlloc(core_ctx.alloc, try file.getEndPos());
        defer core_ctx.alloc.free(no_idb_buf);
        const epb_buf = no_idb_buf[self.shb.block_total_len..];
        var file_w = file.writer(&.{});
        try file_w.seekTo(self.shb.block_total_len);
        const file_writer = &file_w.interface;
        try self.writeIDBs(file_writer);
        _ = try file_writer.write(epb_buf);
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

    /// Write the provided Section Header Block (`shb`) to the provided `Io.Writer` (`writer`).
    pub fn writeSHB(self: *@This(), writer: *Io.Writer) !void {
        _ = try writer.writeStruct(self.shb, .little);
        _ = try writer.writeInt(u32, self.shb.block_total_len, .little);
        try writer.flush();
    }

    /// Write the provided Interface Description Blocks (`idbs`) to the provided `Io.Writer` (`writer`).
    pub fn writeIDBs(self: *@This(), writer: *Io.Writer) !void {
        var opt_buf: [256]u8 = undefined;
        var opt_w: Io.Writer = .fixed(opt_buf[0..]);
        self.idb_opts.mutex.lock();
        defer {
            self.idbs.mutex.unlock();
            self.idb_opts.mutex.unlock();
        }
        for (self.idbs.items(), 0..) |*idb, idx| {
            defer _ = opt_w.consumeAll();
            const opt_bytes: []const u8 = optBytes: {
                const idb_opts = self.idb_opts.map.get(idx) orelse &.{};
                for (idb_opts) |opt| //
                    _ = try opt_w.writeStruct(opt, .little);
                break :optBytes opt_w.buffered();
            };
            idb.block_total_len = @truncate(@sizeOf(pcap.InterfaceDescriptionBlock) + opt_bytes.len + 4);
            try writer.writeStruct(idb.*, .little);
            _ = try writer.write(opt_bytes);
            try writer.writeInt(u32, idb.block_total_len, .little);
            try writer.flush();
        }
    }

    /// Satisfy the `Io.Writer` Interface.
    /// This will inject Enahanced Packet Block Headers for each Frame.
    fn frameDrain(self: *Io.Writer, data: []const []const u8, _: usize) Io.Writer.Error!usize {
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
        var file_w = fileWriter: {
            if (pcap_writer.file_ctx) |file_ctx| {
                const file = &file_ctx.file;
                var file_w = file.writer(&.{});
                //file_w.end() catch return error.WriteFailed;
                file_w.seekTo(file.getEndPos() catch return error.WriteFailed) catch return error.WriteFailed;
                break :fileWriter file_w;
            }
            break :fileWriter null;
        };
        self.end = 0;
        var n: usize = 0;
        var add_bytes = false;
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
            const pad_bytes = mem.alignForward(usize, bytes.len, 4);
            if (file_w) |*fw| {
                const file_writer = &fw.interface;
                try file_writer.writeStruct(epb_hdr, .little);
                _ = try file_writer.write(bytes);
                for (0..pad_bytes) |_| {
                    try file_writer.writeByte(0);
                    n += 1;
                }
                try file_writer.writeInt(u32, epb_hdr.block_total_len, .little);
                add_bytes = true;
            }
            if (pcap_writer.tcp_ctx) |*tcp_ctx| {
                defer tcp_ctx.conn_list.mutex.unlock();
                for (tcp_ctx.conn_list.items()) |*conn| {
                    const conn_writer = &conn.writer.io_writer;
                    try conn_writer.writeStruct(epb_hdr, .little);
                    _ = try conn_writer.write(bytes);
                    for (0..pad_bytes) |_| {
                        try conn_writer.writeByte(0);
                        n += 1;
                    }
                    try conn_writer.writeInt(u32, epb_hdr.block_total_len, .little);
                }
                add_bytes = true;
            }
            if (add_bytes) n += bytes.len;
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
            const pad_bytes = mem.alignForward(usize, bytes.len, 4) - bytes.len;
            if (file_w) |*fw| {
                const file_writer = &fw.interface;
                try file_writer.writeStruct(epb_hdr, .little);
                //log.debug("EPB: Hdr {d}B | Len {d}B {f}", .{ @sizeOf(pcap.EnhancedPacketBlock), epb_hdr.block_total_len, HexF{ .bytes = mem.asBytes(&epb_hdr) } });
                n += try file_writer.write(bytes);
                //log.debug("Frame Hex: {d}B {f}", .{ bytes.len, HexF{ .bytes = bytes } });
                for (0..pad_bytes) |_| {
                    try file_writer.writeByte(0);
                    n += 1;
                }
                try file_writer.writeInt(u32, epb_hdr.block_total_len, .little);
                add_bytes = true;
            }
            if (pcap_writer.tcp_ctx) |*tcp_ctx| {
                defer tcp_ctx.conn_list.mutex.unlock();
                for (tcp_ctx.conn_list.items()) |*conn| {
                    const conn_writer = &conn.writer.io_writer;
                    try conn_writer.writeStruct(epb_hdr, .little);
                    _ = try conn_writer.write(bytes);
                    for (0..pad_bytes) |_| {
                        try conn_writer.writeByte(0);
                        n += 1;
                    }
                    try conn_writer.writeInt(u32, epb_hdr.block_total_len, .little);
                }
                add_bytes = true;
            }
            //log.debug("EPB Footer:\n{X:0>8}", .{ epb_hdr.block_total_len });
            if (add_bytes) n += bytes.len;
        }
        if (file_w) |*fw| {
            const file_writer = &fw.interface;
            try file_writer.flush();
        }
        if (pcap_writer.tcp_ctx) |*tcp_ctx| {
            defer tcp_ctx.conn_list.mutex.unlock();
            for (tcp_ctx.conn_list.items()) |*conn| {
                const conn_writer = &conn.writer.io_writer;
                try conn_writer.flush();
            }
        }
        return n;
        //log.debug("Wrote {d} Frames | {d}B", .{ data.len, n });
        //return 0;
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
