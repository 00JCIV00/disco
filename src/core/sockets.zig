//! Raw Socket Data from Core Interfaces

const std = @import("std");
const atomic = std.atomic;
const linux = std.os.linux;
const log = std.log.scoped(.sockets);
const mem = std.mem;
const posix = std.posix;
const time = std.time;
const ArrayList = std.ArrayList;
const Io = std.Io;
const Thread = std.Thread;

const core = @import("../core.zig");
const netdata = @import("../netdata.zig");
const l2 = netdata.l2;
const nl = @import("../netlink.zig");
const utils = @import("../utils.zig");
const c = utils.toStruct;
const ThreadHashMap = utils.ThreadHashMap;


/// Frame Parser
pub const Parser = struct {
    /// Allocator for the Frame Lists
    alloc: mem.Allocator,
    /// Mutex for Thread Safety between `streamIn()` and `streamOut()` calls.
    mutex: Thread.Mutex = .{},
    /// The Posix Socket from which data is read
    sock: posix.socket_t,
    /// Parser Context
    ctx: Context,
    /// The underlying `Io.Reader` Interface
    io_reader: Io.Reader,
    /// The underlying `Io.Writer` Interface
    io_writer: Io.Writer,
    /// Buffer for the IO Writer
    io_buf: [16_000]u8 = undefined,
    /// Ethernet Frames List
    eth_list: ArrayList([]const u8) = .empty,
    /// WiFi Frames List
    wifi_list: ArrayList([]const u8) = .empty,


    /// Parser Context
    pub const Context = struct {
        /// The MAC of the corresponding Interface for this Parser
        if_mac: [6]u8,
        /// Parser State
        state: enum { up, down } = .down,
        /// Parser Mode
        mode: enum { managed, monitor } = .managed,
    };

    /// Initialize a new Parser
    pub fn init(alloc: mem.Allocator, sock: posix.socket_t, if_mac: [6]u8) @This() {
        var self: @This() = .{
            .alloc = alloc,
            .sock = sock,
            .ctx = .{ .if_mac = if_mac },
            .io_reader = .{
                .vtable = &.{
                    .stream = io_stream,
                },
                .buffer = &.{},
                .seek = 0,
                .end = 0,
            },
            .io_writer = .{
                .vtable = &.{
                    .drain = io_drain,
                },
                .buffer = &.{},
            },
        };
        self.io_writer.buffer = self.io_buf[0..];
        return self;
    }

    /// Deinitialize this Parser
    pub fn deinit(self: *@This()) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.eth_list.items) |frame| self.alloc.free(frame);
        self.eth_list.deinit(self.alloc);
        for (self.wifi_list.items) |frame| self.alloc.free(frame);
        self.wifi_list.deinit(self.alloc);
    }

    /// Parse data from the Raw Socket into Frames
    pub fn parse(self: *@This()) !usize {
        const locked = self.mutex.tryLock();
        if (!locked) return 0;
        defer if (locked) self.mutex.unlock();
        return try self.io_reader.stream(&self.io_writer, .unlimited);
    }

    /// Get the current Ethernet Frames
    pub fn getEthFrames(self: *@This()) ![]const []const u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return try self.eth_list.toOwnedSlice(self.alloc);
    }

    /// Get the current WiFi Frames
    pub fn getWifiFrames(self: *@This()) ![]const []const u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return try self.wifi_list.toOwnedSlice(self.alloc);
    }

    /// Satisfy the `Io.Reader` Interface.
    fn io_stream(self: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        const parser: *@This() = @alignCast(@fieldParentPtr("io_reader", self));
        if (parser.ctx.state == .down) return 0;
        //log.debug("Reading Data...", .{});
        var n: usize = 0;
        //while (true) {
            const dest = limit.slice(try w.writableSliceGreedy(2500));
            n += posix.recv(parser.sock, dest[0..], 0) catch |err| switch (err) {
                //error.WouldBlock => break,
                error.WouldBlock => return n,
                else => {
                    //log.debug("Read Error: {t}", .{ err });
                    return error.ReadFailed;
                }
            };
            //log.debug("Read {d}B Frame", .{ n });
        //}
        w.advance(n);
        try w.flush();
        return n;
    }

    /// Satisfy the `Io.Writer` Interface.
    fn io_drain(self: *Io.Writer, data: []const []const u8, _: usize) Io.Writer.Error!usize {
        if (data.len == 0) return 0;
        const parser: *@This() = @fieldParentPtr("io_writer", self);
        //log.debug("Writing {d} Frames", .{ data.len });
        var n: usize = 0;
        if (self.buffered().len > 0) {
            const bytes = self.buffered();
            const alloc_bytes = parser.alloc.dupe(u8, bytes) catch @panic("OOM");
            switch (parser.ctx.mode) {
                .managed => parser.eth_list.append(parser.alloc, alloc_bytes) catch @panic("OOM"),
                .monitor => parser.wifi_list.append(parser.alloc, alloc_bytes) catch @panic("OOM"),
            }
            //log.debug("Wrote {d}B Frame", .{ bytes.len });
            n += bytes.len;
        }
        for (data) |bytes| {
            if (bytes.len == 0) continue;
            const alloc_bytes = parser.alloc.dupe(u8, bytes) catch @panic("OOM");
            switch (parser.ctx.mode) {
                .managed => parser.eth_list.append(parser.alloc, alloc_bytes) catch @panic("OOM"),
                .monitor => parser.wifi_list.append(parser.alloc, alloc_bytes) catch @panic("OOM"),
            }
            //log.debug("Wrote {d}B Frame", .{ bytes.len });
            n += bytes.len;
        }
        //log.debug(
        //    \\Wrote {d} Frame(s) | {d}B.
        //    \\- Total Eth:  {d} Frames
        //    \\- Total Wifi: {d} Frames
        //    , .{
        //        if (self.buffered().len > 0) 1 else 0 + data.len,
        //        n,
        //        parser.eth_list.items.len,
        //        parser.wifi_list.items.len,
        //    },
        //);
        self.end = 0;
        return n;
    }
};

/// Frame Handler
pub const Handler = struct {
    /// Hanlde Function Context
    ctx: *anyopaque,
    /// Ethernet Frame Handling Function
    eth_handle_fn: ?*const fn (*anyopaque, []const []const u8, Parser.Context) anyerror!void = null,
    /// WiFi Frame Handling Function
    wifi_handle_fn: ?*const fn (*anyopaque, []const []const u8, Parser.Context) anyerror!void = null,

    /// Handle an Ethernet Frame
    pub fn handleEth(self: @This(), data: []const []const u8, parse_ctx: Parser.Context) anyerror!void {
        const ethFn = self.eth_handle_fn orelse return;
        return ethFn(self.ctx, data, parse_ctx);
    }

    /// Handle a WiFi Frame
    pub fn handleWifi(self: @This(), data: []const []const u8, parse_ctx: Parser.Context) anyerror!void {
        const wifiFn = self.wifi_handle_fn orelse return;
        return wifiFn(self.ctx, data, parse_ctx);
    }
};

/// Sockets Event Loop
pub const Loop = struct {
    /// Thread on which this Loop will run
    /// *Internal Use*
    _thread: Thread = undefined,
    /// Active State of the Loop
    /// *Internal Use*
    _active: atomic.Value(bool) = .init(false),
    /// Epoll File Descriptor
    /// *Internal Use*
    _epoll_fd: posix.socket_t,
    /// Parsers for each Interface
    parsers: ThreadHashMap(posix.socket_t, Parser) = .empty,
    /// Frame Handlers
    handlers: ThreadHashMap([]const u8, Handler) = .empty,

    /// Initialize a new Event Loop
    pub fn init() !@This() {
        return .{
            ._epoll_fd = @intCast(try posix.epoll_create1(0)),
        };
    }

    /// Deinitialize this Event Loop
    pub fn deinit(self: *@This(), alloc: mem.Allocator) void {
        var parsers_iter = self.parsers.iterator();
        while (parsers_iter.next()) |parser_entry| {
            const parser = parser_entry.value_ptr;
            parser.deinit();
        }
        self.parsers.mutex.unlock();
        self.parsers.deinit(alloc);
        self.handlers.deinit(alloc);
    }

    /// Start the Event Loop on its own Thread
    pub fn start(self: *@This(), core_ctx: *core.Core) !void {
        if (self._active.load(.acquire)) return;
        self._active.store(true, .monotonic);
        self._thread = try .spawn(
            .{ .allocator = core_ctx.alloc },
            startThread,
            .{
                self,
                core_ctx,
            },
        );
    }

    /// Start the Event Loop Thread
    fn startThread(self: *@This(), core_ctx: *core.Core) void {
        var events: [64]posix.system.epoll_event = undefined;
        while (core_ctx.active.load(.acquire) and self._active.load(.acquire)) {
            //log.debug("Start: SOCKET THREAD", .{});
            defer {
                //log.debug("End: SOCKET THREAD", .{});
                Thread.sleep(10 * time.ns_per_ms);
            }
            const event_count = posix.epoll_wait(self._epoll_fd, events[0..], -1);
            //log.debug("{d} events: SOCKET THREAD", .{ event_count });
            self.parsers.mutex.lock();
            defer self.parsers.mutex.unlock();
            for (events[0..event_count]) |event| {
                if (!core_ctx.active.load(.acquire) or !self._active.load(.acquire)) break;
                //log.debug("Received event on: {d} ({d})", .{ event.data.fd, event.events });
                if (event.events & linux.EPOLL.ERR != 0) {
                    var err_buf: [1]u8 = .{ 0 };
                    posix.getsockopt(event.data.fd, linux.SOL.SOCKET, linux.SO.ERROR, err_buf[0..]) catch |err| //
                        log.err("Could not clear Socket Error: {t}.", .{ err });
                    //log.debug("Continuing: SOCKET THREAD", .{});
                    continue;
                }
                if (event.events & linux.EPOLL.IN != 0) {
                    const parser_entry = self.parsers.map.getEntry(event.data.fd) orelse continue;
                    const parser = parser_entry.value_ptr;
                    //log.debug("Reading: SOCKET THREAD", .{});
                    const frames_buf_len = parser.parse() catch |err| {
                        if (err == error.OutOfMemory) @panic("OOM");
                        if (err == error.Unexpected) {
                            parser.ctx.state = .down;
                            //continue;
                        }
                        log.err("There was an error while processing a Raw Socket: {t}", .{ err });
                        continue;
                    };
                    _ = frames_buf_len;
                    //log.debug("Read {d}B Frame Bytes.", .{ frames_buf_len });
                }
            }
        }
    }

    /// Stop the Event Loop and its Thread
    /// Optionally deinitialize the Event Loop and its Handlers if `de_alloc` is provided
    pub fn stop(self: *@This(), de_alloc: ?mem.Allocator) void {
        self._active.store(false, .monotonic);
        self._thread.join();
        if (de_alloc) |alloc| self.deinit(alloc);
    }

    /// Update this Socket Loop
    pub fn update(self: *@This(), core_ctx: *core.Core) !void {
        //log.debug("Start: Socket Monitor Update", .{});
        const epoll_events: u32 = linux.EPOLL.IN | linux.EPOLL.OUT;
        //if (self.readers.mutex.tryLock()) {} else return;
        self.parsers.mutex.lock();
        defer self.parsers.mutex.unlock();
        defer core_ctx.if_ctx.interfaces.mutex.unlock();
        var if_iter = core_ctx.if_ctx.interfaces.iterator();
        while (if_iter.next()) |sock_if_entry| {
            const sock_if = sock_if_entry.value_ptr;
            //log.debug("'{s}': Socket Monitor Update", .{ sock_if.name });
            const raw_sock = sock_if.raw_sock orelse continue;
            const sock_parser = sockParser: {
                if (self.parsers.map.getEntry(raw_sock)) |sock_parser_entry| {
                    const sock_parser = sock_parser_entry.value_ptr;
                    if (sock_parser.sock == raw_sock) {
                        sock_parser.ctx.state = //
                            if (sock_if.state != c(nl.route.IFF).DOWN) .up //
                            else .down;
                        sock_parser.ctx.mode = //
                            if (sock_if.mode == c(nl._80211.IFTYPE).MONITOR) .monitor //
                            else .managed;
                        break :sockParser sock_parser;
                    }
                    var event_data: linux.epoll_event = .{
                        .events = epoll_events,
                        .data = .{ .fd = raw_sock },
                    };
                    try posix.epoll_ctl(
                        self._epoll_fd,
                        linux.EPOLL.CTL_DEL,
                        raw_sock,
                        &event_data,
                    );
                    _ = self.parsers.map.remove(raw_sock);
                    //log.debug("Stopped monitoring Raw Socket for '{s}'.", .{ sock_if.name });
                }
                try self.parsers.map.put(
                    core_ctx.alloc,
                    raw_sock,
                    .init(core_ctx.alloc, raw_sock, sock_if_entry.key_ptr.*),
                );
                var event_data: linux.epoll_event = .{
                    .events = epoll_events,
                    .data = .{ .fd = raw_sock },
                };
                try posix.epoll_ctl(
                    self._epoll_fd,
                    linux.EPOLL.CTL_ADD,
                    raw_sock,
                    &event_data,
                );
                //log.debug("Started monitoring Raw Socket for '{s}'.", .{ sock_if.name });
                break :sockParser self.parsers.map.getEntry(raw_sock).?.value_ptr;
            };
            if (//
                sock_parser.eth_list.items.len == 0 and //
                sock_parser.wifi_list.items.len == 0 //
            ) return;
            const eth_frames = try sock_parser.getEthFrames();
            defer {
                for (eth_frames) |frame| core_ctx.alloc.free(frame);
                core_ctx.alloc.free(eth_frames);
            }
            const wifi_frames = try sock_parser.getWifiFrames();
            defer {
                for (wifi_frames) |frame| core_ctx.alloc.free(frame);
                core_ctx.alloc.free(wifi_frames);
            }
            //log.debug("Handling {d} Eth and {d} WiFi Frames", .{ eth_frames.len, wifi_frames.len });
            defer self.handlers.mutex.unlock();
            var handler_iter = self.handlers.iterator();
            while (handler_iter.next()) |handler_entry| {
                const handler = handler_entry.value_ptr;
                handler.handleEth(eth_frames, sock_parser.ctx) catch {
                    log.warn("There was an issue handling an Ethernet Frame w/ the '{s}' Handler.", .{ handler_entry.key_ptr.* });
                };
                handler.handleWifi(wifi_frames, sock_parser.ctx) catch {
                    log.warn("There was an issue handling a Wifi Frame w/ the '{s}' Handler.", .{ handler_entry.key_ptr.* });
                };
                //log.debug("- {s} handled {d} Eth and {d} WiFi Frames", .{ handler_entry.key_ptr.*, eth_frames.len, wifi_frames.len });
            }
        }
        //log.debug("End: Socket Monitor Update", .{});
    }
};
