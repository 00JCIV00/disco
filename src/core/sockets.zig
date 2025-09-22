//! Raw Socket Data from Core Interfaces

const std = @import("std");
const atomic = std.atomic;
const linux = std.os.linux;
const log = std.log.scoped(.sockets);
const mem = std.mem;
const posix = std.posix;
const time = std.time;
const Io = std.Io;
const Thread = std.Thread;

const core = @import("../core.zig");
const nl = @import("../netlink.zig");
const utils = @import("../utils.zig");
const c = utils.toStruct;
const ThreadHashMap = utils.ThreadHashMap;


/// Reader
pub const Reader = struct {
    /// The Posix Socket from which data is read
    sock: posix.socket_t,
    /// The MAC of the corresponding Interface for this Reader
    if_mac: [6]u8,
    /// The underlying `Io.Reader` Interface
    io_reader: Io.Reader,
    /// Reader State
    state: enum { up, down } = .down,


    /// Initialize a new Reader
    pub fn init(sock: posix.socket_t, if_mac: [6]u8) @This() {
        return .{
            .sock = sock,
            .if_mac = if_mac,
            .io_reader = .{
                .vtable = &.{
                    .stream = stream,
                },
                //.buffer = buffer,
                .buffer = &.{},
                .seek = 0,
                .end = 0,
            },
        };
    }

    /// Satisfy the `Io.Reader` Interface.
    fn stream(self: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        const r: *@This() = @alignCast(@fieldParentPtr("io_reader", self));
        if (r.state == .down) return 0;
        log.debug("Reading Data...", .{});
        const dest = limit.slice(try w.writableSliceGreedy(1));
        const n = posix.read(r.sock, dest[0..]) catch |err| {
            log.debug("Read Error: {t}", .{ err });
            return error.ReadFailed;
        };
        log.debug("Read {d} Bytes!", .{ n });
        w.advance(n);
        return n;
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
    /// Readers for each Interface
    readers: ThreadHashMap(posix.socket_t, Reader) = .empty,


    /// Initialize a new Event Loop
    pub fn init() !@This() {
        return .{
            ._epoll_fd = @intCast(try posix.epoll_create1(0)),
        };
    }

    /// Deinitialize this Event Loop and any Handlers associated to it
    pub fn deinit(self: *@This(), alloc: mem.Allocator) void {
        self.readers.deinit(alloc);
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
            self.readers.mutex.lock();
            defer self.readers.mutex.unlock();
            for (events[0..event_count]) |event| {
                if (!core_ctx.active.load(.acquire) or !self._active.load(.acquire)) break;
                //log.debug("Received event on: {d} ({d})", .{ event.data.fd, event.events });
                if (event.events & linux.EPOLL.ERR != 0) {
                    var err_buf: [1]u8 = .{ 0 };
                    posix.getsockopt(event.data.fd, linux.SOL.SOCKET, linux.SO.ERROR, err_buf[0..]) catch |err| //
                        log.err("Could not clear Socket Error on: {t}.", .{ err });
                    log.debug("Continuing: SOCKET THREAD", .{});
                    continue;
                }
                if (event.events & linux.EPOLL.IN != 0) {
                    const reader_entry = self.readers.map.getEntry(event.data.fd) orelse continue;
                    const reader = reader_entry.value_ptr;
                    log.debug("Reading: SOCKET THREAD", .{});
                    const frames_buf = reader.io_reader.readAlloc(core_ctx.alloc, 16_000) catch |err| {
                        if (err == error.OutOfMemory) @panic("OOM");
                        if (err == error.Unexpected) {
                            reader.state = .down;
                            //continue;
                        }
                        log.err("There was an error while processing a Raw Socket: {t}", .{ err });
                        continue;
                    };
                    defer core_ctx.alloc.free(frames_buf);
                    log.debug("Read {d}B Frame Bytes.", .{ frames_buf.len });
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
        self.readers.mutex.lock();
        defer self.readers.mutex.unlock();
        defer core_ctx.if_ctx.interfaces.mutex.unlock();
        var if_iter = core_ctx.if_ctx.interfaces.iterator();
        while (if_iter.next()) |sock_if_entry| {
            const sock_if = sock_if_entry.value_ptr;
            //log.debug("'{s}': Socket Monitor Update", .{ sock_if.name });
            const raw_sock = sock_if.raw_sock orelse continue;
            if (self.readers.map.getEntry(raw_sock)) |sock_reader_entry| {
                const sock_reader = sock_reader_entry.value_ptr;
                if (sock_reader.sock == raw_sock) {
                    sock_reader.state = //
                        if (sock_if.state != c(nl.route.IFF).DOWN) .up //
                        else .down;
                    continue;
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
                _ = self.readers.map.remove(raw_sock);
                log.debug("Stopped monitoring Raw Socket for '{s}'.", .{ sock_if.name });
            }
            try self.readers.map.put(core_ctx.alloc, raw_sock, .init(raw_sock, sock_if_entry.key_ptr.*));
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
            log.debug("Started monitoring Raw Socket for '{s}'.", .{ sock_if.name });
        }
        //log.debug("End: Socket Monitor Update", .{});
    }
};
