//! Packet Captures

const std = @import("std");
const atomic = std.atomic;
const log = std.log.scoped(.pcap);
const mem = std.mem;
const posix = std.posix;
const Thread = std.Thread;

const netdata = @import("../netdata.zig");
const pcap = netdata.pcap;


/// Capture Event Loop
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

    /// Initialize a new Event Loop
    pub fn init() !@This() {
        return .{
            ._epoll_fd = @intCast(try posix.epoll_create1(0)),
        };
    }

    /// Deinitialize this Event Loop and any Handlers associated to it
    pub fn deinit(self: *@This(), alloc: mem.Allocator) void {
        var handlers_iter = self._handlers.iterator();
        while (handlers_iter.next()) |handler| handler.value_ptr.*.deinit();
        self._handlers.deinit(alloc);
    }

    /// Start the Event Loop on its own Thread
    pub fn start(self: *@This(), alloc: mem.Allocator, active: *atomic.Value(bool)) !void {
        if (self._active.load(.acquire)) return;
        self._active.store(true, .monotonic);
        self._thread = try .spawn(
            .{ .allocator = alloc },
            startThread,
            .{
                self,
                active,
            },
        );
    }

    /// Start the Event Loop Thread
    fn startThread(self: *@This(), active: *atomic.Value(bool)) void {
        var events: [64]posix.system.epoll_event = undefined;
        while (active.load(.acquire) and self._active.load(.acquire)) {
            const event_count = posix.epoll_wait(self._epoll_fd, events[0..], -1);
            for (events[0..event_count]) |event| {
                if (!active.load(.acquire) or !self._active.load(.acquire)) break;
                //log.debug("Received event on: {d}", .{ event.data.fd });
                const handler = self._handlers.get(event.data.fd) orelse continue;
                handler.handleResponse();
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
};
