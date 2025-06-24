//! Asynchronous IO for Netlink

const std = @import("std");
const atomic = std.atomic;
const heap = std.heap;
const log = std.log.scoped(.nl_io);
const mem = std.mem;
const os = std.os;
const posix = std.posix;
const ArrayList = std.ArrayListUnmanaged;
const HashMap = std.AutoHashMapUnmanaged;
const Thread = std.Thread;

const nl = @import("../netlink.zig");
const parse = @import("parse.zig");
const utils = @import("../utils.zig");
const c = utils.toStruct;

/// Netlink Message Handler
pub const Handler = struct {
    /// Allocator used for all allocations within this Netlink Message Handler
    _alloc: mem.Allocator,
    /// Netlink Socket for this Event Loop
    _nl_sock: posix.socket_t,
    /// Receive Buffer 
    _recv_buf: [16_000]u8 = undefined,
    /// Response Data for corresponing Sequence IDs
    /// *Internal Use*
    _seq_resp_data: HashMap(u32, []const u8) = .empty,
    /// Callback Functions for corresponding Sequence IDs
    seq_cb_fns: HashMap(u32, *const fn([]const u8) anyerror!void) = .empty,
    /// Callback Function for Unsolicited Messages
    us_cb_fn: ?*const fn([]const u8) anyerror!void = null,
    /// Error Handling Function for errors on the Netlink Socket
    err_fn: ?*const fn(anyerror) void = null,

    /// Initialization Config
    pub const InitConfig = struct {
        /// Callback Functions for corresponding Sequence IDs
        seq_cb_fns: HashMap(u32, *const fn([]const u8) anyerror!void) = .empty,
        /// Callback Function for Unsolicited Messages
        us_cb_fn: ?*const fn([]const u8) anyerror!void = null,
        /// Error Handling Function for errors on the Netlink Socket
        err_fn: ?*const fn(anyerror) void = null,
    };

    /// Initialize a new Netlink Message Handler
    pub fn init(alloc: mem.Allocator, nl_sock: posix.socket_t, init_config: InitConfig) @This() {
        return .{
            ._alloc = alloc,
            ._nl_sock = nl_sock,
            .seq_cb_fns = init_config.seq_cb_fns,
            .us_cb_fn = init_config.us_cb_fn,
            .err_fn = init_config.err_fn,
        };
    }

    /// Deinitialize this Netlink Message Handler
    pub fn deinit(self: *@This()) void {
        posix.close(self._nl_sock);
        var seq_resp_iter = self._seq_resp_data.iterator();
        while (seq_resp_iter.next()) |resp_data| self._alloc.free(resp_data);
        self._seq_resp_data.deinit(self._alloc);
        self.seq_cb_fns.deinit(self._alloc);
    }

    /// Handle a Netlink Response
    pub fn handleResponse(self: *@This()) void {
        // Receive Netlink Messages from Socket
        const recv_len = posix.recv(self._nl_sock, self._recv_buf, 0) catch |err| self.handleError(err);
        const recv_buf = self._recv_buf[0..recv_len];
        // Iterate over each Netlink Message
        var msg_iter: nl.parse.Iterator(nl.MessageHeader, .{}) = .{ .bytes = recv_buf };
        while (msg_iter.next()) |msg| {
            const resp_data = respData: {
                var msg_buf = 
                    self._seq_resp_data.get(msg.hdr.seq) orelse
                    self._alloc.dupe(u8, &.{}) catch |err| {
                        self.handleError(err);
                        continue;
                    };
                var msg_list: ArrayList(u8) = .fromOwnedSlice(msg_buf);
                msg_list.append(self._alloc, mem.asBytes(&msg.hdr)) catch |err| {
                    self.handleError(err);
                    continue;
                };
                msg_list.append(self._alloc, msg.data) catch |err| {
                    self.handleError(err);
                    continue;
                };
                msg_buf = msg_list.toOwnedSlice(self._alloc);
                self._seq_resp_data.put(self._alloc, msg.hdr.seq, msg_buf) catch |err| {
                    self.handleError(err);
                    continue;
                };
                break :respData msg_buf;
            };
            const cbFn = self.seq_cb_fns(msg.hdr.seq) orelse self.handleUnsolicited;
            var done = false;
            defer if (done) {
                self._alloc.free(resp_data);
                _ = self._seq_resp_data.remove(msg.hdr.seq);
            };
            // Check Netlink Message "Type"
            switch (msg.hdr.type) {
                c(nl.NLMSG).NOOP => done = true,
                c(nl.NLMSG).ERROR => {
                    const nl_err = mem.bytesAsValue(nl.ErrorHeader, msg.data[0..@sizeOf(nl.ErrorHeader)]);
                    const msg_err: ?anyerror = switch (posix.errno(@as(isize, @intCast(nl_err.err)))) {
                        .SUCCESS => null,
                        .BUSY => error.BUSY,
                        .NOLINK => error.NOLINK,
                        .ALREADY => error.ALREADY,
                        .EXIST => error.EXIST,
                        .ADDRNOTAVAIL => error.ADDRNOTAVAIL,
                        .SRCH => error.SRCH,
                        .NETUNREACH => error.NETUNREACH,
                        .INPROGRESS => error.INPROGRESS,
                        .NODEV => error.NODEV,
                        else => error.OSError,
                    };
                    if (msg_err) |err| self.handleError(err)
                    else cbFn(resp_data) catch |err| self.handleError(err);
                    done = true;
                },
                c(nl.NLMSG).DONE => {
                    cbFn(resp_data) catch |err| self.handleError(err);
                    done = true;
                },
                c(nl.NLMSG).OVERRUN => {
                    self.handleError(error.Overrun);
                    done = true;
                },
                else => {},
            }
            if (done) continue;
            // Check Netlink Message Flags
            done = (msg.hdr.flags & c(nl.NLM_F).MULTI) == 0;
        }
    }

    /// Handle an Error with this Netlink Message Handler
    pub fn handleError(self: *@This(), err: anyerror) void {
        if (self.err_fn) |errFn| return errFn(err);
        log.debug("An Error occured with the Handler: {e}", .{ err });
    }

    /// Handle an Unsolicited Netlink Message
    fn handleUnsolicited(self: *@This(), buf: []const u8) !void {
        defer self._alloc.free(buf);
        if (self.us_cb_fn) |cbFn| return cbFn(buf);
        log.debug("Discarded Unsolicited Netlink Message", .{});
    }
};

/// Asynchronous Netlink Event Loop for one or more Netlink Message Handler
pub const Loop = struct {
    /// Thread on which this Loop will run
    /// *Internal Use*
    _thread: Thread = undefined,
    /// Active State of the Loop
    /// *Internal Use*
    _active: atomic.Value(bool) = .init(false),
    /// Netlink Messsage Handlers to loop through
    /// *Internal Use*
    _handlers: HashMap(posix.socket_t, Handler) = .empty,
    /// Epoll File Descriptor
    /// *Internal Use*
    _epoll_fd: posix.socket_t,
    /// Error Handling Function
    err_fn: ?*const fn(*@This(), anyerror) void = null,
    /// Diagnostics Data
    /// This is not implemented by default, but it's made available for users
    diag: ?*anyopaque = null,

    /// Initialization Config
    pub const InitConfig = struct {
        /// Error Handling Function
        err_fn: ?*const fn(*@This(), anyerror) void = null,
        /// Diagnostics Data
        /// This is not implemented by default, but it's made available for users
        diag: ?*anyopaque = null,
    };

    /// Initialize a new Event Loop
    pub fn init(init_config: InitConfig) @This() {
        return .{
            .err_fn = init_config.err_fn,
            .diag = init_config.diag,
        };
    }

    /// Deinitialize this Event Loop and any Handlers associated to it
    pub fn deinit(self: *@This(), alloc: mem.Allocator) void {
        var handlers_iter = self._handlers.iterator();
        while (handlers_iter.next()) |handler| handler.deinit();
        self._handlers.deinit(alloc);
    }

    /// Start the Event Loop on its own Thread
    pub fn start(self: *@This(), alloc: mem.Allocator, active: atomic.Value(bool)) !void {
        self._active.store(true, .monotonic);
        self._epoll = @intCast(try posix.epoll_create1(0));
        self._thread = .spawn(
            .{ .alloc = alloc },
            startThread,
            .{
                self,
                active,
            },
        );
    }

    /// Start the Event Loop Thread
    fn startThread(self: *@This(), active: atomic.Value(bool)) void {
        var events: [64]posix.system.epoll_event = undefined;
        while (active.load(.acquire) and self._active.load(.acquire)) {
            const event_count = posix.epoll_wait(self._epoll_fd, events[0..], -1);
            for (events[0..event_count]) |event| {
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

    /// Handle an Error
    fn handleError(self: *@This(), err: anyerror) void {
        if (self.err_fn) |errFn| return errFn(self, err);
        log.debug("The Netlink Event Loop caught an Error: {e}", .{ err });
    }

    /// Add a new Handler to the Event Loop
    pub fn addHandler(self: *@This(), alloc: mem.Allocator, handler: Handler) !void {
        try self._handlers.put(alloc, handler._nl_sock, handler);
        const event: posix.system.epoll_event = .{
            .events = os.linux.EPOLL.IN,
            .data = .{ .fd = handler._nl_sock },
        };
        try posix.epoll_ctl(
            self._epoll_fd, 
            os.linux.EPOLL.CTL_ADD, 
            handler._nl_sock,
            &event,
        );
    }
};
