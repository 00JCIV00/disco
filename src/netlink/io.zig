//! Asynchronous IO for Netlink

const std = @import("std");
const atomic = std.atomic;
const heap = std.heap;
const log = std.log.scoped(.nl_io);
const mem = std.mem;
const os = std.os;
const posix = std.posix;
const time = std.time;
const ArrayList = std.ArrayListUnmanaged;
const HashMap = std.AutoHashMapUnmanaged;
const Thread = std.Thread;

const nl = @import("../netlink.zig");
const parse = @import("parse.zig");
const utils = @import("../utils.zig");
const c = utils.toStruct;
const ThreadHashMap = utils.ThreadHashMap;

/// Netlink Message Handler
pub const Handler = struct {
    /// Response Data
    pub const Response = union(enum) {
        pub const Timeout = struct {
            timer: time.Timer,
            timeout: u32 = 100,

            pub fn check(self: *@This()) bool {
                const now: u64 = self.timer.read();
                const timeout: u64 = self.timeout * time.ns_per_ms;
                return @divFloor(now, time.ns_per_ms) >= timeout;
            }
        };

        timeout: Timeout,
        working: []u8,
        ready: anyerror![]const u8,
    };

    /// Initialization Config
    pub const InitConfig = struct {
        /// Callback Function for Unsolicited Messages
        us_cb_fn: ?*const fn([]const u8) anyerror!void = null,
        /// Error Handling Function for errors on the Netlink Socket
        err_fn: ?*const fn(anyerror) void = null,
    };

    /// Allocator used for all allocations within this Netlink Message Handler
    /// *Internal Use*
    _alloc: mem.Allocator,
    /// Receive Buffer 
    /// *Internal Use*
    _recv_buf: [16_000]u8 = undefined,
    /// Responses for corresponing Sequence IDs
    /// *Internal Use*
    _seq_responses: ThreadHashMap(u32, Response) = .empty,
    /// Epoll Event
    epoll_event: posix.system.epoll_event,
    /// Netlink Socket for this Event Loop
    /// *Read Only*
    nl_sock: posix.socket_t,
    /// Callback Function for Unsolicited Messages
    us_cb_fn: ?*const fn([]const u8) anyerror!void = null,
    /// Error Handling Function for errors on the Netlink Socket
    err_fn: ?*const fn(anyerror) void = null,

    /// Initialize a new Netlink Message Handler
    pub fn init(alloc: mem.Allocator, nl_sock: posix.socket_t, init_config: InitConfig) @This() {
        return .{
            ._alloc = alloc,
            .nl_sock = nl_sock,
            .us_cb_fn = init_config.us_cb_fn,
            .err_fn = init_config.err_fn,
            .epoll_event = .{
                .events = os.linux.EPOLL.IN,
                .data = .{ .fd = nl_sock },
            },
        };
    }

    /// Deinitialize this Netlink Message Handler
    pub fn deinit(self: *@This()) void {
        posix.close(self.nl_sock);
        var seq_resp_iter = self._seq_responses.iterator();
        while (seq_resp_iter.next()) |resp_data| self._alloc.free(resp_data);
        self._seq_responses.deinit(self._alloc);
        self.seq_cb_fns.deinit(self._alloc);
    }

    /// Track a specific Request
    pub fn trackRequest(self: *@This(), req_ctx: nl.RequestContext) !void {
        try self._seq_responses.put(
            self._alloc,
            req_ctx.seq_id,
            .{
                .timeout = .{
                    .timeout = req_ctx.timeout,
                    .timer = try .start(),
                },
            },
        );
        //log.debug("Tracking Seq ID: {d}", .{ req_ctx.seq_id });
    }

    /// Check for a Response for a specific Request
    pub fn checkResponse(self: *@This(), seq_id: u32) bool {
        self._seq_responses.mutex.lock();
        defer self._seq_responses.mutex.unlock();
        const resp_entry = self._seq_responses.map.getEntry(seq_id) orelse return false;
        const response = resp_entry.value_ptr;
        //log.debug("{d} - {}: {s}", .{ seq_id, @intFromPtr(response), @tagName(response.*) });
        return switch (response.*) {
            .timeout => |*timeout| timeout.check(),
            .working => false,
            .ready => true,
        };
    }

    /// Get a Response for a specific Request
    pub fn getResponse(self: *@This(), seq_id: u32) ?anyerror![]const u8 {
        self._seq_responses.mutex.lock();
        defer self._seq_responses.mutex.unlock();
        const resp_entry = self._seq_responses.map.getEntry(seq_id) orelse return null;
        const response = resp_entry.value_ptr;
        var timeout_state: Response = .{ .ready = error.Timeout };
        return resp_state: switch (response.*) {
            .timeout => |*timeout| timeout: {
                if (!timeout.check()) break :timeout null;
                continue :resp_state timeout_state;
            },
            .working => null,
            .ready => |ready| ready: {
                defer _ = self._seq_responses.map.remove(seq_id);
                break :ready ready;
            },
        };
    }

    /// Handle a Netlink Response
    pub fn handleResponse(self: *@This()) void {
        // Receive Netlink Messages from Socket
        const recv_len = posix.recv(self.nl_sock, self._recv_buf[0..], 0) catch |err| return self.handleError(err);
        const recv_buf = self._recv_buf[0..recv_len];
        // Iterate over each Netlink Message
        var msg_iter: nl.parse.Iterator(nl.MessageHeader, .{}) = .{ .bytes = recv_buf };
        while (msg_iter.next()) |msg| {
            //log.debug("Handling Response for Seq ID: {d}", .{ msg.hdr.seq });
            const response = respCtx: {
                if (self._seq_responses.getEntry(msg.hdr.seq)) |resp_entry| break :respCtx resp_entry.value_ptr;
                self._seq_responses.mutex.unlock();
                log.debug("Seq ID {d} is untracked. Tracking now.", .{ msg.hdr.seq });
                self._seq_responses.put(
                    self._alloc,
                    msg.hdr.seq,
                    .{
                        .timeout = .{
                            .timer = time.Timer.start() catch |err| {
                                self.handleError(err);
                                continue;
                            },
                        },
                    },
                ) catch |err| {
                    self.handleError(err);
                    continue;
                };
                const resp_entry = self._seq_responses.getEntry(msg.hdr.seq).?;
                break :respCtx resp_entry.value_ptr;
            };
            defer self._seq_responses.mutex.unlock();
            const resp_bytes = respData: {
                var msg_buf = switch (response.*) {
                    .working => |buf| buf,
                    else => self._alloc.dupe(u8, &.{}) catch |err| {
                        self.handleError(err);
                        continue;
                    },
                };
                var msg_list: ArrayList(u8) = .fromOwnedSlice(msg_buf);
                msg_list.appendSlice(self._alloc, mem.asBytes(&msg.hdr)) catch |err| {
                    self.handleError(err);
                    continue;
                };
                msg_list.appendSlice(self._alloc, msg.data) catch |err| {
                    self.handleError(err);
                    continue;
                };
                msg_buf = msg_list.toOwnedSlice(self._alloc) catch |err| {
                    self.handleError(err);
                    continue;
                };
                break :respData msg_buf;
            };
            response.* = .{ .working = resp_bytes };
            // Check Netlink Message "Type"
            const resp_data: anyerror![]const u8 = switch (msg.hdr.type) {
                c(nl.NLMSG).ERROR => nlError: {
                    const nl_err = mem.bytesAsValue(nl.ErrorHeader, msg.data[0..@sizeOf(nl.ErrorHeader)]);
                    break :nlError switch (posix.errno(@as(isize, @intCast(nl_err.err)))) {
                        .SUCCESS => resp_bytes,
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
                },
                c(nl.NLMSG).OVERRUN => error.Overrun,
                c(nl.NLMSG).NOOP,
                c(nl.NLMSG).DONE,
                => resp_bytes,
                else => other: {
                    const is_multi = (msg.hdr.flags & c(nl.NLM_F).MULTI) != 0;
                    if (is_multi) continue else break :other resp_bytes;
                },
            };
            response.* = .{ .ready = resp_data };
            //if (resp_data) |resp|
            //    log.debug("Finished Response for Seq ID: {d}, Len: {d}B", .{ msg.hdr.seq, resp.len })
            //else |err|
            //    log.debug("Errored Response for Seq ID: {d}, Err: {s}", .{ msg.hdr.seq, @errorName(err) });
        }
    }

    /// Handle an Error with this Netlink Message Handler
    pub fn handleError(self: *@This(), err: anyerror) void {
        if (self.err_fn) |errFn| return errFn(err);
        log.debug("An Error occured with the Handler: {s}", .{ @errorName(err) });
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
    _handlers: HashMap(posix.socket_t, *Handler) = .empty,
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
        err_fn: ?*const fn(*Loop, anyerror) void = null,
        /// Diagnostics Data
        /// This is not implemented by default, but it's made available for users
        diag: ?*anyopaque = null,
    };

    /// Initialize a new Event Loop
    pub fn init(init_config: InitConfig) @This() {
        return .{
            .err_fn = init_config.err_fn,
            .diag = init_config.diag,
            ._epoll_fd = undefined,
        };
    }

    /// Deinitialize this Event Loop and any Handlers associated to it
    pub fn deinit(self: *@This(), alloc: mem.Allocator) void {
        var handlers_iter = self._handlers.iterator();
        while (handlers_iter.next()) |handler| handler.deinit();
        self._handlers.deinit(alloc);
    }

    /// Start the Event Loop on its own Thread
    pub fn start(self: *@This(), alloc: mem.Allocator, active: *atomic.Value(bool)) !void {
        self._active.store(true, .monotonic);
        self._epoll_fd = @intCast(try posix.epoll_create1(0));
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

    /// Handle an Error
    fn handleError(self: *@This(), err: anyerror) void {
        if (self.err_fn) |errFn| return errFn(self, err);
        log.debug("The Netlink Event Loop caught an Error: {s}", .{ @errorName(err) });
    }

    /// Add a new Handler to the Event Loop
    pub fn addHandler(self: *@This(), alloc: mem.Allocator, handler: *Handler) !void {
        try self._handlers.put(alloc, handler.nl_sock, handler);
        try posix.epoll_ctl(
            self._epoll_fd,
            os.linux.EPOLL.CTL_ADD,
            handler.nl_sock,
            &handler.epoll_event,
        );
    }
};
