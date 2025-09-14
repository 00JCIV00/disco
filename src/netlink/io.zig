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
const HexF = utils.HexFormatter;
const ThreadHashMap = utils.ThreadHashMap;

/// Netlink Message Handler
pub const Handler = struct {
    /// Response Data
    pub const Response = union(enum) {
        pub const Timeout = struct {
            timer: time.Timer,
            timeout: u32 = 1_000,

            pub fn check(self: *@This()) bool {
                const now: u64 = self.timer.read();
                //log.info("Now: {d}ms, Timeout: {d}ms", .{ @divFloor(now, time.ns_per_ms), self.timeout });
                return @divFloor(now, time.ns_per_ms) >= self.timeout;
            }
        };

        timeout: Timeout,
        working: []u8,
        ready: anyerror![]const u8,

        pub fn deinit(self: *@This(), alloc: mem.Allocator) void {
            switch (self.*) {
                .working => |data| alloc.free(data),
                .ready => |resp| if (resp) |data| alloc.free(data) else |_| {},
                else => {},
            }
        }
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
    /// Responses/Messages from corresponding Commands
    /// *Internal Use*
    _cmd_response_maps: ThreadHashMap(u16, ThreadHashMap(u32, Response)) = .empty,
    /// Epoll Event
    epoll_event: posix.system.epoll_event,
    /// Netlink Socket Protocol
    /// *Read Only*
    nl_sock_proto: u32,
    /// Netlink Socket for this Handler
    /// *Read Only*
    nl_sock: posix.socket_t,
    /// Callback Function for Unsolicited Messages
    us_cb_fn: ?*const fn([]const u8) anyerror!void = null,
    /// Error Handling Function for errors on the Netlink Socket
    err_fn: ?*const fn(anyerror) void = null,

    /// Initialize a new Netlink Message Handler
    pub fn init(alloc: mem.Allocator, nl_sock_proto: u32, init_config: InitConfig) !@This() {
        const nl_sock = try nl.initSock(.{ .kind = nl_sock_proto });
        return .{
            ._alloc = alloc,
            .nl_sock_proto = nl_sock_proto,
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
        while (seq_resp_iter.next()) |resp| resp.value_ptr.deinit(self._alloc);
        self._seq_responses.mutex.unlock();
        self._seq_responses.deinit(self._alloc);
        //log.debug("Total Command Response Maps: {d}", .{ self._cmd_response_maps.count() });
        var cmd_resp_map_iter = self._cmd_response_maps.iterator();
        while (cmd_resp_map_iter.next()) |resp_map_entry| {
            const resp_map = resp_map_entry.value_ptr;
            var cmd_resp_iter = resp_map.iterator();
            while (cmd_resp_iter.next()) |resp| resp.value_ptr.deinit(self._alloc);
            resp_map.mutex.unlock();
            resp_map.deinit(self._alloc);
        }
        self._cmd_response_maps.mutex.unlock();
        self._cmd_response_maps.deinit(self._alloc);
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

    /// Track a specific Command
    pub fn trackCommand(self: *@This(), cmd: u16) !void {
        if (self._cmd_response_maps.get(cmd)) |_| return;
        try self._cmd_response_maps.put(self._alloc, cmd, .empty);
    }

    /// Check for a Response for a specific Request (`seq_id`).
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

    /// Check for Responses/Messages from a specific Command (`cmd`).
    pub fn checkCmdResponses(self: *@This(), cmd: u16) bool {
        defer self._cmd_response_maps.mutex.unlock();
        const map_entry = self._cmd_response_maps.getEntry(cmd) orelse return false;
        const map = map_entry.value_ptr;
        defer map.mutex.unlock();
        var map_iter = map.iterator();
        while (map_iter.next()) |resp| {
            if (resp.value_ptr.* == .ready) return true;
        }
        return false;
    }

    /// Get a Response for a specific Request (`seq_id`).
    /// Caller owns memory for non-null, non-errored responses.
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

    /// Get Responses/Messages for a specific Command (`cmd`).
    /// Caller owns memory for non-errored responses and the slice containing them.
    pub fn getCmdResponses(self: *@This(), cmd: u16) ![]const anyerror![]const u8 {
        defer self._cmd_response_maps.mutex.unlock();
        const cmd_map_entry = self._cmd_response_maps.getEntry(cmd) orelse return &.{};
        //defer self._cmd_response_maps.map.remove(cmd_map_entry.key_ptr.*);
        const cmd_resp_map = cmd_map_entry.value_ptr;
        defer cmd_resp_map.mutex.unlock();
        var cmd_resp_iter = cmd_resp_map.iterator();
        var resp_list: ArrayList(anyerror![]const u8) = .empty;
        while (cmd_resp_iter.next()) |resp_entry| {
            const response = resp_entry.value_ptr;
            var timeout_state: Response = .{ .ready = error.Timeout };
            resp_state: switch (response.*) {
                .timeout => |*timeout| {
                    if (!timeout.check()) continue;
                    continue :resp_state timeout_state;
                },
                .working => continue,
                .ready => |ready| {
                    defer _ = cmd_resp_map.map.remove(resp_entry.key_ptr.*);
                    try resp_list.append(self._alloc, ready);
                },
            }
        }
        //log.debug("Total Responses: {d}", .{ resp_list.items.len });
        return try resp_list.toOwnedSlice(self._alloc);
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
                defer self._seq_responses.mutex.unlock();
                if (self._seq_responses.getEntry(msg.hdr.seq)) |resp_entry| break :respCtx resp_entry.value_ptr;
                const msg_cmd = self.detectCmd(msg.hdr, msg.data) catch |err| {
                    self.handleError(err);
                    continue;
                };
                defer self._cmd_response_maps.mutex.unlock();
                const cmd_resp_map_entry = self._cmd_response_maps.getEntry(msg_cmd) orelse continue;
                const cmd_resp_map = cmd_resp_map_entry.value_ptr;
                cmd_resp_map.mutex.lock();
                defer cmd_resp_map.mutex.unlock();
                const resp_entry = cmd_resp_map.map.getEntry(msg.hdr.seq) orelse respEntry: {
                    cmd_resp_map.map.put(
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
                    //log.debug("MAP COUNT: {d} | CMD: {d}", .{ cmd_resp_map.map.count(), msg_cmd });
                    break :respEntry cmd_resp_map.map.getEntry(msg.hdr.seq).?;
                };
                break :respCtx resp_entry.value_ptr;
            };
            if (response.* == .ready) continue;
            const resp_bytes = respData: {
                var msg_buf = switch (response.*) {
                    .working => |buf| buf,
                    else => self._alloc.dupe(u8, &.{}) catch |err| {
                        self.handleError(err);
                        continue;
                    },
                };
                var valid: bool = false;
                var msg_list: ArrayList(u8) = .fromOwnedSlice(msg_buf);
                defer if (!valid) msg_list.deinit(self._alloc);
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
                valid = true;
                break :respData msg_buf;
            };
            response.* = .{ .working = resp_bytes };
            // Check Netlink Message "Type"
            const resp_data: anyerror![]const u8 = switch (msg.hdr.type) {
                c(nl.NLMSG).ERROR => nlError: {
                    const nl_err = mem.bytesAsValue(nl.ErrorHeader, msg.data[0..@sizeOf(nl.ErrorHeader)]);
                    var valid: bool = false;
                    defer if (!valid) self._alloc.free(resp_bytes);
                    break :nlError switch (posix.errno(@as(isize, @intCast(nl_err.err)))) {
                        .SUCCESS => success: {
                            valid = true;
                            break :success resp_bytes;
                        },
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
                c(nl.NLMSG).OVERRUN => overrun: {
                    defer self._alloc.free(resp_bytes);
                    break :overrun error.Overrun;
                },
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
        log.debug("An Error occured with the Handler: {s}", .{ @errorName(err) });
        if (self.err_fn) |errFn| return errFn(err);
    }

    /// Detect the Command 'Type' of Netlink Message using the provided Netlink Message Header (`hdr`) and `data`.
    fn detectCmd(self: *const @This(), hdr: nl.MessageHeader, data: []const u8) !u16 {
        if (self.nl_sock_proto != nl.NETLINK.GENERIC)
            return hdr.type;
        const generic_hdr_len = @sizeOf(nl.generic.Header);
        if (data.len < generic_hdr_len)
            return error.IncompleteGenericHeader;
        const fam_hdr = mem.bytesToValue(nl.generic.Header, data[0..generic_hdr_len]);
        return fam_hdr.cmd;
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
    pub fn init(init_config: InitConfig) !@This() {
        return .{
            .err_fn = init_config.err_fn,
            .diag = init_config.diag,
            //._epoll_fd = undefined,
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
        //self._epoll_fd = @intCast(try posix.epoll_create1(0));
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
