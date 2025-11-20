//! Requests to DisCo Core

const std = @import("std");
const atomic = std.atomic;
const log = std.log;
const math = std.math;
const mem = std.mem;
const posix = std.posix;
const HashMap = std.HashMapUnmanaged;
const Io = std.Io;
const ArrayList = std.ArrayList;
const Thread = std.Thread;

const core = @import("../core.zig");
const nl = @import("../netlink.zig");
const utils = @import("../utils.zig");
const CSlice = utils.CSlice;
const ThreadArrayList = utils.ThreadArrayList;
const ThreadHashMap = utils.ThreadHashMap;


/// Core Modules to request from
pub const Module = union(enum) {
    core,
    interfaces,
    networks,
    connections,
    sockets,
    captures,
    serve,
};

/// Request
pub const Request = union(enum) {
    core,
    interfaces: union(enum) {
        get: [6]u8,
        get_all,
        mod: struct { mod_if: [6]u8, mod_field: core.interfaces.Interface.ModifyField },
    },
    networks,
    connections,
    sockets,
    captures,
    serve,
};

/// Response
pub const Response = union(enum) {
    ack,
    interfaces: union(enum) {
        single: ?core.interfaces.Interface.Simple,
        list: []const core.interfaces.Interface.Simple,
    },
    networks,
    connections,
};

/// Errors
pub const Error = error {
    InvalidRequest,
    Timeout,
    ProcessingFailure,
};

/// Request/Response Handler
pub const Handler = struct {
    aggregator: *Aggregator,

    /// Send a Request to the Aggregator
    pub fn sendRequest(self: *@This(), core_ctx: *core.Core, req: Request) !usize {
        return self.aggregator.push(core_ctx, req);
    }

    /// Check for a Response from the Aggregator
    pub fn checkResponse(self: *@This()) ?Response {
        return self.aggregator.get(usize);
    }
};

/// Asynchronous Aggregator for Core Requests
pub const Aggregator = struct {
    /// Current Request ID
    req_id: atomic.Value(usize) = .init(1),
    /// Requests Map
    req_map: ThreadHashMap(usize, Request) = .empty,
    /// Response Map
    resp_map: ThreadHashMap(usize, Error!Response) = .empty,

    /// Deinitialize this Aggregator
    pub fn deinit(self: *@This(), alloc: mem.Allocator) void {
        self.req_map.deinit(alloc);
        self.resp_map.deinit(alloc);
    }

    /// Push a Request to the queue (`req_map`).
    pub fn push(self: *@This(), req: Request) !usize {
        const core_ctx: *core.Core = @fieldParentPtr("req_aggregator", self);
        const id = self.getReqID();
        try self.req_map.put(core_ctx.alloc, id, req);
        return id;
    }

    /// Get a Response to a corresponding Request ID (`req_id`).
    pub fn get(self: *@This(), req_id: usize) ?Error!Response {
        const resp = self.resp_map.get(req_id) orelse return null;
        defer _ = self.resp_map.remove(req_id);
        return resp;
    }

    /// Process any queued requests
    pub fn process(self: *@This()) !void {
        const core_ctx: *core.Core = @fieldParentPtr("req_aggregator", self);
        self.req_map.mutex.lock();
        var reqs = self.req_map.map.move();
        defer reqs.deinit(core_ctx.alloc);
        self.req_map.mutex.unlock();
        var reqs_iter = reqs.iterator();
        while (reqs_iter.next()) |req| {
            switch (req.value_ptr.*) {
                .interfaces => |if_req| {
                    core_ctx.if_ctx.interfaces.mutex.lock();
                    defer core_ctx.if_ctx.interfaces.mutex.unlock();
                    switch (if_req) {
                        .get => |if_mac| {
                            const resp_if = core_ctx.if_ctx.interfaces.get(if_mac);
                            _ = resp_if;
                        },
                        .get_all => {
                            var if_list: ArrayList(core.interfaces.Interface.Simple) = .empty;
                            var if_iter = core_ctx.if_ctx.interfaces.map.valueIterator();
                            while (if_iter.next()) |next_if| {
                                const resp_if: core.interfaces.Interface.Simple = .from(core_ctx.alloc, next_if.*);
                                try if_list.append(core_ctx.alloc, resp_if);
                            }
                            const resp_ifs = try if_list.toOwnedSlice(core_ctx.alloc);
                            try self.resp_map.put(core_ctx.alloc, req.key_ptr.*, .{ .interfaces = .{ .list = resp_ifs } });
                            log.debug("Handled Interfaces Request: {d}", .{ req.key_ptr.* });
                        },
                        else => {},
                    }
                },
                else => |tag| log.err("Unimplemented: {t}", .{ tag }),
            }
        }
    }

    /// Get the next Request ID
    fn getReqID(self: *@This()) usize {
        defer if (self.req_id.load(.acquire) >= math.maxInt(usize) - 1)
            self.req_id.store(1, .monotonic);
        return self.req_id.fetchAdd(1, .acquire);
    }
};
