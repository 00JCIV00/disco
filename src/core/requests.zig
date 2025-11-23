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
const HexF = utils.HexFormatter;
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
        get: InterfaceID,
        get_all,
        mod: struct { mod_if: [6]u8, mod_field: core.interfaces.Interface.ModifyField },
        usage: struct {
            if_id: InterfaceID,
            state: enum { activate, deactivate }
        },

        pub const InterfaceID = union(enum) {
            mac: [6]u8,
            name: []const u8,

            pub fn deinit(self: *const @This(), alloc: mem.Allocator) void {
                switch (self.*) {
                    .name => |name| alloc.free(name),
                    else => {},
                }
            }
        };

        pub fn deinit(self: *const @This(), alloc: mem.Allocator) void {
            switch (self.*) {
                .get => |get_id| get_id.deinit(alloc),
                .usage => |usage_req| usage_req.if_id.deinit(alloc),
                else => {},
            }
        }
    },
    networks: union(enum) {
        get: core.networks.Network.ID,
        get_all,

        pub fn deinit(self: *const @This(), alloc: mem.Allocator) void {
            switch (self.*) {
                .get => |id| id.deinit(alloc),
                else => {},
            }
        }
    },
    connections: union(enum) {
        add: core.connections.Config,
        enable: core.networks.Network.ID,
        disable: core.networks.Network.ID,

        pub fn deinit(self: *const @This(), alloc: mem.Allocator) void {
            switch (self.*) {
                .enable,
                .disable,
                    => |id| id.deinit(alloc),
                else => {},
            }
        }
    },
    sockets,
    captures,
    serve,

    /// Deinitialize any Allocations in this Request.
    pub fn deinit(self: *const @This(), alloc: mem.Allocator) void {
        switch (self.*) {
            .interfaces => |if_req| if_req.deinit(alloc),
            .networks => |net_req| net_req.deinit(alloc),
            .connections => |conn_req| conn_req.deinit(alloc),
            else => {},
        }
    }
};

/// Response
pub const Response = union(enum) {
    ack,
    interfaces: union(enum) {
        single: ?core.interfaces.Interface.Simple,
        list: []const core.interfaces.Interface.Simple,

        pub fn deinit(self: *const @This(), alloc: mem.Allocator) void {
            switch (self.*) {
                .single => |s_if| single: {
                    const resp_if = s_if orelse break :single;
                    resp_if.deinit(alloc);
                },
                .list => |if_list| {
                    for (if_list) |resp_if| //
                        resp_if.deinit(alloc);
                    alloc.free(if_list);
                }
            }
        }
    },
    networks: union(enum) {
        single: ?core.networks.Network.Simple,
        list: []const core.networks.Network.Simple,

        pub fn deinit(self: *const @This(), alloc: mem.Allocator) void {
            switch (self.*) {
                .single => |s_net| single: {
                    const resp_net = s_net orelse break :single;
                    resp_net.deinit(alloc);
                },
                .list => |net_list| {
                    for (net_list) |resp_net| //
                        resp_net.deinit(alloc);
                    alloc.free(net_list);
                }
            }
        }
    },
    connections,

    /// Deinitialize any Allocations in this Response.
    pub fn deinit(self: *const @This(), alloc: mem.Allocator) void {
        switch (self.*) {
            .interfaces => |if_resp| if_resp.deinit(alloc),
            .networks => |net_resp| net_resp.deinit(alloc),
            else => {},
        }
    }
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
        {
            self.req_map.mutex.lock();
            defer self.req_map.mutex.unlock();
            var req_iter = self.req_map.map.valueIterator();
            while (req_iter.next()) |req| //
                req.deinit(alloc);
        }
        self.req_map.deinit(alloc);
        {
            self.resp_map.mutex.lock();
            defer self.resp_map.mutex.unlock();
            var resp_iter = self.resp_map.map.valueIterator();
            while (resp_iter.next()) |resp| {
                const free_resp = resp.* catch continue;
                free_resp.deinit(alloc);
            }
        }
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
            var deinit_req: bool = true;
            defer if (deinit_req) //
                req.value_ptr.deinit(core_ctx.alloc);
            switch (req.value_ptr.*) {
                .interfaces => |if_req| {
                    core_ctx.if_ctx.interfaces.mutex.lock();
                    defer core_ctx.if_ctx.interfaces.mutex.unlock();
                    switch (if_req) {
                        .get => |if_id| {
                            const get_if = switch (if_id) {
                                .name => |if_name| getIF: {
                                    var if_iter = core_ctx.if_ctx.interfaces.map.valueIterator();
                                    while (if_iter.next()) |next_if| {
                                        if (mem.eql(u8, if_name, next_if.name))
                                            break :getIF next_if.*;
                                    }
                                    break :getIF null;
                                },
                                .mac => |if_mac| core_ctx.if_ctx.interfaces.get(if_mac),
                            };
                            const resp_if: ?core.interfaces.Interface.Simple = respIF: {
                                const raw_if = get_if orelse break :respIF null;
                                break :respIF .from(core_ctx.alloc, raw_if);
                            };
                            self.resp_map.put(core_ctx.alloc, req.key_ptr.*, .{ .interfaces = .{ .single = resp_if } }) catch @panic("OOM");
                        },
                        .get_all => {
                            var if_list: ArrayList(core.interfaces.Interface.Simple) = .empty;
                            var if_iter = core_ctx.if_ctx.interfaces.map.valueIterator();
                            while (if_iter.next()) |next_if| {
                                const resp_if: core.interfaces.Interface.Simple = .from(core_ctx.alloc, next_if.*);
                                if_list.append(core_ctx.alloc, resp_if) catch @panic("OOM");
                            }
                            const resp_ifs = if_list.toOwnedSlice(core_ctx.alloc) catch @panic("OOM");
                            self.resp_map.put(core_ctx.alloc, req.key_ptr.*, .{ .interfaces = .{ .list = resp_ifs } }) catch @panic("OOM");
                        },
                        .usage => |usage| {
                            const if_name = switch (usage.if_id) {
                                .name => |name| name,
                                .mac => |mac| mac: {
                                    var if_iter = core_ctx.if_ctx.interfaces.map.valueIterator();
                                    while (if_iter.next()) |next_if| {
                                        if (!mem.eql(u8, mac[0..], next_if.og_mac[0..]))
                                            continue;
                                        break :mac next_if.name;
                                    }
                                    log.err("No Interface found for MAC '{f}'.", .{ HexF{ .bytes = mac[0..] } });
                                    self.resp_map.put(core_ctx.alloc, req.key_ptr.*, error.InvalidRequest) catch @panic("OOM");
                                    continue;
                                },
                            };
                            switch (usage.state) {
                                .activate => {
                                    core_ctx.if_ctx.avail_if_names.put(core_ctx.alloc, if_name, {}) catch @panic("OOM");
                                    log.info("Added Interface '{s}' to the Active list.", .{ if_name });
                                    self.resp_map.put(core_ctx.alloc, req.key_ptr.*, .ack) catch @panic("OOM");
                                    deinit_req = false;
                                },
                                .deactivate => deactivate: {
                                    core_ctx.if_ctx.avail_if_names.mutex.lock();
                                    defer core_ctx.if_ctx.avail_if_names.mutex.unlock();
                                    const name = core_ctx.if_ctx.avail_if_names.map.fetchRemove(if_name) orelse break :deactivate;
                                    core_ctx.alloc.free(name.key);
                                    var if_iter = core_ctx.if_ctx.interfaces.map.iterator();
                                    while (if_iter.next()) |next_if_entry| {
                                        const next_if = next_if_entry.value_ptr;
                                        if (!mem.eql(u8, if_name, next_if.name))
                                            continue;
                                        next_if.usage = .inactive;
                                        break;
                                    }
                                    log.info("Removed Interface '{s}' from the Active list.", .{ if_name });
                                    self.resp_map.put(core_ctx.alloc, req.key_ptr.*, .ack) catch @panic("OOM");
                                },
                            }
                        },
                        .mod => {},
                    }
                    log.debug("Handled Interfaces Request: {d}", .{ req.key_ptr.* });
                },
                .networks => |net_req| {
                    core_ctx.network_ctx.networks.mutex.lock();
                    defer core_ctx.network_ctx.networks.mutex.unlock();
                    switch (net_req) {
                        .get_all => {
                            var net_list: ArrayList(core.networks.Network.Simple) = .empty;
                            var net_iter = core_ctx.network_ctx.networks.map.valueIterator();
                            while (net_iter.next()) |next_net| {
                                const resp_net: core.networks.Network.Simple = .from(core_ctx.alloc, next_net.*);
                                net_list.append(core_ctx.alloc, resp_net) catch @panic("OOM");
                            }
                            const resp_nets = net_list.toOwnedSlice(core_ctx.alloc) catch @panic("OOM");
                            self.resp_map.put(core_ctx.alloc, req.key_ptr.*, .{ .networks = .{ .list = resp_nets } }) catch @panic("OOM");
                        },
                        else => {},
                    }
                    log.debug("Handled Networks Request: {d}", .{ req.key_ptr.* });
                },
                .connections => |conn| {
                    core_ctx.conn_ctx.configs.mutex.lock();
                    defer core_ctx.conn_ctx.configs.mutex.unlock();
                    switch (conn) {
                        .add => |add_conn| {
                            for (core_ctx.conn_ctx.configs.list.items, 0..) |next_conn, idx| {
                                if (!next_conn.id.eql(add_conn.id))
                                    continue;
                                _ = core_ctx.conn_ctx.configs.list.orderedRemove(idx);
                                break;
                            }
                            core_ctx.conn_ctx.configs.list.append(core_ctx.alloc, add_conn) catch @panic("OOM");
                            self.resp_map.put(core_ctx.alloc, req.key_ptr.*, .ack) catch @panic("OOM");
                            log.info("Added new Connection: '{f}'", .{ add_conn.id });
                        },
                        .enable => |enable_id| {
                            var enabled = false;
                            for (core_ctx.conn_ctx.configs.list.items) |*next_conn| {
                                if (!next_conn.id.eql(enable_id))
                                    continue;
                                next_conn.enabled = true;
                                enabled = true;
                            }
                            self.resp_map.put(core_ctx.alloc, req.key_ptr.*, .ack) catch @panic("OOM");
                            if (!enabled) //
                                log.info("Connection '{f}' not found.", .{ enable_id }) //
                            else //
                                log.info("Enabled Connection: '{f}'", .{ enable_id });
                        },
                        .disable => |disable_id| disable: {
                            var disabled = false;
                            for (core_ctx.conn_ctx.configs.list.items) |*next_conn| {
                                if (!next_conn.id.eql(disable_id))
                                    continue;
                                next_conn.enabled = false;
                                disabled = true;
                            }
                            self.resp_map.put(core_ctx.alloc, req.key_ptr.*, .ack) catch @panic("OOM");
                            if (!disabled) {
                                log.info("Connection '{f}' not found.", .{ disable_id });
                                break :disable;
                            } //
                            else //
                                log.info("Disabled Connection: '{f}'", .{ disable_id });
                            core_ctx.if_ctx.interfaces.mutex.lock();
                            defer core_ctx.if_ctx.interfaces.mutex.unlock();
                            var if_iter = core_ctx.if_ctx.interfaces.map.iterator();
                            while (if_iter.next()) |next_if_entry| {
                                const next_if = next_if_entry.value_ptr;
                                switch (next_if.usage) {
                                    .connect => |*if_conn| if_conn.stop(core_ctx),
                                    else => {},
                                }
                            }
                        },
                    }
                    log.debug("Handled Connection Request: {d}", .{ req.key_ptr.* });
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
