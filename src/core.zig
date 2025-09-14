//! Core Functionality of DisCo

const std = @import("std");
const atomic = std.atomic;
const heap = std.heap;
const io = std.io;
const log = std.log.scoped(.core);
const mem = std.mem;
const meta = std.meta;
const posix = std.posix;
const time = std.time;
const ArrayList = std.ArrayListUnmanaged;

const netdata = @import("netdata.zig");
const oui = netdata.oui;
const nl = @import("netlink.zig");
const sys = @import("sys.zig");
const utils = @import("utils.zig");
const c = utils.toStruct;

pub const interfaces = @import("core/interfaces.zig");
pub const networks = @import("core/networks.zig");
pub const connections = @import("core/connections.zig");
pub const profiles = @import("core/profiles.zig");
pub const serve = @import("core/serve.zig");


/// Core Context of DisCo.
/// This should be used as a Singleton that is passed around for context.
pub const Core = struct {
    /// Config
    /// This is made to be configurable by users via JSON or ZON.
    pub const Config = struct {
        pub const ScanConfig = struct {
            if_name: []const u8,
            ssids: ?[]const []const u8 = null,
            channels: ?[]const usize = null,
        };

        /// Profile Settings
        profile: profiles.Profile = .{},
        /// Available Interface Names
        avail_if_names: []const []const u8 = &.{},
        /// Scan Configs
        scan_configs: []const ScanConfig = &.{},
        /// Global Connect Config
        global_connect_config: connections.GlobalConfig = .{},
        /// Connection Configs
        connect_configs: []const connections.Config = &.{},
        /// Serve Config
        serve_config: ?serve.Config = null,
    };

    /// Mutex Lock
    _mutex: std.Thread.Mutex = .{},
    /// Timer
    _timer: time.Timer,
    /// Thread Pool
    _thread_pool: std.Thread.Pool,
    /// Wait Group
    _wait_group: std.Thread.WaitGroup = .{},
    /// Allocator
    alloc: mem.Allocator,
    ///// Arena Wrapper f/ Allocator
    //arena: heap.ArenaAllocator,
    /// Config
    config: Config,
    run_condition: ?RunCondition = null,
    /// Interval for Thread Checks.
    interval: usize = 100 * time.ns_per_ms,
    /// Active Status of the overall program.
    active: atomic.Value(bool) = .init(false),
    /// Netlink Event Loop
    nl_event_loop: nl.io.Loop,
    /// Netlink 802.11 Handler
    nl80211_handler: *nl.io.Handler,
    /// Netlink Route Handler
    rtnetlink_handler: *nl.io.Handler,
    /// Interface Context
    if_ctx: interfaces.Context,
    /// Network Context
    network_ctx: networks.Context,
    /// Connection Context
    conn_ctx: connections.Context,
    /// Serve Context
    serve_ctx: serve.Context,
    /// Original Hostname
    og_hostname: []const u8,
    /// Forced Close
    forced_close: bool = false,


    /// Initialize the Core Context.
    pub fn init(alloc: mem.Allocator, config: Config) !@This() {
        log.info("Initializing DisCo Core...", .{});
        //var arena = heap.ArenaAllocator.init(alloc);
        //errdefer arena.deinit();
        // Get Original Hostname
        var og_hn_buf: [posix.HOST_NAME_MAX]u8 = undefined;
        const og_hostname = alloc.dupe(u8, try posix.gethostname(og_hn_buf[0..posix.HOST_NAME_MAX])) catch @panic("OOM");
        errdefer alloc.free(og_hostname);
        // Netlink Handlers
        const nl80211_handler = alloc.create(nl.io.Handler) catch @panic("OOM");
        nl80211_handler.* = try .init(alloc, nl.NETLINK.GENERIC, .{});
        errdefer alloc.destroy(nl80211_handler);
        const rtnetlink_handler = alloc.create(nl.io.Handler) catch @panic("OOM");
        rtnetlink_handler.* = try .init(alloc, nl.NETLINK.ROUTE, .{});
        errdefer alloc.destroy(rtnetlink_handler);
        // Core Creation
        var self: @This() = .{
            ._timer = try std.time.Timer.start(),
            ._thread_pool = .{ .ids = .{}, .threads = &[_]std.Thread{}, .allocator = alloc },
            .alloc = alloc,
            //.arena = arena,
            .config = config,
            .nl_event_loop = try .init(.{}),
            .nl80211_handler = nl80211_handler,
            .rtnetlink_handler = rtnetlink_handler,
            .og_hostname = og_hostname,
            .if_ctx = undefined,
            .network_ctx = undefined,
            .conn_ctx = undefined,
            .serve_ctx = undefined,
        };
        try self.nl_event_loop.addHandler(self.alloc, self.nl80211_handler);
        try self.nl_event_loop.addHandler(self.alloc, self.rtnetlink_handler);
        //// Context Initialization
        self.if_ctx = try .init(&self);
        errdefer self.if_ctx.deinit(alloc);
        self.network_ctx = try .init(&self);
        errdefer self.network_ctx.deinit(alloc);
        self.conn_ctx = try .init(&self);
        errdefer self.conn_ctx.deinit(alloc);
        self.serve_ctx = serve.Context.init(alloc) catch @panic("OOM");
        errdefer self.serve_ctx.deinit(alloc);
        // Context Setup
        //self.conn_ctx.global_config.* = config.global_connect_config;
        //for (config.connect_configs) |conn_conf| {
        //    try self.conn_ctx.configs.put(
        //        alloc,
        //        conn_conf.ssid,
        //        conn_conf,
        //    );
        //}
        //log.info("- Initialized Connection Tracking Data.", .{});
        if (config.serve_config) |serve_conf| {
            self.serve_ctx.conf.* = serve_conf;
            log.info("- Initialized File Serve Data.", .{});
        }
        log.info("Initialized DisCo Core.", .{});
        //time.sleep(5 * time.ns_per_s);
        return self;
    }

    /// Start the Core Context
    /// This is the main loop for how DisCo is typically run.
    pub fn start(self: *@This()) !void {
        if (!self._mutex.tryLock()) return error.CoreAlreadyRunning;
        log.info("Core Locked!", .{});
        log.info("Starting DisCo Core...", .{});
        self.active.store(true, .release);
        defer {
            log.info("Core Unlocked!", .{});
            self._mutex.unlock();
        }
        // Find Conflicting PIDs
        const found_pids = try findConflictPIDs(
            self.alloc,
            self.config.profile.conflict_processes,
            null,
            "- Found the '{s}' process running {d} time(s) (PID(s): {d}). This could cause issues w/ DisCo.",
        );
        if (found_pids and self.config.profile.require_conflicts_ack) {
            const stdout = io.getStdOut().writer();
            try stdout.print(
                \\
                \\Conflict PIDs found! You may want to kill those processes or ensure you've deconflicted WiFi Interfaces.
                \\Press ENTER to acknowledge and continue.
                \\
                , .{}
            );
            const stdin = io.getStdIn().reader();
            const input = try stdin.readUntilDelimiterOrEofAlloc(self.alloc, '\n', 4096);
            defer if (input) |in| self.alloc.free(in);
        }
        // Profile Mask
        if (self.config.profile.mask == null) setMask: {
            log.info("- No Profile Mask provided.", .{}); 
            if (!self.config.profile.use_random_mask) {
                log.info("- Profile Mask explicitly NOT used.", .{});
                break :setMask;
            }
            const mask = profiles.Mask.getRandom();
            self.config.profile.mask = mask;
            log.info("- Defaulting to a random '{s}' Profile Mask:\n{s}", .{ 
                try oui.findOUI(.long, mask.oui.? ++ .{ 0, 0, 0 }),
                mask,
            });
        }
        if (self.config.profile.mask) |pro_mask| {
            if (self.config.profile.change_sys_hostname) {
                try sys.setHostName(pro_mask.hostname);
                log.info("- Set Hostname to '{s}'.", .{ pro_mask.hostname });
            }
            else
                log.info("- The masked Network Hostname is '{s}'. The System Hostname is still '{s}'.", .{ pro_mask.hostname, self.og_hostname });
        }
        // File Serving
        if (self.config.serve_config) |_| {
            self._thread_pool.spawnWg(
                &self._wait_group,
                serve.serveDir,
                .{
                    self.alloc,
                    &self.serve_ctx,
                    &self.active,
                },
            );
            log.info("- Started File Serving.", .{});
        }
        // Available Interfaces
        log.debug("Searching for the following Interfaces: {s}", .{ self.config.avail_if_names });
        // Event Loop
        try self.nl_event_loop.start(self.alloc, &self.active); 
        // Core Loop
        log.info("Started DisCo Core.", .{});
        while (self.active.load(.acquire)) {
            // Interface Tracking
            try self.if_ctx.update(self);
            time.sleep(1 * time.ns_per_ms);
            // Connection Tracking
            try self.conn_ctx.update(self);
            // Network Tracking
            try self.network_ctx.update(self);
            time.sleep(10 * time.ns_per_ms);
        }
        //self._thread_pool.waitAndWork(&self._wait_group);
        self._thread_pool.deinit();
    }

    /// Run Condition for `runTo()`.
    pub const RunCondition = union(enum) {
        list_interfaces: struct {
            updated: bool = false,
        },
        mod_interfaces: struct {
            complete: bool = false,
        },
        network_scan: struct {
            _cur_passes: u8 = 0,
            max_passes: u8 = 10,
        },
    };
    /// (WIP) Run the Core Context up To the provided `condition`.
    /// This is useful for getting info from all Interfaces, doing a single Scan, etc
    pub fn runTo(self: *@This(), condition: RunCondition) !void {
        if (!self._mutex.tryLock()) return error.CoreAlreadyRunning;
        defer self._mutex.unlock();
        self.active.store(true, .release);
        self.run_condition = condition;
        // Event Loop
        try self.nl_event_loop.start(self.alloc, &self.active);
        // Core Loop
        try self.if_ctx.update(self);
        while (switch (self.run_condition.?) {
            .list_interfaces => |list_cond| !list_cond.updated,
            //TODO: WIP
            .mod_interfaces => |mod_cond| !mod_cond.complete,
            .network_scan => |scan_cond| scan_cond._cur_passes < scan_cond.max_passes,
        }) {
            try self.if_ctx.update(self);
        }
    }

    /// Stop the Core Context
    /// TODO: archive session data
    pub fn stop(self: *@This()) void {
        var stop_timer = time.Timer.start() catch null;
        log.info("Stopping DisCo Core...", .{});
        self.active.store(false, .seq_cst);
        self._mutex.lock();
        defer self._mutex.unlock();
        //self.nl_event_loop.stop(null);
        //log.info("- Stopped Netlink Event Loop.", .{});
        //self._thread_pool.waitAndWork(&self._wait_group);
        //self._thread_pool.deinit();
        log.info("- Stopped all Core Threads.", .{});
        // TODO Archive Session Data
        self.cleanUp();
        log.info("Stopped DisCo Core.", .{});
        if (stop_timer) |*st|
            log.debug("Stop Time: {d}ms", .{ @divTrunc(st.read(), time.ns_per_ms) });
    }

    /// Clean Up.
    /// TODO: Improve this if it will be needed outside of closing DisCo.
    pub fn cleanUp(self: *@This()) void {
        log.info("Cleaning up DisCo Core...", .{});
        if (self.config.profile.mask != null and self.config.profile.change_sys_hostname) {
            if (sys.setHostName(self.og_hostname)) 
                log.info("- Restored the Hostname to '{s}'.", .{ self.og_hostname })
            else |err|
                log.warn("- Couldn't reset the Hostname: {s}", .{ @errorName(err) });
        }
        self.if_ctx.restore(self.alloc);
        self.alloc.free(self.og_hostname);
        if (self.forced_close) {
            log.warn("- Forced close. Leaving memory clean up to the OS.", .{});
            return;
        }
        self.if_ctx.deinit(self.alloc);
        log.info("- Deinitialized Interface Tracking.", .{});
        self.network_ctx.deinit(self.alloc);
        //if (self.config.scan_configs.len > 0) self._alloc.free(self.config.scan_configs);
        log.info("- Deinitialized Network Tracking.", .{});
        self.conn_ctx.deinit(self.alloc);
        log.info("- Deinitialized Connection Tracking.", .{});
        self.serve_ctx.deinit(self.alloc);
        log.info("- Deinitialized File Serving.", .{});
        //self.arena.deinit();
        self.nl_event_loop.deinit(self.alloc);
        self.alloc.destroy(self.nl80211_handler);
        self.alloc.destroy(self.rtnetlink_handler);
        //self.nl_event_loop.stop(self.alloc);
        log.info("- Deinitialized Netlink Event Loop.", .{});
        log.info("- Deinitialized All Contexts.", .{});
        log.info("Cleaned up DisCo Core.", .{});
    }

    /// Print Config
    pub const PrintConfig = struct {
        sys_info: bool = true,
        if_info: IFInfo = .all,

        pub const IFInfo = enum {
            none,
            available,
            all,
        };
    };
    /// Print System & Interface Info
    pub fn printInfo(self: *@This(), writer: anytype, config: PrintConfig) !void {
        try writer.print("DisCo Info:\n", .{});
        if (config.sys_info) {
            var hn_buf: [posix.HOST_NAME_MAX]u8 = undefined;
            try writer.print(
                //\\DisCo Info:
                \\-----------
                \\Hostname: {s}
                \\-----------
                \\
                , .{ try posix.gethostname(hn_buf[0..]) }
            );
        }
        try writer.print("Interface Details:\n", .{});
        if (config.if_info == .none) return;
        var if_iter = self.if_ctx.interfaces.iterator(); 
        defer if_iter.unlock();
        while (if_iter.next()) |print_if_entry| {
            const print_if = print_if_entry.value_ptr;
            if (config.if_info == .available and print_if.usage != .available) continue;
            try writer.print(
                \\{s}
                \\-----------
                \\
                , .{ print_if }
            );
        }
    }
};

/// Netlink Async State for Core Contexts
pub const AsyncState = enum {
    ready,
    request,
    await_response,
    parse,
};

/// Find Conflicting PIDs
pub fn findConflictPIDs(
    alloc: mem.Allocator, 
    proc_names: []const []const u8,
    writer: ?io.AnyWriter,
    comptime fmt: []const u8,
) !bool {
    var found_pids: bool = false;
    for (proc_names) |p_name| {
        const pids = try sys.getPIDs(alloc, &.{ p_name });
        defer alloc.free(pids);
        if (pids.len > 0) {
            found_pids = true;
            if (writer) |w| {
                try w.print(fmt, .{ p_name, pids.len, pids });
                continue;
            }
            log.warn(fmt, .{ p_name, pids.len, pids });
        }
    }
    return found_pids;
}

/// Reset a Map containing Netlink Data
pub fn resetNLMap(
    alloc: mem.Allocator,
    K: type,
    V: type,
    map: *utils.ThreadHashMap(K, V),
) void {
    // Clean
    var map_iter = map.iterator();
    var rm_idxs: [16_000]?K = @splat(null);
    var rm_count: u16 = 0;
    while (map_iter.next()) |val| {
        nl.parse.freeBytes(alloc, V, val.value_ptr.*);
        rm_idxs[rm_count] = val.key_ptr.*;
        rm_count +|= 1;
    }
    map_iter.unlock();
    for (rm_idxs[0..rm_count]) |_idx| {
        const idx = _idx orelse break;
        _ = map.remove(idx);
    }
}
