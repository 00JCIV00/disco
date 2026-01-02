//! Core Functionality of DisCo

const std = @import("std");
const atomic = std.atomic;
const fmt = std.fmt;
const fs = std.fs;
const heap = std.heap;
const io = std.io;
const log = std.log.scoped(.core);
const mem = std.mem;
const meta = std.meta;
const posix = std.posix;
const time = std.time;
const ArrayList = std.ArrayList;
const Io = std.Io;
const Thread = std.Thread;

const zeit = @import("zeit");

const dbus = @import("dbus.zig");
const netdata = @import("netdata.zig");
const oui = netdata.oui;
const wifi = netdata.l2.wifi;
const chs = wifi.channels;
const nl = @import("netlink.zig");
const sys = @import("sys.zig");
const ui = @import("ui.zig");
const utils = @import("utils.zig");
const ansi = utils.ansi;
const c = utils.toStruct;
const PIDF = utils.SliceFormatter(u32, "{d}");
const SlicesF = utils.SliceFormatter([]const u8, "{s}");

pub const captures = @import("core/captures.zig");
pub const connections = @import("core/connections.zig");
pub const devices = @import("core/devices.zig");
pub const interfaces = @import("core/interfaces.zig");
pub const networks = @import("core/networks.zig");
pub const profiles = @import("core/profiles.zig");
pub const serve = @import("core/serve.zig");
pub const sockets = @import("core/sockets.zig");
pub const requests = @import("core/requests.zig");


/// Core Context of DisCo.
/// This should be used as a Singleton that is passed around for context.
pub const Core = struct {
    /// Config
    /// This is made to be configurable by users via JSON or ZON.
    pub const Config = struct {
        /// Profile Settings
        profile: profiles.Profile = .{},
        /// Available Interface Names
        avail_if_names: []const []const u8 = &.{},
        /// Global Scan Config
        global_scan_config: GlobalScanConfig = .{},
        /// Scan Configs
        scan_configs: []const ScanConfig = &.{},
        /// Global Connect Config
        global_connect_config: connections.GlobalConfig = .{},
        /// Connection Configs
        connect_configs: []const connections.Config = &.{},
        /// Log Config
        log_config: ?ui.log.FileConfig = .{},
        /// PCAP Config
        pcap_config: captures.Config = .{},
        /// Serve Config
        serve_config: ?serve.Config = null,

        pub const GlobalScanConfig = struct {
            /// Scan Mode: `netlink` or `monitor`
            mode: meta.Tag(networks.ScanContext) = .monitor,
            /// SSIDs to Scan for
            /// Note, this is only used for `netlink` Scanning
            ssids: ?[]const []const u8 = null,
            /// Channels to Scan through
            channels: []const chs.Channel = &.{},
            /// Dwell Time for each Channel in Milliseconds (ms)
            /// Note, this is only used for `monitor` Scanning
            dwell: u64 = 1_000, 
        };

        pub const ScanConfig = struct {
            if_name: []const u8,
            /// SSIDs to Scan for
            /// Note, this is only used for `netlink` Scanning
            ssids: ?[]const []const u8 = null,
            /// Channels to Scan through
            channels: ?[]const chs.Channel = null,
            /// Dwell Time for each Channel in Milliseconds (ms)
            /// Note, this is only used for `monitor` Scanning
            dwell: ?u64 = null,
        };
    };

    /// Mutex Lock
    _mutex: Thread.Mutex = .{},
    /// Timer
    _timer: time.Timer,
    /// Thread Pool
    _thread_pool: Thread.Pool,
    /// Wait Group
    _wait_group: Thread.WaitGroup = .{},
    /// Allocator
    alloc: mem.Allocator,
    ///// Arena Wrapper f/ Allocator
    //arena: heap.ArenaAllocator,
    /// Config
    config: Config,
    /// Run Condition
    run_condition: ?RunCondition = null,
    /// TUI Context
    tui_ctx: ?ui.tui.Context = null,
    /// Time Zone
    timezone: zeit.TimeZone = zeit.utc,
    /// Interval for Thread Checks.
    interval: usize = 100 * time.ns_per_ms,
    /// Active Status of the overall program.
    active: atomic.Value(bool) = .init(false),
    /// Forced Close
    forced_close: bool = false,
    /// Original Hostname
    og_hostname: []const u8,
    /// Netlink Event Loop
    nl_event_loop: nl.io.Loop,
    /// Netlink 802.11 Handler
    nl80211_handler: *nl.io.Handler,
    /// Netlink Route Handler
    rtnetlink_handler: *nl.io.Handler,
    /// Requests Aggregator
    req_aggregator: requests.Aggregator,
    /// Socket Event Loop
    sock_event_loop: sockets.Loop,
    /// Interface Context
    if_ctx: interfaces.Context,
    /// Network Context
    network_ctx: networks.Context,
    /// Connection Context
    conn_ctx: connections.Context,
    /// Device Context
    dev_ctx: devices.Context,
    /// Serve Context
    serve_ctx: serve.Context,
    /// Capture Writer
    cap_writer: captures.Writer,
    /// D-Bus Connection
    dbus_conn: dbus.Connection,


    /// Initialize the Core Context.
    pub fn init(alloc: mem.Allocator, timezone: zeit.TimeZone, config: Config) !@This() {
        log.info("{s}{s}Initializing DisCo Core...{s}", .{ ansi.fmt.bold, ansi.fmt.italic, ansi.reset });
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
            ._thread_pool = .{ .ids = .{}, .threads = &[_]Thread{}, .allocator = alloc },
            .alloc = alloc,
            //.arena = arena,
            .config = config,
            .timezone = timezone,
            .nl_event_loop = try .init(.{}),
            .nl80211_handler = nl80211_handler,
            .rtnetlink_handler = rtnetlink_handler,
            .req_aggregator = .{},
            .sock_event_loop = try .init(),
            .og_hostname = og_hostname,
            .if_ctx = undefined,
            .network_ctx = undefined,
            .conn_ctx = undefined,
            .dev_ctx = undefined,
            .serve_ctx = undefined,
            .cap_writer = undefined,
            .dbus_conn = try .init(alloc),
        };
        errdefer self.nl_event_loop.deinit(alloc);
        try self.nl_event_loop.addHandler(self.alloc, self.nl80211_handler);
        try self.nl_event_loop.addHandler(self.alloc, self.rtnetlink_handler);
        // Context Initialization
        self.if_ctx = try .init(&self);
        errdefer self.if_ctx.deinit(alloc);
        log.debug("Initialized Interfaces Context", .{});
        self.network_ctx = try .init(&self);
        errdefer self.network_ctx.deinit(alloc);
        log.debug("Initialized Networks Context", .{});
        self.conn_ctx = try .init(&self);
        errdefer self.conn_ctx.deinit(alloc);
        log.debug("Initialized Connections Context", .{});
        self.dev_ctx = try .init(&self);
        errdefer self.dev_ctx.deinit(alloc);
        log.debug("Initialized Devices Context", .{});
        if (config.serve_config) |serve_conf| {
            self.serve_ctx = serve.Context.init(alloc, serve_conf) catch @panic("OOM");
            log.info("- Initialized File Serve Data.", .{});
        }
        errdefer if (config.serve_config) |_| //
            self.serve_ctx.deinit(alloc);
        log.info("{s}{s}Initialized DisCo Core.{s}", .{ ansi.fmt.bold, ansi.fmt.italic, ansi.reset });
        return self;
    }

    /// Start the Core Context
    /// This is the main loop for how DisCo is typically run.
    pub fn start(self: *@This()) !void {
        if (!self._mutex.tryLock()) //
            return error.CoreAlreadyRunning;
        log.debug("Core Locked!", .{});
        log.info("{s}{s}Starting DisCo Core...{s}", .{ ansi.fmt.bold, ansi.fmt.italic, ansi.reset });
        defer {
            log.debug("Core Unlocked!", .{});
            self._mutex.unlock();
        }
        // Find Conflicting PIDs
        const found_pids = try findConflictPIDs(
            self.alloc,
            self.config.profile.conflict_processes,
            null,
            "- Found the '{s}' process running {d} time(s) (PID(s): {f}). This could cause issues w/ DisCo.",
        );
        if (found_pids and self.config.profile.require_conflicts_ack) {
            var stdout_file = fs.File.stdout();
            var stdout_writer = stdout_file.writer(&.{});
            const stdout = &stdout_writer.interface;
            try stdout.print(
                \\
                \\{s}{s}Conflict PIDs found! You may want to kill those processes or ensure you've deconflicted WiFi Interfaces.{s}
                \\Press {s}{s}[ENTER]{s} to acknowledge and continue.
                \\
                , .{
                    ansi.fmt.italic,
                    ansi.fg.yellow,
                    ansi.reset,
                    ansi.fmt.bold,
                    ansi.fg.blue,
                    ansi.reset,
                },
            );
            var stdin_file = fs.File.stdin();
            var stdin_buf: [16]u8 = undefined;
            var stdin_reader = stdin_file.reader(stdin_buf[0..]);
            const stdin = &stdin_reader.interface;
            _ = try stdin.discardDelimiterExclusive('\n');
        }
        self.active.store(true, .release);
        // Profile Mask
        if (self.config.profile.mask == null) setMask: {
            log.info("- No Profile Mask provided.", .{});
            if (!self.config.profile.use_random_mask) {
                log.info("- Profile Mask explicitly NOT used.", .{});
                break :setMask;
            }
            const mask = profiles.Mask.getRandom();
            self.config.profile.mask = mask;
            log.info("- Defaulting to a random '{s}' Profile Mask:\n{f}", .{ 
                try oui.findOUI(.long, mask.oui.? ++ .{ 0, 0, 0 }),
                mask,
            });
        }
        if (self.config.profile.mask) |pro_mask| {
            if (self.config.profile.change_sys_hostname) {
                try sys.setHostName(pro_mask.hostname);
                log.info("- Set Hostname to '{s}'.", .{ pro_mask.hostname });
            } //
            else //
                log.info("- The masked Network Hostname is '{s}'. The System Hostname is still '{s}'.", .{ pro_mask.hostname, self.og_hostname });
        }
        // File Serving
        if (self.config.serve_config) |_| //
            try self.serve_ctx.start(self.alloc);
        self._wait_group.start();
        // Available Interfaces
        log.debug("Searching for the following Interfaces: {f}", .{ SlicesF{ .slice = self.config.avail_if_names } });
        // Netlink Event Loop
        try self.nl_event_loop.start(self.alloc, &self.active);
        // Sockets Event Loop
        try self.sock_event_loop.start();
        // Device Tracking
        self.dev_ctx.start();
        // PCAP Handling
        self.cap_writer = try .init(self);
        // Core Loop
        log.info("{s}{s}Started DisCo Core.{s}", .{ ansi.fmt.bold, ansi.fmt.italic, ansi.reset });
        self._timer.reset();
        while (self.active.load(.acquire)) {
            //defer log.debug("Core Loop: {d}ms", .{ self._timer.lap() / time.ns_per_ms });
            //log.debug("Core Update", .{});
            //defer Thread.sleep(10 * time.ns_per_ms);
            // Interface Tracking
            try self.if_ctx.update();
            //Thread.sleep(1 * time.ns_per_ms);
            // Socket Monitoring
            try self.sock_event_loop.update();
            // Connection Tracking
            try self.conn_ctx.update();
            // Network Tracking
            try self.network_ctx.update();
            // Capture Writing
            try self.cap_writer.update();
            // Request Processing
            try self.req_aggregator.process();
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
            _cur_iter: u8 = 0,
            _cur_passes: u8 = 0,
            max_passes: u8 = 4,
        },
    };
    /// (WIP) Run the Core Context up To the provided `condition`.
    /// This is useful for getting info from all Interfaces, doing a single Scan, etc
    pub fn runTo(self: *@This(), condition: RunCondition) !void {
        if (!self._mutex.tryLock()) //
            return error.CoreAlreadyRunning;
        defer self._mutex.unlock();
        self.active.store(true, .release);
        self.run_condition = condition;
        // Event Loop
        try self.nl_event_loop.start(self.alloc, &self.active);
        // Core Loop
        try self.if_ctx.update();
        while (switch (self.run_condition.?) {
            .list_interfaces => |list_cond| !list_cond.updated,
            //TODO: WIP
            .mod_interfaces => |mod_cond| !mod_cond.complete,
            .network_scan => |scan_cond| scan_cond._cur_passes < scan_cond.max_passes,
        }) {
            // Interface Tracking
            try self.if_ctx.update();
            // Network Tracking
            try self.network_ctx.update();
            Thread.sleep(10 * time.ns_per_ms);
        }
    }

    /// Stop the Core Context
    pub fn stop(self: *@This()) void {
        var stop_timer = time.Timer.start() catch null;
        log.info("{s}{s}Stopping DisCo Core...{s}", .{ ansi.fmt.bold, ansi.fmt.italic, ansi.reset });
        self.active.store(false, .seq_cst);
        self._mutex.lock();
        defer self._mutex.unlock();
        //self.nl_event_loop.stop(null);
        //log.info("- Stopped Netlink Event Loop.", .{});
        //self._thread_pool.waitAndWork(&self._wait_group);
        //self._thread_pool.deinit();
        //self.serve_ctx.active.store(false, .monotonic);
        if (self.config.serve_config) |_| //
            self.serve_ctx.stop();
        log.info("- Stopped all Core Threads.", .{});
        // TODO Archive Session Data
        self.cleanUp();
        log.info("{s}{s}Stopped DisCo Core.{s}", .{ ansi.fmt.bold, ansi.fmt.italic, ansi.reset });
        if (stop_timer) |*st| //
            log.debug("Stop Time: {d}ms", .{ @divTrunc(st.read(), time.ns_per_ms) });
    }

    /// Clean Up.
    /// TODO: Improve this if it will be needed outside of closing DisCo.
    pub fn cleanUp(self: *@This()) void {
        log.info("Cleaning up DisCo Core...", .{});
        if (self.config.profile.mask != null and self.config.profile.change_sys_hostname) {
            if (sys.setHostName(self.og_hostname)) //
                log.info("- Restored the Hostname to '{s}'.", .{ self.og_hostname })
            else |err| //
                log.warn("- Couldn't reset the Hostname: {t}", .{ err });
        }
        if (self.run_condition == null) //
            self.cap_writer.deinit();
        self.if_ctx.restore();
        self.alloc.free(self.og_hostname);
        if (self.forced_close) {
            log.warn("- Forced close. Leaving resource clean up to the OS.", .{});
            return;
        }
        self.if_ctx.deinit(self.alloc);
        log.info("- Deinitialized Interface Tracking.", .{});
        self.network_ctx.deinit(self.alloc);
        //if (self.config.scan_configs.len > 0) self._alloc.free(self.config.scan_configs);
        log.info("- Deinitialized Network Tracking.", .{});
        self.conn_ctx.deinit(self.alloc);
        log.info("- Deinitialized Connection Tracking.", .{});
        self.dev_ctx.deinit(self.alloc);
        log.info("- Deinitialized Device Tracking.", .{});
        if (self.config.serve_config) |_| {
            self.serve_ctx.deinit(self.alloc);
            log.info("- Deinitialized File Serving.", .{});
        }
        if (self.run_condition == null) //
            log.info("- Deinitialized PCAP Writing.", .{});
        self.sock_event_loop.deinit(self.alloc);
        log.info("- Deinitialized Socket Event Loop.", .{});
        //self.arena.deinit();
        self.req_aggregator.deinit(self.alloc);
        log.info("- Deinitialized Request Aggregation.", .{});
        self.nl_event_loop.deinit(self.alloc);
        self.alloc.destroy(self.nl80211_handler);
        self.alloc.destroy(self.rtnetlink_handler);
        //self.nl_event_loop.stop(self.alloc);
        log.info("- Deinitialized Netlink Event Loop.", .{});
        self.dbus_conn.deinit(self.alloc);
        log.info("- Deinitialized D-Bus Connection.", .{});
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
        if (config.sys_info == false and config.if_info == .none) //
            return;
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
            if (config.if_info == .available and print_if.usage != .active) continue;
            try writer.print(
                \\{f}
                \\-----------
                \\
                , .{ fmt.alt(print_if.*, .formatANSI) }
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
    writer: ?*Io.Writer,
    comptime fmt_str: []const u8,
) !bool {
    var found_pids: bool = false;
    for (proc_names) |p_name| {
        const pids = try sys.getPIDs(alloc, &.{ p_name });
        defer alloc.free(pids);
        if (pids.len > 0) {
            found_pids = true;
            if (writer) |w| {
                try w.print(fmt_str, .{ p_name, pids.len, PIDF{ .slice = pids } });
                continue;
            }
            log.warn(fmt_str, .{ p_name, pids.len, PIDF{ .slice = pids } });
        }
    }
    return found_pids;
}

