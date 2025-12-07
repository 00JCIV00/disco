//! REPL Modules for DisCo

const builtin = @import("builtin");
const std = @import("std");
const ascii = std.ascii;
const enums = std.enums;
const fmt = std.fmt;
const heap = std.heap;
const log = std.log;
const mem = std.mem;
const debug = log.scoped(.repl).debug;
const ArrayList = std.ArrayList;
const Io = std.Io;
const Thread = std.Thread;

const cova = @import("cova");
const vaxis = @import("vaxis");
const vxfw = vaxis.vxfw;
const zeit = @import("zeit");

const art = @import("../art.zig");
const core = @import("../core.zig");
const netdata = @import("../netdata.zig");
const address = netdata.address;
const wifi = netdata.l2.wifi;
const chs = wifi.channels;
const nl = @import("../netlink.zig");
const ui = @import("../ui.zig");
const utils = @import("../utils.zig");
const ansi = utils.ansi;
const main_cli = ui.cli;
const ThreadArrayList = utils.ThreadArrayList;


/// Full REPL Shell
pub const Shell = struct {
    core_ctx: *core.Core,
    display: *Display,
    cmd_bar: *CommandBar,
    tick_interval: u32 = 200,
    active: enum { display, cmd_bar } = .cmd_bar,
    cmd_legend_segs: []const vaxis.Segment,
    dis_legend_segs: []const vaxis.Segment,

    /// Initialize a new REPL Shell
    pub fn init(alloc: mem.Allocator, core_ctx: *core.Core) mem.Allocator.Error!*@This() {
        const self = try alloc.create(@This());
        self.* = .{
            .core_ctx = core_ctx,
            .display = try .init(alloc),
            .cmd_bar = try .init(alloc),
            .cmd_legend_segs = ui.tui.ansiToSegments(alloc, comptime legendString(.cmd_bar)) catch return mem.Allocator.Error.OutOfMemory,
            .dis_legend_segs = ui.tui.ansiToSegments(alloc, comptime legendString(.display)) catch return mem.Allocator.Error.OutOfMemory,
        };
        self.display.shell = self;
        self.cmd_bar.shell = self;
        self.display.tick_interval = self.tick_interval;
        self.cmd_bar.textfield.userdata = @as(*anyopaque, @ptrCast(&self.cmd_bar));
        return self;
    }

    /// Deinitialize this REPL Shell
    pub fn deinit(self: *@This(), alloc: mem.Allocator) void {
        self.display.deinit();
        self.cmd_bar.deinit();
        inline for (&.{ self.cmd_legend_segs, self.dis_legend_segs }) |legend_segs| {
            for (legend_segs) |seg|
                alloc.free(seg.text);
            alloc.free(legend_segs);
        }
        alloc.destroy(self);
    }

    /// Get the `vxfw.Widget` for this REPL Shell
    pub fn widget(self: *@This()) vxfw.Widget {
        return .{
            .userdata = self,
            .drawFn = drawTypeErased,
            .eventHandler = handleEventTypeErased,
            .captureHandler = handleEventTypeErased,
        };
    }

    /// Handle Events on this REPL Shell
    pub fn handleEvent(self: *@This(), ctx: *vxfw.EventContext, event: vxfw.Event) !void {
        switch (event) {
            .init => {
                try ctx.requestFocus(self.widget());
                try ctx.tick(self.tick_interval, self.widget());
                try ctx.tick(self.tick_interval, self.display.widget());
                try ctx.tick(self.tick_interval, self.cmd_bar.widget());
            },
            .key_press => |key| {
                if (key.matches('c', .{ .ctrl = true })) {
                    ctx.quit = true;
                    return;
                }
                if (key.matches(vaxis.Key.up, .{ .ctrl = true } ))
                    self.active = .display;
                if ( //
                    key.matches(vaxis.Key.down, .{ .ctrl = true }) or //
                    key.matches(':', .{}) //
                )
                    self.active = .cmd_bar;
            },
            .tick => {
                try ctx.tick(self.tick_interval, self.widget());
                try ctx.tick(self.tick_interval, self.display.widget());
                try ctx.tick(self.tick_interval, self.cmd_bar.widget());
                if (self.display.auto_scroll) //
                    try ctx.queueRefresh();
                switch (self.active) {
                    //.display => try ctx.requestFocus(self.display.list_view.widget()),
                    .display => try ctx.requestFocus(self.display.scroll_bars.scroll_view.widget()),
                    .cmd_bar => try ctx.requestFocus(self.cmd_bar.textfield.widget()),
                }
            },
            else => {},
        }
    }

    /// Draw this REPL Shell
    pub fn draw(self: *@This(), ctx: vxfw.DrawContext) mem.Allocator.Error!vxfw.Surface {
        const max = ctx.max.size();
        const legend_segs = switch (self.active) {
            .cmd_bar => self.cmd_legend_segs,
            .display => self.dis_legend_segs,
        };
        const legend_text: vxfw.RichText = .{
            .text = legend_segs,
            .softwrap = false,
        };
        const legend_center: vxfw.Center = .{
            .child = legend_text.widget(),
        };
        const legend_surf: vxfw.SubSurface = .{
            .origin = .{ .row = 0, .col = 0 },
            .surface = try legend_center.draw(ctx.withConstraints(
                .{ .width = max.width, .height = 1 },
                .{ .width = max.width, .height = 1 },
            )),
        };
        const cmd_bar_height: u16 = 1;
        const display_surf: vxfw.SubSurface = .{
            .origin = .{ .row = 1, .col = 0 },
            .surface = try self.display.draw(ctx.withConstraints(
                .{ .width = ctx.min.width, .height = ctx.min.height },
                .{ .width = max.width, .height = max.height - cmd_bar_height - 1 },
            )),
        };
        const cmd_bar_surf: vxfw.SubSurface = .{
            .origin = .{ .row = max.height - cmd_bar_height, .col = 0 },
            .surface = try self.cmd_bar.draw(ctx.withConstraints(
                .{ .width = max.width, .height = cmd_bar_height },
                .{ .width = max.width, .height = cmd_bar_height },
            )),
        };
        const children = try ctx.arena.alloc(vxfw.SubSurface, 3);
        children[0] = legend_surf;
        children[1] = display_surf;
        children[2] = cmd_bar_surf;
        return .{
            .size = max,
            .widget = self.widget(),
            .buffer = &.{},
            .children = children,
        };
    }

    fn handleEventTypeErased(ptr: *anyopaque, ctx: *vxfw.EventContext, event: vxfw.Event) anyerror!void {
        const self: *@This() = @ptrCast(@alignCast(ptr));
        try self.handleEvent(ctx, event);
    }

    fn drawTypeErased(ptr: *anyopaque, ctx: vxfw.DrawContext) mem.Allocator.Error!vxfw.Surface {
        const self: *@This() = @ptrCast(@alignCast(ptr));
        return try self.draw(ctx);
    }

    fn legendString(comptime kind: enum { cmd_bar, display }) []const u8 {
        const focus_display: []const u8 = fmt.comptimePrint(
            "{s}{s}Focus Display{s}:{s} {s}{f}ctrl+up{s}",
            .{
                // Focus Display
                ansi.fmt.underline,
                ansi.fmt.dim,
                ansi.reset,
                ansi.fmt.reset_underline,
                // ctrl+up
                ansi.fmt.bold,
                ansi.fg.rgb(.from(art.disco_blue)),
                ansi.reset,
            },
        );
        const focus_cmd_bar: []const u8 = fmt.comptimePrint(
            "{s}{s}Focus Command Bar{s}:{s} {s}{f}ctrl+down{s}{s} or {s}{s}{f}:{s}",
            .{
                // Focus Command Bar
                ansi.fmt.underline,
                ansi.fmt.dim,
                ansi.fmt.reset_underline,
                ansi.reset,
                // ctrl+down
                ansi.fmt.bold,
                ansi.fg.rgb(.from(art.disco_blue)),
                ansi.reset,
                // or
                ansi.fmt.dim,
                ansi.reset,
                // :
                ansi.fmt.bold,
                ansi.fg.rgb(.from(art.disco_blue)),
                ansi.reset,
            },
        );
        const cmd_history: []const u8 = fmt.comptimePrint(
            "{s}{s}Command History{s}:{s} {s}{f}up{s}{s}/{s}{s}{f}down{s}",
            .{
                // Focus Command Bar
                ansi.fmt.underline,
                ansi.fmt.dim,
                ansi.fmt.reset_underline,
                ansi.reset,
                // ctrl+down
                ansi.fmt.bold,
                ansi.fg.rgb(.from(art.disco_blue)),
                ansi.reset,
                // /
                ansi.fmt.dim,
                ansi.reset,
                // :
                ansi.fmt.bold,
                ansi.fg.rgb(.from(art.disco_blue)),
                ansi.reset,
            },
        );
        const auto_scroll: []const u8 = fmt.comptimePrint(
            "{s}{s}Auto Scroll{s}:{s} {s}{f}end{s}",
            .{
                // Auto Scroll
                ansi.fmt.underline,
                ansi.fmt.dim,
                ansi.fmt.reset_underline,
                ansi.reset,
                // end
                ansi.fmt.bold,
                ansi.fg.rgb(.from(art.disco_blue)),
                ansi.reset,
            },
        );
        const see_cmds: []const u8 = fmt.comptimePrint(
            "{s}{s}See Commands{s}:{s} {s}{f}help{s}",
            .{
                // See Commands
                ansi.fmt.underline,
                ansi.fmt.dim,
                ansi.fmt.reset_underline,
                ansi.reset,
                // help
                ansi.fmt.bold,
                ansi.fg.rgb(.from(art.disco_blue)),
                ansi.reset,
            },
        );
        const exit: []const u8 = fmt.comptimePrint(
            "{s}{s}Exit{s}:{s} {s}{f}ctrl+c{s}{s} or {s}{s}{f}exit{s}",
            .{
                // Exit
                ansi.fmt.underline,
                ansi.fmt.dim,
                ansi.fmt.reset_underline,
                ansi.reset,
                // ctrl+c
                ansi.fmt.bold,
                ansi.fg.rgb(.from(art.disco_blue)),
                ansi.reset,
                // or
                ansi.fmt.dim,
                ansi.reset,
                // exit
                ansi.fmt.bold,
                ansi.fg.rgb(.from(art.disco_blue)),
                ansi.reset,
            },
        );
        return switch (kind) {
            .cmd_bar => fmt.comptimePrint(
                "{s} | {s} | {s} | {s}",
                .{
                    focus_display,
                    see_cmds,
                    cmd_history,
                    exit,
                },
            ),
            .display => fmt.comptimePrint(
                "{s} | {s} | {s}",
                .{
                    focus_cmd_bar,
                    auto_scroll,
                    exit,
                },
            ),
        };
    }
};

/// Display
pub const Display = struct {
    /// Base Allocator
    alloc: mem.Allocator,
    /// Arena Memory for long-term storage of this Display
    arena: *heap.ArenaAllocator,
    /// Shortcut to `arena.allocator()`
    a_alloc: mem.Allocator,
    /// Mutext
    mutex: Thread.Mutex,
    /// Parent Shell
    shell: ?*Shell = null,
    /// Original Log Context for restoration on `deinit()`
    og_log_ctx: *ui.log.Context,
    /// List of Messages in this Display
    msgs: ThreadArrayList(Message) = .empty,
    /// Allow Filter for Visible Messages
    allow_filters: []Message.Filter = &.{},
    /// Block Filter for Visible Messages
    block_filters: []Message.Filter = &.{},
    /// Filtered Messages
    filtered_msgs: []Message = &.{},
    /// Stdin for this Display
    in_writer: Io.Writer,
    /// Stdout for this Display
    out_writer: Io.Writer,
    /// Log for this Display
    log_writer: Io.Writer,
    /// Log Context
    log_ctx: ui.log.Context,
    /// Current Log Level for the next Item's Meta Data
    cur_log_level: log.Level = .debug,
    /// Current Scope for the next Item's Meta Data
    cur_log_scope: []const u8 = "",
    /// Tick Interval in ms
    tick_interval: u32 = 200,
    /// Scroll Bars Widget
    scroll_bars: vxfw.ScrollBars,
    /// List View
    //list_view: vxfw.ListView,
    /// Auto Scroll
    auto_scroll: bool = true,
    /// Auto Scroll Ticks
    auto_scroll_ticks: u4 = 0,
    /// Scroll Diff
    scroll_diff: usize = 0,
    /// Border
    border: vxfw.Border,
 
    pub const Message = struct {
        timestamp: zeit.Time,
        tag: Tag,
        scope: []const u8,
        text: []const u8,
        wrap_lines: bool = true,

        pub const Tag = enum {
            in,
            out,
            debug,
            info,
            warn,
            err,
        };

        pub const Filter = struct {
            tag: ?Tag = null,
            scope: ?[]const u8 = null,
            text: ?[]const u8 = null,
        };

        /// Get the `vxfw.Widget` for this Message
        pub fn widget(self: *@This()) vxfw.Widget {
            return .{
                .userdata = self,
                .drawFn = @This().drawTypeErased,
            };
        }

        /// Draw this Message
        pub fn draw(self: *@This(), ctx: vxfw.DrawContext) mem.Allocator.Error!vxfw.Surface {
            //if (builtin.mode != .Debug) {
            //    return .{
            //        .size = .{},
            //        .widget = self.widget(),
            //        .buffer = &.{},
            //        .children = &.{},
            //    };
            //}
            const oom: mem.Allocator.Error = error.OutOfMemory;
            const db_cfg = ansi.fg.rgb(.from(art.disco_blue));
            const disco_blue: []const u8 = db_cfg.buf[0..db_cfg.len];
            // Meta Prefix
            const meta_text = metaText: {
                // Writer Setup
                var meta_writer: Io.Writer.Allocating = .init(ctx.arena);
                errdefer meta_writer.deinit();
                const meta_w = &meta_writer.writer;
                // Format Setup
                const time_fmt: []const u8 = switch (builtin.mode) {
                    .Debug => "%H:%M:%S:%f",
                    else => "%T",
                };
                const tag_color: []const u8 = switch (self.tag) {
                    .debug => ansi.fg.blue,
                    .info => ansi.fg.green,
                    .warn => ansi.fg.yellow,
                    .err => ansi.fg.red,
                    .in => disco_blue,
                    else => ansi.fg.gray,
                };
                var up_buf: [6]u8 = undefined;
                const tag_upper: []const u8 = ascii.upperString(up_buf[0..], @tagName(self.tag));
                var scope_buf: [32]u8 = undefined;
                const scope_fmt = //
                    if (self.scope.len > 0) //
                        fmt.bufPrint(scope_buf[0..], "({s}):", .{ self.scope }) catch return oom //
                    else "";
                // Write Meta
                meta_w.writeAll(ansi.fmt.bold) catch return oom;
                self.timestamp.strftime(meta_w, time_fmt) catch return oom;
                meta_w.print(
                    " {s}{s: <5}{s}{s} {s}",
                    .{
                        tag_color,
                        tag_upper,
                        ansi.reset,
                        ansi.fmt.bold,
                        scope_fmt,
                    },
                ) catch return oom;
                break :metaText meta_writer.written();
            };
            const meta_width: u16 = //
                if (builtin.mode == .Debug) 38 //
                else 33;
            const meta_rich = ui.tui.ansiToSegments(ctx.arena, meta_text) catch return oom;
            const meta_widget: vxfw.RichText = .{ .text = meta_rich };
            const meta_surf: vxfw.SubSurface = .{
                .origin = .{ .row = 0, .col = 0 },
                .surface = try meta_widget.draw(ctx.withConstraints(
                    .{ .width = @truncate(meta_text.len), .height = 1 },
                    .{ .width = meta_width, .height = 1 },
                )),
            };
            // Message Text
            const msg_text: []const u8 = msgText: {
                switch (self.tag) {
                    .in, .out => break :msgText try fmt.allocPrint(
                        ctx.arena,
                        "{s}{s}{s}",
                        .{
                            if (self.tag == .in) disco_blue //
                            else ansi.fmt.bold,
                            self.text,
                            ansi.reset,
                        },
                    ),
                    else => break :msgText self.text,
                }
            };
            const text_rich = ui.tui.ansiToSegments(ctx.arena, msg_text) catch return oom;
            const text_widget: vxfw.RichText = .{ .text = text_rich, .softwrap = self.wrap_lines };
            //const text_widget: vxfw.Text = .{ .text = "Release Test" };
            const text_surf: vxfw.SubSurface = .{
                .origin = .{ .row = 0, .col = meta_width + 1 },
                .surface = try text_widget.draw(ctx.withConstraints(
                    ctx.min,
                    if (self.wrap_lines) .{
                        .width = ctx.min.width -| meta_width,
                        .height = ctx.max.height,
                    }
                    else .{
                        .width = //
                            if (ctx.max.width) |w| w -| (meta_width) //
                            else null,
                        .height = ctx.max.height,
                    },
                )),
            };
            // Draw Message
            const children = try ctx.arena.alloc(vxfw.SubSurface, 2);
            children[0] = meta_surf;
            children[1] = text_surf;
            return .{
                .size = .{
                    .width = (meta_width) + text_surf.surface.size.width,
                    .height = @max(meta_surf.surface.size.height, text_surf.surface.size.height),
                },
                .widget = self.widget(),
                .buffer = &.{},
                .children = children,
            };
        }

        fn drawTypeErased(ptr: *anyopaque, ctx: vxfw.DrawContext) mem.Allocator.Error!vxfw.Surface {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            return try self.draw(ctx);
        }
    };

    /// Initialize a new Display
    pub fn init(alloc: mem.Allocator) mem.Allocator.Error!*@This() {
        const self: *@This() = try alloc.create(@This());
        const arena: *heap.ArenaAllocator = try alloc.create(heap.ArenaAllocator);
        arena.* = .init(alloc);
        self.* = .{
            .alloc = alloc,
            .arena = arena,
            .a_alloc = arena.allocator(),
            .mutex = .{},
            .og_log_ctx = ui.log.contexts[0] orelse @panic("No Stdout?"),
            .in_writer = .{
                .vtable = &.{
                    .drain = inDrain,
                },
                .buffer = try alloc.alloc(u8, 4096),
            },
            .out_writer = .{
                .vtable = &.{
                    .drain = outDrain,
                },
                .buffer = try alloc.alloc(u8, 4096),
            },
            .log_writer = .{
                .vtable = &.{
                    .drain = logDrain,
                },
                .buffer = try alloc.alloc(u8, 4096),
            },
            .log_ctx = undefined,
            .scroll_bars = undefined,
            //.list_view = undefined,
            .border = undefined,
        };
        self.log_ctx = .{
            .writer = &self.log_writer,
            .ansi = true,
            .timestamps = false,
            .meta_prefix = false,
            .start_fn = logMetaStart,
            .end_fn = logMetaEnd,
        };
        self.scroll_bars = .{
            .scroll_view = .{
                .children = .{
                    .builder = .{
                        .userdata = self,
                        .buildFn = msgWidget,
                    },
                },
            },
            .estimated_content_height = 50,
        };
        //self.list_view = .{
        //    .children = .{
        //        .builder = .{
        //            .userdata = self,
        //            .buildFn = msgWidget,
        //        },
        //    },
        //};
        self.border = .{
            .child = self.scroll_bars.widget(),
            //.child = self.list_view.widget(),
            .style = .{ .dim = true },
        };
        ui.log.contexts[0] = &self.log_ctx;
        debug("Initialized REPL Display", .{});
        return self;
    }

    /// Deinitialize this Display
    pub fn deinit(self: *@This()) void {
        ui.log.contexts[0] = self.og_log_ctx;
        inline for (&.{ self.allow_filters, self.block_filters }) |filters| {
            for (filters) |filter| {
                if (filter.scope) |scope|
                    self.alloc.free(scope);
                if (filter.text) |text|
                    self.alloc.free(text);
            }
            self.alloc.free(filters);
        }
        self.alloc.free(self.filtered_msgs);
        self.alloc.free(self.in_writer.buffer);
        self.alloc.free(self.out_writer.buffer);
        self.alloc.free(self.log_writer.buffer);
        self.arena.deinit();
        self.alloc.destroy(self.arena);
        self.alloc.destroy(self);
    }

    /// Get a Vaxis Framework (vxfw) Widget from this Display
    pub fn widget(self: *@This()) vxfw.Widget {
        return .{
            .userdata = self,
            .captureHandler = handleEventTypeErased,
            .eventHandler = handleEventTypeErased,
            .drawFn = drawTypeErased,
        };
    }

    /// Get the Widget for the Message at `idx`.
    pub fn msgWidget(ptr: *const anyopaque, idx: usize, _: usize) ?vxfw.Widget {
        const self: *const @This() = @ptrCast(@alignCast(ptr));
        if (idx >= self.filtered_msgs.len)
            return null;
        return self.filtered_msgs[idx].widget();
    }

    /// Handle Events on this Display
    pub fn handleEvent(self: *@This(), ctx: *vxfw.EventContext, event: vxfw.Event) !void {
        switch (event) {
            .mouse => |mouse| switch (mouse.button) {
                .wheel_down, .wheel_up => {
                    self.auto_scroll_ticks = 0;
                    self.auto_scroll = false;
                },
                .left => {
                    if (self.shell) |shell|
                        shell.active = .display;
                },
                else => {},
            },
            .key_press => |key| {
                if (key.matches(vaxis.Key.end, .{}))
                    self.auto_scroll = true;
            },
            .tick => {
                self.filtered_msgs = filteredMsgs: {
                    self.alloc.free(self.filtered_msgs);
                    self.msgs.mutex.lock();
                    defer self.msgs.mutex.unlock();
                    // TODO: Reduce the need for constant reallocations if we're not filtering
                    if (self.allow_filters.len == 0 and self.block_filters.len == 0)
                        break :filteredMsgs try self.alloc.dupe(Message, self.msgs.list.items);
                    var msg_list: ArrayList(Message) = .empty;
                    msgs: for (self.msgs.list.items) |msg| {
                        for (self.block_filters) |filter| {
                            const match_tag: bool = match: {
                                const f_tag = filter.tag orelse break :match true;
                                break :match msg.tag == f_tag;
                            };
                            const match_scope: bool = match: {
                                const f_scope = filter.scope orelse break :match true;
                                break :match mem.eql(u8, msg.scope, f_scope);
                            };
                            const match_text: bool = match: {
                                const f_text = filter.text orelse break :match true;
                                break :match mem.indexOf(u8, msg.text, f_text) != null;
                            };
                            if (match_tag and match_scope and match_text)
                                continue :msgs;
                        }
                        var allowed: bool = self.allow_filters.len == 0;
                        for (self.allow_filters) |filter| {
                            const match_tag: bool = match: {
                                const f_tag = filter.tag orelse break :match true;
                                break :match msg.tag == f_tag;
                            };
                            const match_scope: bool = match: {
                                const f_scope = filter.scope orelse break :match true;
                                break :match mem.eql(u8, msg.scope, f_scope);
                            };
                            const match_text: bool = match: {
                                const f_text = filter.text orelse break :match true;
                                break :match mem.indexOf(u8, msg.text, f_text) != null;
                            };
                            allowed = allowed or (match_tag and match_scope and match_text);
                        }
                        if (!allowed)
                            continue :msgs;
                        try msg_list.append(self.alloc, msg);
                        continue :msgs;
                    }
                    break :filteredMsgs try msg_list.toOwnedSlice(self.alloc);
                };
                //self.list_view.item_count = @truncate(self.filtered_msgs.len);
                //self.scroll_diff = (self.list_view.item_count.? -| self.list_view.scroll.top);
                ////debug("Scroll Diff: {d}", .{ self.scroll_diff });
                //if (self.scroll_diff <= 100)
                //    self.auto_scroll_ticks +|= 1;
                //self.auto_scroll = self.auto_scroll_ticks >= 3;
                //if (self.auto_scroll) {
                //    self.list_view.cursor = @truncate(self.filtered_msgs.len -| 1);
                //    self.list_view.ensureScroll();
                //    try ctx.queueRefresh();
                //}
                self.scroll_bars.scroll_view.item_count = @truncate(self.filtered_msgs.len);
                self.scroll_bars.estimated_content_height = @as(u32, @truncate(self.filtered_msgs.len * 10));
                self.scroll_diff = (self.scroll_bars.scroll_view.item_count.? -| self.scroll_bars.scroll_view.scroll.top);
                //debug("Scroll Diff: {d}", .{ self.scroll_diff });
                if (self.scroll_diff <= 10)
                    self.auto_scroll_ticks +|= 1;
                if (self.auto_scroll_ticks >= 150)
                    self.auto_scroll = true;
                if (self.auto_scroll) {
                    self.scroll_bars.scroll_view.cursor = @truncate(self.filtered_msgs.len -| 1);
                    self.scroll_bars.scroll_view.ensureScroll();
                    try ctx.queueRefresh();
                }
            },
            else => {},
        }
    }

    /// Draw this Display
    pub fn draw(self: *@This(), ctx: vxfw.DrawContext) mem.Allocator.Error!vxfw.Surface {
        //self.scroll_diff = self.msgs.list.items.len -| self.scroll_bars.scroll_view.scroll.top;
        const max = ctx.max.size();
        if (self.shell) |shell| {
            self.border.style = switch(shell.active) {
                .display => .{ .fg = .{ .rgb = art.disco_blue } },
                .cmd_bar => .{ .dim = true },
            };
        }
        const border: vxfw.SubSurface = .{
            .origin = .{ .row = 0, .col = 0 },
            .surface = try self.border.draw(ctx),
        };
        const children = try ctx.arena.alloc(vxfw.SubSurface, 1);
        children[0] = border;
        return .{
            .size = max,
            .widget = self.widget(),
            .buffer = &.{},
            .children = children,
        };
    }

    fn handleEventTypeErased(ptr: *anyopaque, ctx: *vxfw.EventContext, event: vxfw.Event) anyerror!void {
        const self: *@This() = @ptrCast(@alignCast(ptr));
        try self.handleEvent(ctx, event);
    }

    fn drawTypeErased(ptr: *anyopaque, ctx: vxfw.DrawContext) mem.Allocator.Error!vxfw.Surface {
        const self: *@This() = @ptrCast(@alignCast(ptr));
        return try self.draw(ctx);
    }

    fn msgDrain(
        self: *Io.Writer,
        data: []const []const u8,
        tag: Message.Tag,
        scope: []const u8,
    ) Io.Writer.Error!usize {
        var display: *@This() = switch (tag) {
            .in => @fieldParentPtr("in_writer", self),
            .out => @fieldParentPtr("out_writer", self),
            else => @fieldParentPtr("log_writer", self),
        };
        //display.mutex.lock();
        //defer display.mutex.unlock();
        const instant = zeit.instant(.{ .timezone = ui.log.timezone orelse &zeit.utc }) catch @panic("Missing Time Source!");
        const timestamp = instant.time();
        var alloc_w: Io.Writer.Allocating = .init(display.a_alloc);
        errdefer alloc_w.deinit();
        const w = &alloc_w.writer;
        w.writeAll(self.buffered()) catch return Io.Writer.Error.WriteFailed;
        for (data) |text|
            w.writeAll(text) catch return Io.Writer.Error.WriteFailed;
        const text = alloc_w.toOwnedSlice() catch return Io.Writer.Error.WriteFailed;
        const msg: Message = .{
            .timestamp = timestamp,
            .tag = tag,
            .scope = scope,
            .text = text,
        };
        display.msgs.append(display.a_alloc, msg) catch return Io.Writer.Error.WriteFailed;
        return text.len;
    }

    fn inDrain(self: *Io.Writer, data: []const []const u8, _: usize) Io.Writer.Error!usize {
        defer self.end = 0;
        return msgDrain(self, data, .in, "");
    }

    fn outDrain(self: *Io.Writer, data: []const []const u8, _: usize) Io.Writer.Error!usize {
        defer self.end = 0;
        return msgDrain(self, data, .out, "");
    }

    fn logDrain(self: *Io.Writer, data: []const []const u8, _: usize) Io.Writer.Error!usize {
        defer self.end = 0;
        const display: *@This() = @fieldParentPtr("log_writer", self);
        const tag: Message.Tag = switch (display.cur_log_level) {
            .debug => .debug,
            .info => .info,
            .warn => .warn,
            .err => .err,
        };
        return msgDrain(self, data, tag, display.cur_log_scope);
    }
 
    fn logMetaStart(
        ctx: *ui.log.Context,
        level: log.Level,
        scope: []const u8,
    ) void {
        const self: *@This() = @fieldParentPtr("log_ctx", ctx);
        self.mutex.lock();
        self.cur_log_level = level;
        self.cur_log_scope = scope;
    }

    fn logMetaEnd(
        ctx: *ui.log.Context,
        _: log.Level,
        _: []const u8,
    ) void {
        const self: *@This() = @fieldParentPtr("log_ctx", ctx);
        self.mutex.unlock();
    }
};

/// Command Bar for User Input
pub const CommandBar = struct {
    /// Parent Shell
    shell: ?*Shell = null,
    /// Arena Allocator
    arena: *heap.ArenaAllocator,
    /// Shortcut to `arena.allocator()`
    a_alloc: mem.Allocator,
    /// Request ID List
    req_list: ArrayList(usize) = .empty,
    ///// Border
    //border: vxfw.Border,
    /// Prompt Text
    prompt_text: []const u8 = "🪩DisCo :",
    /// Prompt
    prompt: vxfw.TextField,
    /// Text Field
    textfield: vxfw.TextField,
    /// Command History
    history: ArrayList([]const u8) = .empty,
    /// Command History Index
    hist_idx: ?usize = null,


    /// Initialize a new CommandBar
    pub fn init(alloc: mem.Allocator) mem.Allocator.Error!*@This() {
        const self = try alloc.create(@This());
        const arena = try alloc.create(heap.ArenaAllocator);
        arena.* = .init(alloc);
        self.* = .{
            .arena = arena,
            .a_alloc = arena.allocator(),
            //.border = .{ .child = undefined },
            .prompt = .init(alloc),
            .textfield = .init(alloc),
        };
        self.textfield.onChange = onChange;
        self.textfield.onSubmit = onSubmit;
        try self.prompt.insertSliceAtCursor(self.prompt_text);
        //self.border.child = self.textfield.widget();
        //self.border.style = .{ .italic = true, .fg = .{ .rgb = art.disco_blue } };
        //self.border.labels = &.{ .{ .text = "DisCo", .alignment = .top_left } };
        return self;
    }

    /// Deinitialize this Command Bar
    pub fn deinit(self: *@This()) void {
        const alloc = self.arena.child_allocator;
        if (self.shell) |shell|
            self.req_list.deinit(shell.core_ctx.alloc);
        self.prompt.deinit();
        self.textfield.deinit();
        self.arena.deinit();
        alloc.destroy(self.arena);
        alloc.destroy(self);
    }

    /// Get a Vaxis Framework (vxfw) Widget from this Command Bar
    pub fn widget(self: *@This()) vxfw.Widget {
        return .{
            .userdata = self,
            .captureHandler = handleEventTypeErased,
            .eventHandler = handleEventTypeErased,
            .drawFn = drawTypeErased,
        };
    }

    /// Handle Events on this Command Bar
    pub fn handleEvent(self: *@This(), ctx: *vxfw.EventContext, event: vxfw.Event) !void {
        switch (event) {
            .tick => tick: {
                try ctx.requestFocus(self.textfield.widget());
                const shell = self.shell orelse break :tick;
                const core_ctx = shell.core_ctx;
                const req_ids = try self.req_list.toOwnedSlice(core_ctx.alloc);
                defer core_ctx.alloc.free(req_ids);
                for (req_ids) |req_id| {
                    log.debug("Parsing Response: {d}", .{ req_id });
                    const sep: []const u8 = "------------------------------\n";
                    const req = core_ctx.req_aggregator.get(req_id) orelse {
                        try self.req_list.append(core_ctx.alloc, req_id);
                        continue;
                    };
                    const resp = req catch |err| {
                        log.err("Request Error: {t}", .{ err });
                        continue;
                    };
                    defer resp.deinit(core_ctx.alloc);
                    switch (resp) {
                        .ack => {
                            log.debug("Ack from Request {d}", .{ req_id });
                        },
                        .interfaces => |if_resp| switch (if_resp) {
                            .single => |resp_if| {
                                const out_if = resp_if orelse continue;
                                try shell.display.out_writer.print("{f}", .{ fmt.alt(out_if, .formatANSI) });
                                try shell.display.out_writer.flush();
                            },
                            .list => |resp_ifs| respIFs: {
                                if (resp_ifs.len == 0)
                                    break :respIFs;
                                try shell.display.out_writer.print("Interfaces ({d}):\n{s}", .{ resp_ifs.len, sep });
                                for (resp_ifs) |resp_if| {
                                    try shell.display.out_writer.print("{f}{s}", .{ fmt.alt(resp_if, .formatANSI), sep });
                                }
                                try shell.display.out_writer.flush();
                            },
                        },
                        .networks => |net_resp| switch (net_resp) {
                            .list => |resp_nets| respNets: {
                                if (resp_nets.len == 0)
                                    break :respNets;
                                try shell.display.out_writer.print("Networks ({d}):\n{s}", .{ resp_nets.len, sep });
                                for (resp_nets, 0..) |resp_net, idx| {
                                    try shell.display.out_writer.print("{f}{s}", .{ fmt.alt(resp_net, .formatANSI), sep });
                                    if (idx % 5 == 0)
                                        try shell.display.out_writer.flush();
                                }
                                try shell.display.out_writer.flush();
                            },
                            else => {},
                        },
                        .connections => |conn_resp| switch (conn_resp) {
                            .list => |resp_conns| respconns: {
                                if (resp_conns.len == 0)
                                    break :respconns;
                                try shell.display.out_writer.print("Connections ({d}):\n{s}", .{ resp_conns.len, sep });
                                for (resp_conns, 0..) |resp_conn, idx| {
                                    try shell.display.out_writer.print("{f}{s}", .{ fmt.alt(resp_conn, .formatANSI), sep });
                                    if (idx % 5 == 0)
                                        try shell.display.out_writer.flush();
                                }
                                try shell.display.out_writer.flush();
                            },
                        },
                        //else => {},
                    }
                }
            },
            .mouse => |mouse| switch (mouse.button) {
                .left => {
                    if (self.shell) |shell|
                        shell.active = .cmd_bar;
                },
                else => {},
            },
            .key_press => |key| key: {
                if (key.matchesAny(&.{ vaxis.Key.up, vaxis.Key.down }, .{})) {
                    const hist_len = self.history.items.len;
                    if (hist_len == 0)
                        break :key;
                    if (key.matches(vaxis.Key.up, .{})) {
                        if (self.hist_idx) |*idx| {
                            idx.* +|= 1;
                            idx.* = @min(hist_len - 1, idx.*);
                        } //
                        else
                            self.hist_idx = 0;
                    }
                    if (key.matches(vaxis.Key.down, .{})) {
                        if (self.hist_idx) |*idx| {
                            if (idx.* == 0) //
                                self.hist_idx = null //
                            else //
                                idx.* -|= 1;
                        }
                    }
                    self.textfield.clearAndFree();
                    const hist_item: []const u8 = //
                        if (self.hist_idx) |idx| self.history.items[idx] //
                        else "";
                    try self.textfield.insertSliceAtCursor(hist_item);
                    ctx.consumeAndRedraw();
                }
                if (key.matchesAny(&.{ vaxis.Key.left, vaxis.Key.right }, .{ .ctrl = true })) {
                    if (key.matches(vaxis.Key.left, .{ .ctrl = true }))
                        self.textfield.moveBackwardWordwise();
                    if (key.matches(vaxis.Key.right, .{ .ctrl = true }))
                        self.textfield.moveForwardWordwise();
                    ctx.consume_event = true;
                }
            },
            else => {},
        }
    }

    /// Draw this Command Bar
    pub fn draw(self: *@This(), ctx: vxfw.DrawContext) mem.Allocator.Error!vxfw.Surface {
        const max = ctx.max.size();
        if (self.shell) |shell| {
            switch (shell.active) {
                .cmd_bar => {
                    self.textfield.style = .{};
                    self.textfield.style.bg = .{ .rgb = art.disco_blue };
                    self.textfield.style.fg = .{ .rgb = @splat(10) };
                    self.prompt.style = .{ .bold = true, .italic = true };
                    self.prompt.style.bg = .{ .rgb = art.disco_blue };
                    self.prompt.style.fg = .{ .rgb = @splat(10) };
                },
                else => {
                    self.textfield.style = .{};
                    self.textfield.style.dim = true;
                    self.prompt.style = .{ .bold = true, .italic = true };
                    self.prompt.style.dim = true;
                    self.prompt.style.blink = true;
                },
            }
        }
        const pt_len: u16 = @truncate(self.prompt_text.len);
        const prompt_surf: vxfw.SubSurface = .{
            .origin = .{ .row = 0, .col = 0 },
            .surface = try self.prompt.draw(ctx.withConstraints(
                .{ .width = pt_len, .height = 1 },
                .{ .width = pt_len, .height = 1 },
            )),
        };
        const textfield_surf: vxfw.SubSurface = .{
            .origin = .{ .row = 0, .col = pt_len -| 1 },
            .surface = try self.textfield.draw(ctx.withConstraints(
                .{ .width = max.width, .height = 1 },
                .{ .width = max.width, .height = 1 },
            )),
        };
        const children = try ctx.arena.alloc(vxfw.SubSurface, 2);
        children[0] = prompt_surf;
        children[1] = textfield_surf;
        return .{
            .size = max,
            .widget = self.widget(),
            .buffer = &.{},
            .children = children,
        };
    }

    fn handleEventTypeErased(ptr: *anyopaque, ctx: *vxfw.EventContext, event: vxfw.Event) anyerror!void {
        const self: *@This() = @ptrCast(@alignCast(ptr));
        try self.handleEvent(ctx, event);
    }

    fn drawTypeErased(ptr: *anyopaque, ctx: vxfw.DrawContext) mem.Allocator.Error!vxfw.Surface {
        const self: *@This() = @ptrCast(@alignCast(ptr));
        return try self.draw(ctx);
    }

    fn onChange(ptr: ?*anyopaque, ctx: *vxfw.EventContext, input: []const u8) !void {
        _ = ptr;
        _ = input;
        try ctx.queueRefresh();
        //const self_ptr: **@This() = @ptrCast(@alignCast(_self orelse return));
        //const self = self_ptr.*;
    }

    fn onSubmit(ptr: ?*anyopaque, ctx: *vxfw.EventContext, input: []const u8) !void {
        // Get Pointers
        if (ptr == null)
            debug("Null TextField Pointer?", .{});
        const self_ptr: **@This() = @ptrCast(@alignCast(ptr orelse return));
        const self = self_ptr.*;
        //const shell: *Shell = @fieldParentPtr("cmd_bar", self_ptr);
        const shell = self.shell orelse return error.NoShell;
        // Parse Arguments
        var main_cmd = try setup_cmd.init(self.a_alloc, .{  });
        defer main_cmd.deinit();
        const args = cova.tokenizeArgs(input, ctx.alloc, .{}) catch |err| {
            log.err("Couldn't Tokenize Arguments `{s}`: {t}", .{ input, err });
            return;
        };
        defer ctx.alloc.free(args);
        var args_iter: cova.ArgIteratorGeneric = .{ .raw = .{ .args = @ptrCast(args) } };
        defer args_iter.deinit();
        const out_w = &shell.display.out_writer;
        cova.parseArgs(
            &args_iter,
            main_cli.CommandT,
            main_cmd,
            out_w,
            .{
                .skip_first_arg = false,
                .auto_flush = false,
            },
        ) catch |err| {
            defer out_w.flush() catch {};
            switch (err) {
                error.UsageHelpCalled => {
                    if (mem.indexOf(u8, input, "help") == null)
                        return;
                    try self.addInput(input);
                    ctx.consumeAndRedraw();
                    return;
                },
                else => {
                    log.err("CLI Parsing Error: {t}", .{ err });
                    return;
                },
            }
        };
        // Analyze Arguments
        if (main_cmd.checkFlag("exit")) {
            ctx.quit = true;
            return;
        }
        const core_ctx = shell.core_ctx;
        var out_msg: ?[]const u8 = null;
        // - Display Filters
        if (main_cmd.matchSubCmd("filter")) |filter_cmd| {
            const dp_alloc = shell.display.alloc;
            if (filter_cmd.matchSubCmd("clear")) |clear_cmd| {
                //inline for (&.{ &shell.display.allow_filters, &shell.display.block_filters }) |filters| cont: {
                const filter_kinds: []const []const u8 = &.{ "allow", "block" };
                for (filter_kinds) |f_kind| {
                    if ( //
                        !clear_cmd.checkFlag(f_kind) and //
                        clear_cmd.checkOpts(filter_kinds, .{}) //
                    ) {
                        continue;
                    }
                    const filters = filters: {
                        if (mem.eql(u8, f_kind, "allow")) //
                            break :filters &shell.display.allow_filters //
                        else //
                            break :filters &shell.display.block_filters;
                    };
                    for (filters.*) |filter| {
                        if (filter.scope) |scope|
                            dp_alloc.free(scope);
                        if (filter.text) |text|
                            dp_alloc.free(text);
                    }
                    dp_alloc.free(filters.*);
                    filters.* = &.{};
                }
                out_msg = "Cleared Log Message Filters";
            }
            if (filter_cmd.matchSubCmd("allow")) |add_cmd| {
                var filter: Display.Message.Filter = try add_cmd.to(Display.Message.Filter, .{});
                if (filter.scope) |scope|
                    filter.scope = try dp_alloc.dupe(u8, scope);
                if (filter.text) |text|
                    filter.text = try dp_alloc.dupe(u8, text);
                var filter_list: ArrayList(Display.Message.Filter) = .fromOwnedSlice(shell.display.allow_filters);
                try filter_list.append(dp_alloc, filter);
                shell.display.allow_filters = try filter_list.toOwnedSlice(dp_alloc);
                out_msg = "Added Log Message Allow Filter";
            }
            if (filter_cmd.matchSubCmd("block")) |block_cmd| {
                var filter: Display.Message.Filter = try block_cmd.to(Display.Message.Filter, .{});
                if (filter.scope) |scope| //
                    filter.scope = try dp_alloc.dupe(u8, scope);
                if (filter.text) |text| //
                    filter.text = try dp_alloc.dupe(u8, text);
                var filter_list: ArrayList(Display.Message.Filter) = .fromOwnedSlice(shell.display.block_filters);
                try filter_list.append(dp_alloc, filter);
                shell.display.block_filters = try filter_list.toOwnedSlice(dp_alloc);
                out_msg = "Added Log Message Block Filter";
            }
        }
        // - Lists
        if (main_cmd.matchSubCmd("list")) |list_cmd| {
            const list_opts = try list_cmd.getOpts(.{});
            if (list_opts.get("interface")) |if_opt| ifOpt: {
                const if_name = ifName: {
                    const if_name = try if_opt.val.getAs([]const u8);
                    break :ifName try core_ctx.alloc.dupe(u8, if_name);
                };
                errdefer core_ctx.alloc.free(if_name);
                const req_id = core_ctx.req_aggregator.push(.{ .interfaces = .{ .get = .{ .name = if_name } } }) catch |err| {
                    log.err("Unable to request Interface Info: {t}", .{ err });
                    break :ifOpt;
                };
                try self.req_list.append(core_ctx.alloc, req_id);
                log.debug("Requested Interface '{s}'. Req ID: {d}", .{ if_name, req_id });
            }
            if (list_cmd.checkFlag("interfaces")) ifOpt: {
                const req_id = core_ctx.req_aggregator.push(.{ .interfaces = .get_all }) catch |err| {
                    log.err("Unable to request Interface Info: {t}", .{ err });
                    break :ifOpt;
                };
                try self.req_list.append(core_ctx.alloc, req_id);
                log.debug("Requested Interfaces. Req ID: {d}", .{ req_id });
            }
            if (list_cmd.checkFlag("networks")) netOpt: {
                const req_id = core_ctx.req_aggregator.push(.{ .networks = .get_all }) catch |err| {
                    log.err("Unable to request Network Info: {t}", .{ err });
                    break :netOpt;
                };
                try self.req_list.append(core_ctx.alloc, req_id);
                log.debug("Requested Networks. Req ID: {d}", .{ req_id });
            }
            if (list_cmd.checkFlag("connections")) connOpt: {
                const req_id = core_ctx.req_aggregator.push(.{ .connections = .get_all }) catch |err| {
                    log.err("Unable to request Connection Info: {t}", .{ err });
                    break :connOpt;
                };
                try self.req_list.append(core_ctx.alloc, req_id);
                log.debug("Requested Connections. Req ID: {d}", .{ req_id });
            }
        }
        // - Activate/Deactivate Interfaces
        if (main_cmd.matchSubCmd("activate")) |act_cmd| {
            const act_vals = try act_cmd.getVals(.{});
            const act_ifs_val = act_vals.get("interface").?;
            const if_names = try act_ifs_val.getAllAs([]const u8);
            for (if_names) |if_name| {
                const act_req: core.requests.Request = .{
                    .interfaces = .{
                        .usage = .{
                            .if_id = .{ .name = try core_ctx.alloc.dupe(u8, if_name) },
                            .state = .activate,
                        },
                    },
                };
                const req_id = core_ctx.req_aggregator.push(act_req) catch |err| {
                    log.err("Unable to Activate Interface: {t}", .{ err });
                    continue;
                };
                try self.req_list.append(core_ctx.alloc, req_id);
                log.debug("Activating '{s}'. Req ID: {d}", .{ if_name, req_id });
            }
        }
        if (main_cmd.matchSubCmd("deactivate")) |deact_cmd| {
            const deact_vals = try deact_cmd.getVals(.{});
            const deact_if_val = deact_vals.get("interface").?;
            const if_names = try deact_if_val.getAllAs([]const u8);
            for (if_names) |if_name| {
                const act_req: core.requests.Request = .{
                    .interfaces = .{
                        .usage = .{
                            .if_id = .{ .name = try core_ctx.alloc.dupe(u8, if_name) },
                            .state = .deactivate,
                        },
                    },
                };
                const req_id = core_ctx.req_aggregator.push(act_req) catch |err| {
                    log.err("Unable to Deactivate Interface: {t}", .{ err });
                    continue;
                };
                try self.req_list.append(core_ctx.alloc, req_id);
                log.debug("Deactivating '{s}'. Req ID: {d}", .{ if_name, req_id });
            }
        }
        // - Connect
        if (main_cmd.matchSubCmd("connect")) |connect_cmd| connectCmd: {
            const connect_vals = try connect_cmd.getVals(.{});
            const raw_id = try (connect_vals.get("id").?).getAs([]const u8);
            const id: core.networks.Network.ID = id: {
                break :id //
                    if (address.parseMAC(raw_id)) |bssid| .{ .bssid = bssid } //
                    else |_| .{ .ssid = core_ctx.alloc.dupe(u8, raw_id) catch @panic("OOM") };
            };
            const connect_opts = try connect_cmd.getOpts(.{});
            const security = security: {
                const security_opt = connect_opts.get("security") orelse break :security null;
                break :security try security_opt.val.getAs(wifi.SecurityType);
            };
            const pass = pass: {
                const pass_opt = connect_opts.get("passphrase") orelse {
                    if (security != null and security.? != .open) //
                        log.err("The {t} protocol requires a passhprase.", .{ security.? }) //
                    else //
                        log.warn("No passphrase provided. This will only work with Open Networks.", .{});
                    break :pass "";
                };
                const raw_pass = try pass_opt.val.getAs([]const u8);
                break :pass core_ctx.alloc.dupe(u8, raw_pass) catch @panic("OOM");
            };
            const freqs = freqs: {
                const ch_opt = connect_opts.get("channels") orelse break :freqs null;
                if (!ch_opt.val.isSet()) break :freqs null;
                const channels = try ch_opt.val.getAllAs(usize);
                var freqs_buf = try ArrayList(u32).initCapacity(core_ctx.alloc, 1);
                for (channels) |ch|
                    try freqs_buf.append(core_ctx.alloc, @intCast(try chs.freqFromChannel(ch)));
                break :freqs try freqs_buf.toOwnedSlice(core_ctx.alloc);
            };
            defer if (freqs) |_freqs| //
                core_ctx.alloc.free(_freqs);
            const conn_req: core.requests.Request = .{
                .connections = .{
                    .add = .{
                        .id = id,
                        .passphrase = pass,
                        .security = security,
                        .dhcp = //
                            if (connect_cmd.checkFlag("dhcp")) .{} //
                            else null,
                        .add_gw = connect_cmd.checkFlag("gateway"),
                    },
                },
            };
            const req_id = core_ctx.req_aggregator.push(conn_req) catch |err| {
                log.err("Unable to Add Connection: {t}", .{ err });
                break :connectCmd;
            };
            try self.req_list.append(core_ctx.alloc, req_id);
            log.debug("Adding Connection for '{s}'. Req ID: {d}", .{ raw_id, req_id });
        }
        // - Disconnect
        if (main_cmd.matchSubCmd("disconnect")) |disconn_cmd| disconnCmd: {
            const disconn_vals = try disconn_cmd.getVals(.{});
            const raw_id = try (disconn_vals.get("id").?).getAs([]const u8);
            const id: core.networks.Network.ID = id: {
                break :id //
                    if (address.parseMAC(raw_id)) |bssid| .{ .bssid = bssid } //
                    else |_| .{ .ssid = core_ctx.alloc.dupe(u8, raw_id) catch @panic("OOM") };
            };
            const disconn_req: core.requests.Request = .{
                .connections = .{
                    .disable = id,
                },
            };
            const req_id = core_ctx.req_aggregator.push(disconn_req) catch |err| {
                log.err("Unable to Disable Connection: {t}", .{ err });
                break :disconnCmd;
            };
            try self.req_list.append(core_ctx.alloc, req_id);
            log.debug("Disabling Connection for '{s}'. Req ID: {d}", .{ raw_id, req_id });
        }
        // - Reconnect
        if (main_cmd.matchSubCmd("reconnect")) |reconn_cmd| reconnCmd: {
            const reconn_vals = try reconn_cmd.getVals(.{});
            const raw_id = try (reconn_vals.get("id").?).getAs([]const u8);
            const id: core.networks.Network.ID = id: {
                break :id //
                    if (address.parseMAC(raw_id)) |bssid| .{ .bssid = bssid } //
                    else |_| .{ .ssid = core_ctx.alloc.dupe(u8, raw_id) catch @panic("OOM") };
            };
            const reconn_req: core.requests.Request = .{
                .connections = .{
                    .enable = id,
                },
            };
            const req_id = core_ctx.req_aggregator.push(reconn_req) catch |err| {
                log.err("Unable to Re-add Connection: {t}", .{ err });
                break :reconnCmd;
            };
            try self.req_list.append(core_ctx.alloc, req_id);
            log.debug("Re-adding Connection for '{s}'. Req ID: {d}", .{ raw_id, req_id });
        }
        if (main_cmd.matchSubCmd("serve")) |serve_cmd| serveCmd: {
            const serve_req: core.requests.Request = serveReq: {
                if (serve_cmd.checkFlag("stop")) //
                    break :serveReq .{ .serve = .stop };
                const serve_opts = try serve_cmd.getOpts(.{});
                const ip = try serve_opts.get("ip").?.val.getAs(address.IPv4);
                const port = try serve_opts.get("port").?.val.getAs(u16);
                const dir = try serve_opts.get("directory").?.val.getAs([]const u8);
                const protos = try serve_opts.get("protocols").?.val.getAllAs(core.serve.Protocol);
                const conf: core.serve.Config = .{
                    .ip = ip.addr,
                    .port = port,
                    .path = self.a_alloc.dupe(u8, dir) catch @panic("OOM"),
                    .protocols = protos,
                };
                break :serveReq .{
                    .serve = .{
                        .start = conf,
                    },
                };
            };
            const req_id = core_ctx.req_aggregator.push(serve_req) catch |err| {
                log.err("Unable to Start/Stop File Server: {t}", .{ err });
                break :serveCmd;
            };
            self.req_list.append(core_ctx.alloc, req_id) catch @panic("OOM");
            log.debug("Updating File Server. Req ID: {d}", .{ req_id });
        }
        // Write Valid Arguments to Display
        try self.addInput(input);
        ctx.consumeAndRedraw();
        if (out_msg) |msg| {
            try out_w.writeAll(msg);
            try out_w.flush();
        }
    }

    /// Send the provided `input` to the Display's Input Writer and add it to History.
    pub fn addInput(self: *@This(), input: []const u8) Io.Writer.Error!void {
        const hist_item = self.a_alloc.dupe(u8, input) catch @panic("OOM");
        self.history.insert(self.a_alloc, 0, hist_item) catch @panic("OOM");
        self.hist_idx = null;
        const shell = self.shell orelse return;
        const in_w = &shell.display.in_writer;
        try in_w.writeAll(input);
        try in_w.flush();
        self.textfield.clearRetainingCapacity();
    }
};

pub const setup_cmd: main_cli.CommandT = .{
    .name = "disco-tui",
    .description = "TUI Commands for DisCo.",
    .examples = &.{
        "usage",
        "help",
        "exit",
    },
    .cmd_groups = &.{ "ACTIVE", "INTERFACE", "SETTINGS" },
    .opt_groups = &.{ "ACTIVE", "MASK", "SETTINGS" },
    .sub_cmds_mandatory = false,
    .vals_mandatory = false,
    .allow_inheritable_opts = true,
    .sub_cmds = &.{
        ui.cli.connect_cmd,
        .{
            .name = "disconnect",
            .description = "Disconnect from the specified Network.",
            .cmd_group = "ACTIVE",
            .vals = &.{
                .ofType([]const u8, .{
                    .name = "id",
                    .description = "The Network SSID (up to 32 characters) or BSSID (6 octet MAC Address) to Disconnect from.",
                    .valid_fn = struct {
                        pub fn validSSID(arg: []const u8, _: mem.Allocator) bool {
                            return arg.len > 0 and arg.len <= 32;
                        }
                    }.validSSID,
                }),
            },
        },
        .{
            .name = "reconnect",
            .description = "Reconnect to the specified Network.",
            .cmd_group = "ACTIVE",
            .vals = &.{
                .ofType([]const u8, .{
                    .name = "id",
                    .description = "The Network SSID (up to 32 characters) or BSSID (6 octet MAC Address) to Reconnect to.",
                    .valid_fn = struct {
                        pub fn validSSID(arg: []const u8, _: mem.Allocator) bool {
                            return arg.len > 0 and arg.len <= 32;
                        }
                    }.validSSID,
                }),
            },
        },
        ui.cli.serve_cmd,
        .{
            .name = "exit",
            .alias_names = &.{ "quit", "q" },
            .description = "Exit DisCo.",
        },
        .{
            .name = "filter",
            .description = "Filter Log Messages by their Tag, Scope, and Text.",
            .cmd_group = "SETTINGS",
            .examples = &.{
                "filter allow --tag info --scope 'interfaces'",
                "filter block --text 'Connected'",
                "filter clear",
            },
            .sub_cmds = &.{
                .from(Display.Message.Filter, .{
                    .cmd_name = "allow",
                    .cmd_description = "Allow Log Messages matching this Filter",
                    .sub_descriptions = msg_filter_descs,
                }),
                .from(Display.Message.Filter, .{
                    .cmd_name = "block",
                    .cmd_description = "Block Log Messages matching this Filter",
                    .sub_descriptions = msg_filter_descs,
                }),
                .{
                    .name = "clear",
                    .description = "Clear all Log Message Filters",
                    .opts = &.{
                        .{
                            .name = "allow",
                            .description = "Clear Log Message Allow Filters",
                            .short_name = 'a',
                            .long_name = "allow",
                        },
                        .{
                            .name = "block",
                            .description = "Clear Log Message Block Filters",
                            .short_name = 'b',
                            .long_name = "block",
                        },
                    },
                },
            },
        },
        .{
            .name = "list",
            .alias_names = &.{ "view" },
            .description = "List various System or DisCo properties.",
            .cmd_group = "SETTINGS",
            .vals_mandatory = false,
            .opts = &.{
                .{
                    .name = "masks",
                    .description = "List available Profile Masks.",
                    .long_name = "masks",
                },
                .{
                    .name = "conflict_pids",
                    .description = "List Conflicting Processes.",
                    .long_name = "conflict-pids",
                    .alias_long_names = &.{ "pids", "conflicts", "procs", "processes" },
                },
                .{
                    .name = "config",
                    .description = "List the Config Fields.",
                    .long_name = "config",
                    .alias_long_names = &.{ "fields" },
                },
                .{
                    .name = "interface",
                    .description = "View a specific WiFi Interfaces of the system.",
                    .long_name = "interface",
                    .alias_long_names = &.{ "if" },
                    .val = .ofType([]const u8, .{}),
                },
                .{
                    .name = "interfaces",
                    .description = "List the system's WiFi Interfaces.",
                    .long_name = "interfaces",
                    .alias_long_names = &.{ "ifs" },
                },
                .{
                    .name = "networks",
                    .description = "List the seen WiFi Networks.",
                    .long_name = "networks",
                },
                .{
                    .name = "connections",
                    .description = "List the active WiFi Connections.",
                    .long_name = "connections",
                },
            },
        },
        .{
            .name = "activate",
            .description = "Activate the provided Interface for DisCo use.",
            .cmd_group = "INTERFACE",
            .vals = &.{
                .ofType([]const u8, .{
                    .name = "interface",
                    .description = "The Interface to Activate",
                    .set_behavior = .Multi,
                    .max_entries = 10,
                }),
            },
        },
        .{
            .name = "deactivate",
            .description = "Deactivate the designated Interface from DisCo use.",
            .cmd_group = "INTERFACE",
            .vals = &.{
                .ofType([]const u8, .{
                    .name = "interface",
                    .description = "The Interface to Deactivate",
                    .set_behavior = .Multi,
                    .max_entries = 10,
                }),
            },
        },
    }
};

pub const msg_filter_descs: []const struct { []const u8, []const u8} = &.{
    .{ "tag", "The Message Tag. One of: \"debug\", \"info\", \"warn\", \"err\", \"in\", \"out\"" },
    .{ "scope", "The Message's Scope, referring to the Module it came from. (Ex: \"disco\", \"interfaces\", \"networks\", \"connnections\", etc)" },
    .{ "text", "Text that the Message contains." },
};
