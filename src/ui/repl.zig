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

const cova = @import("cova");
const vaxis = @import("vaxis");
const vxfw = vaxis.vxfw;
const zeit = @import("zeit");

const art = @import("../art.zig");
const ui = @import("../ui.zig");
const utils = @import("../utils.zig");
const ansi = utils.ansi;
const ThreadArrayList = utils.ThreadArrayList;


/// Full REPL Shell
pub const Shell = struct {
    display: *Display,
    cmd_bar: *CommandBar,
    tick_interval: u32 = 200,
    active: enum { display, cmd_bar } = .cmd_bar,

    /// Initialize a new REPL Shell
    pub fn init(alloc: mem.Allocator) mem.Allocator.Error!*@This() {
        const self = try alloc.create(@This());
        self.* = .{
            .display = try .init(alloc),
            .cmd_bar = try .init(alloc),
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
                if (key.matches(vaxis.Key.down, .{ .ctrl = true }))
                    self.active = .cmd_bar;
            },
            .tick => {
                try ctx.tick(self.tick_interval, self.widget());
                try ctx.tick(self.tick_interval, self.display.widget());
                try ctx.tick(self.tick_interval, self.cmd_bar.widget());
                if (self.display.auto_scroll)
                    try ctx.queueRefresh();
                switch (self.active) {
                    .display => try ctx.requestFocus(self.display.list_view.widget()),
                    .cmd_bar => try ctx.requestFocus(self.cmd_bar.textfield.widget()),
                }
            },
            else => {},
        }
    }

    /// Draw this REPL Shell
    pub fn draw(self: *@This(), ctx: vxfw.DrawContext) mem.Allocator.Error!vxfw.Surface {
        const max = ctx.max.size();
        const cmd_bar_height: u16 = 1;
        const display_surf: vxfw.SubSurface = .{
            .origin = .{ .row = 0, .col = 0 },
            .surface = try self.display.draw(ctx.withConstraints(
                .{ .width = ctx.min.width, .height = ctx.min.height },
                .{ .width = max.width, .height = max.height - cmd_bar_height },
            )),
        };
        const cmd_bar_surf: vxfw.SubSurface = .{
            .origin = .{ .row = max.height - cmd_bar_height, .col = 0 },
            .surface = try self.cmd_bar.draw(ctx.withConstraints(
                .{ .width = max.width, .height = cmd_bar_height },
                .{ .width = max.width, .height = cmd_bar_height },
            )),
        };
        const children = try ctx.arena.alloc(vxfw.SubSurface, 2);
        children[0] = display_surf;
        children[1] = cmd_bar_surf;
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
};

/// Display
pub const Display = struct {
    /// Arena Memory for long-term storage of this Display
    arena: heap.ArenaAllocator,
    /// Shortcut to `arena.allocator()`
    alloc: mem.Allocator,
    /// Parent Shell
    shell: ?*Shell = null,
    /// Original Log Context for restoration on `deinit()`
    og_log_ctx: *ui.log.Context,
    /// List of Messages in this Display
    msgs: ThreadArrayList(Message) = .empty,
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
    /// Current Message
    cur_msg: ?Message = null,
    /// Filter for Visible Messages
    filter: []const Message.Tag = enums.values(Message.Tag),
    /// Tick Interval in ms
    tick_interval: u32 = 200,
    ///// Scroll Bars Widget
    //scroll_bars: vxfw.ScrollBars,
    /// List View
    list_view: vxfw.ListView,
    /// Auto Scroll
    auto_scroll: bool = true,
    /// Auto Scroll Ticks
    auto_scroll_ticks: u4 = 0,
    /// Scroll Diff
    scroll_diff: usize = 0,
 
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

        /// Get the `vxfw.Widget` for this Message
        pub fn widget(self: *@This()) vxfw.Widget {
            return .{
                .userdata = self,
                .drawFn = @This().drawTypeErased,
            };
        }

        /// Draw this Message
        pub fn draw(self: *@This(), ctx: vxfw.DrawContext) mem.Allocator.Error!vxfw.Surface {
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
            const meta_width: u16 = 38;
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
                if (self.tag != .in)
                    break :msgText self.text;
                break :msgText try fmt.allocPrint(
                    ctx.arena,
                    "{s}{s}{s}",
                    .{
                        disco_blue,
                        self.text,
                        ansi.reset,
                    },
                );
            };
            const text_rich = ui.tui.ansiToSegments(ctx.arena, msg_text) catch return oom;
            const text_widget: vxfw.RichText = .{ .text = text_rich, .softwrap = self.wrap_lines };
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
        self.* = .{
            .arena = .init(alloc),
            .alloc = undefined,
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
            //.scroll_bars = undefined,
            .list_view = undefined,
        };
        self.alloc = self.arena.allocator();
        self.log_ctx = .{
            .writer = &self.log_writer,
            .ansi = true,
            .timestamps = false,
            .meta_prefix = false,
            .start_fn = logMeta,
        };
        //self.scroll_bars = .{
        //    .scroll_view = .{
        //        .children = .{
        //            .builder = .{
        //                .userdata = self,
        //                .buildFn = msgWidget,
        //            },
        //        },
        //    },
        //    .estimated_content_height = 50,
        //};
        self.list_view = .{
            .children = .{
                .builder = .{
                    .userdata = self,
                    .buildFn = msgWidget,
                },
            },
        };
        ui.log.contexts[0] = &self.log_ctx;
        debug("Initialized REPL Display", .{});
        return self;
    }

    /// Deinitialize this Display
    pub fn deinit(self: *@This()) void {
        ui.log.contexts[0] = self.og_log_ctx;
        const alloc = self.arena.child_allocator;
        alloc.free(self.in_writer.buffer);
        alloc.free(self.out_writer.buffer);
        alloc.free(self.log_writer.buffer);
        self.arena.deinit();
        alloc.destroy(self);
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
        // This `@constCast()` is safe since we have a heap allocated, stable reference to the Display.
        // The cast required to work with the `vxfw.ScrollView` API.
        const self: *@This() = @constCast(@ptrCast(@alignCast(ptr)));
        self.msgs.mutex.lock();
        defer self.msgs.mutex.unlock();
        if (idx >= self.msgs.list.items.len)
            return null;
        return self.msgs.list.items[idx].widget();
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
            .tick => {
                self.list_view.item_count = @truncate(self.msgs.list.items.len);
                self.scroll_diff = (self.list_view.item_count.? -| self.list_view.scroll.top);
                //debug("Scroll Diff: {d}", .{ self.scroll_diff });
                if (self.scroll_diff <= 100)
                    self.auto_scroll_ticks +|= 1;
                self.auto_scroll = self.auto_scroll_ticks >= 3;
                if (self.auto_scroll) {
                    self.list_view.cursor = @truncate(self.msgs.list.items.len - 1);
                    self.list_view.ensureScroll();
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
        const list_view: vxfw.SubSurface = .{
            .origin = .{ .row = 0, .col = 0 },
            .surface = try self.list_view.draw(ctx),
        };
        const children = try ctx.arena.alloc(vxfw.SubSurface, 1);
        children[0] = list_view;
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
        const instant = zeit.instant(.{ .timezone = ui.log.timezone orelse &zeit.utc }) catch @panic("Missing Time Source!");
        const timestamp = instant.time();
        var alloc_w: Io.Writer.Allocating = .init(display.alloc);
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
        display.msgs.append(display.alloc, msg) catch return Io.Writer.Error.WriteFailed;
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
    
    fn logMeta(
        ctx: *ui.log.Context,
        level: log.Level,
        scope: []const u8,
    ) void {
        const self: *@This() = @fieldParentPtr("log_ctx", ctx);
        self.cur_log_level = level;
        self.cur_log_scope = scope;
    }
};

/// Command Bar for User Input
pub const CommandBar = struct {
    /// Parent Shell
    shell: ?*Shell = null,
    ///// Border
    //border: vxfw.Border,
    /// Prompt Text
    prompt_text: []const u8 = "🪩DisCo >",
    /// Prompt
    prompt: vxfw.TextField,
    /// Text Field
    textfield: vxfw.TextField,


    /// Initialize a new CommandBar
    pub fn init(alloc: mem.Allocator) mem.Allocator.Error!*@This() {
        const self = try alloc.create(@This());
        self.* = .{
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
        self.prompt.deinit();
        self.textfield.deinit();
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
            .tick => {
                try ctx.requestFocus(self.textfield.widget());
            },
            .mouse => |mouse| switch (mouse.button) {
                .left => {
                    if (self.shell) |shell|
                        shell.active = .cmd_bar;
                },
                else => {},
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
        //const border_surf: vxfw.SubSurface = .{
        //    .origin = .{ .row = 0, .col = 0 },
        //    .surface = try self.border.draw(ctx),
        //};
        //const children = try ctx.arena.alloc(vxfw.SubSurface, 1);
        //children[0] = border_surf;
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

    fn onChange(_self: ?*anyopaque, ctx: *vxfw.EventContext, input: []const u8) !void {
        _ = _self;
        _ = input;
        try ctx.queueRefresh();
        //const self_ptr: **@This() = @ptrCast(@alignCast(_self orelse return));
        //const self = self_ptr.*;
    }

    fn onSubmit(_self: ?*anyopaque, ctx: *vxfw.EventContext, input: []const u8) !void {
        if (_self == null)
            debug("Null TextField Pointer?", .{});
        const self_ptr: **@This() = @ptrCast(@alignCast(_self orelse return));
        const self = self_ptr.*;
        const shell: *Shell = @fieldParentPtr("cmd_bar", self_ptr);
        const in_w = &shell.display.in_writer;
        try in_w.writeAll(input);
        try in_w.flush();
        self.textfield.clearRetainingCapacity();
        ctx.consumeAndRedraw();
    }
};

