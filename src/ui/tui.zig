//! TUI for DisCo

const std = @import("std");
const fmt = std.fmt;
const log = std.log;
const mem = std.mem;
const ArrayList = std.ArrayList;
const Io = std.Io;

const cova = @import("cova");
const vaxis = @import("vaxis");
const vxfw = vaxis.vxfw;

const core = @import("../core.zig");
const ui = @import("../ui.zig");
const utils = @import("../utils.zig");
const ansi = utils.ansi;


/// TUI Context
pub const Context = struct {
    /// The `vxfw.App` for the TUI.
    app: *vxfw.App,
    /// The MainWidget for the DisCo TUI.
    main: MainWidget,

    pub fn init(alloc: mem.Allocator, mode: ui.Mode, core_ctx: *core.Core) !@This() {
        return .{
            .app = try .init(alloc),
            .main = try .init(alloc, mode, core_ctx),
        };
    }

    pub fn deinit(self: *@This(), alloc: mem.Allocator) void {
        self.app.deinit();
        self.main.deinit(alloc);
    }

    pub fn run(self: *@This(), opts: vxfw.App.Options) !void {
        try self.app.run(self.main.widget(), opts);
    }
};

/// Main Widget
pub const MainWidget = union(enum) {
    repl: *ui.repl.Shell,

    pub fn init(alloc: mem.Allocator, mode: ui.Mode, core_ctx: *core.Core) mem.Allocator.Error!@This() {
        return switch (mode) {
            .repl => .{ .repl = try ui.repl.Shell.init(alloc, core_ctx) },
            else => @panic("Non-TUI Mode"),
        };
    }

    pub fn deinit(self: @This(), alloc: mem.Allocator) void {
        switch (self) {
            inline else => |main| main.deinit(alloc),
        }
    }

    pub fn widget(self: @This()) vxfw.Widget {
        return switch (self) {
            inline else => |main| main.widget(),
        };
    }
};

/// ANSI to Segments
pub fn ansiToSegments(alloc: mem.Allocator, slice: []const u8) ![]vaxis.Segment {
    var seg_list: ArrayList(vaxis.Segment) = .empty;
    var cur_seg: vaxis.Segment = .{ .text = "" };
    var alloc_w: Io.Writer.Allocating = .init(alloc);
    const w = &alloc_w.writer;
    var state: enum { search, read } = .search;
    for (slice) |c| {
        state: switch (state) {
            .search => {
                if (c != '\x1b') {
                    try w.writeByte(c);
                    continue;
                }
                if (alloc_w.written().len > 0) {
                    cur_seg.text = try alloc_w.toOwnedSlice();
                    try seg_list.append(alloc, cur_seg);
                }
                state = .read;
                continue :state state;
            },
            .read => {
                try w.writeByte(c);
                if ((c < 'A' or c > 'Z') and (c < 'a' or c > 'z'))
                    continue;
                const cur_code = try alloc_w.toOwnedSlice();
                defer alloc.free(cur_code);
                // Reset
                if (mem.eql(u8, cur_code, ansi.reset))
                    cur_seg.style = .{}
                // Format Codes
                else if (mem.eql(u8, cur_code, ansi.fmt.reset)) {
                    cur_seg.style.blink = false;
                    cur_seg.style.bold = false;
                    cur_seg.style.dim = false;
                    cur_seg.style.italic = false;
                    cur_seg.style.reverse = false;
                    cur_seg.style.strikethrough = false;
                    cur_seg.style.ul_style = .off;
                } //
                else if (mem.eql(u8, cur_code, ansi.fmt.blink))
                    cur_seg.style.blink = true
                else if (mem.eql(u8, cur_code, ansi.fmt.reset_blink))
                    cur_seg.style.blink = false
                else if (mem.eql(u8, cur_code, ansi.fmt.bold))
                    cur_seg.style.bold = true
                else if (mem.eql(u8, cur_code, ansi.fmt.reset_bold)) {
                    cur_seg.style.bold = false;
                    cur_seg.style.dim = false;
                } //
                else if (mem.eql(u8, cur_code, ansi.fmt.dim))
                    cur_seg.style.dim = true
                else if (mem.eql(u8, cur_code, ansi.fmt.italic))
                    cur_seg.style.italic = true
                else if (mem.eql(u8, cur_code, ansi.fmt.reset_italic))
                    cur_seg.style.italic = false
                else if (mem.eql(u8, cur_code, ansi.fmt.reverse))
                    cur_seg.style.reverse = true
                else if (mem.eql(u8, cur_code, ansi.fmt.reset_reverse))
                    cur_seg.style.reverse = false
                else if (mem.eql(u8, cur_code, ansi.fmt.strikethrough))
                    cur_seg.style.strikethrough = true
                else if (mem.eql(u8, cur_code, ansi.fmt.reset_strikethrough))
                    cur_seg.style.strikethrough = false
                else if (mem.eql(u8, cur_code, ansi.fmt.underline))
                    cur_seg.style.ul_style = .single
                else if (mem.eql(u8, cur_code, ansi.fmt.reset_underline))
                    cur_seg.style.ul_style = .off
                // Foreground Codes
                else if (mem.eql(u8, cur_code, ansi.fg.reset))
                    cur_seg.style.fg = .default
                else if (mem.eql(u8, cur_code, ansi.fg.black))
                    cur_seg.style.fg = .{ .rgb = [_]u8{ 0, 0, 0 } }
                else if (mem.eql(u8, cur_code, ansi.fg.blue))
                    cur_seg.style.fg = .{ .rgb = [_]u8{ 64, 128, 196 } }
                else if (mem.eql(u8, cur_code, ansi.fg.cyan))
                    cur_seg.style.fg = .{ .rgb = [_]u8{ 0, 196, 196 } }
                else if (mem.eql(u8, cur_code, ansi.fg.gray))
                    cur_seg.style.fg = .{ .rgb = [_]u8{ 128, 128, 128 } }
                else if (mem.eql(u8, cur_code, ansi.fg.green))
                    cur_seg.style.fg = .{ .rgb = [_]u8{ 0, 196, 0 } }
                else if (mem.eql(u8, cur_code, ansi.fg.magenta))
                    cur_seg.style.fg = .{ .rgb = [_]u8{ 196, 196, 0 } }
                else if (mem.eql(u8, cur_code, ansi.fg.red))
                    cur_seg.style.fg = .{ .rgb = [_]u8{ 196, 0, 0 } }
                else if (mem.eql(u8, cur_code, ansi.fg.white))
                    cur_seg.style.fg = .{ .rgb = [_]u8{ 196, 196, 0 } }
                else if (mem.eql(u8, cur_code, ansi.fg.yellow))
                    cur_seg.style.fg = .{ .rgb = [_]u8{ 196, 196, 0 } }
                // Background Codes
                else if (mem.eql(u8, cur_code, ansi.bg.reset))
                    cur_seg.style.bg = .default
                else if (mem.eql(u8, cur_code, ansi.bg.black))
                    cur_seg.style.bg = .{ .rgb = [_]u8{ 0, 0, 0 } }
                else if (mem.eql(u8, cur_code, ansi.bg.blue))
                    cur_seg.style.bg = .{ .rgb = [_]u8{ 64, 128, 196 } }
                else if (mem.eql(u8, cur_code, ansi.bg.cyan))
                    cur_seg.style.bg = .{ .rgb = [_]u8{ 0, 196, 196 } }
                else if (mem.eql(u8, cur_code, ansi.bg.gray))
                    cur_seg.style.bg = .{ .rgb = [_]u8{ 128, 128, 128 } }
                else if (mem.eql(u8, cur_code, ansi.bg.green))
                    cur_seg.style.bg = .{ .rgb = [_]u8{ 0, 196, 0 } }
                else if (mem.eql(u8, cur_code, ansi.bg.magenta))
                    cur_seg.style.bg = .{ .rgb = [_]u8{ 196, 196, 0 } }
                else if (mem.eql(u8, cur_code, ansi.bg.red))
                    cur_seg.style.bg = .{ .rgb = [_]u8{ 196, 0, 0 } }
                else if (mem.eql(u8, cur_code, ansi.bg.white))
                    cur_seg.style.bg = .{ .rgb = [_]u8{ 196, 196, 0 } }
                else if (mem.eql(u8, cur_code, ansi.bg.yellow))
                    cur_seg.style.bg = .{ .rgb = [_]u8{ 196, 196, 0 } }
                // Foreground RGB Codes
                else if (mem.startsWith(u8, cur_code, "\x1b[38;2;")) rgb: {
                    if (cur_code.len < 13)
                        break :rgb;
                    const rgb_slice = cur_code[7..];
                    var buf: [3]u8 = undefined;
                    var rgb_iter = mem.splitAny(u8, rgb_slice, ";m");
                    var i: u4 = 0;
                    while (rgb_iter.next()) |ch| : (i += 1) {
                        buf[i] = fmt.parseInt(u8, ch, 0) catch break :rgb;
                        if (i >= 2) break;
                    }
                    cur_seg.style.fg = .{ .rgb = buf };
                }
                // Background RGB Codes
                else if (mem.startsWith(u8, cur_code, "\x1b[48;2;")) rgb: {
                    if (cur_code.len < 13)
                        break :rgb;
                    const rgb_slice = cur_code[7..];
                    var buf: [3]u8 = undefined;
                    var rgb_iter = mem.splitAny(u8, rgb_slice, ";m");
                    var i: u4 = 0;
                    while (rgb_iter.next()) |ch| : (i += 1) {
                        buf[i] = fmt.parseInt(u8, ch, 0) catch break :rgb;
                        if (i >= 2) break;
                    }
                    cur_seg.style.bg = .{ .rgb = buf };
                }
                // Search for next ANSI Escape Code
                state = .search;
            }
        }
    }
    if (alloc_w.written().len > 0 and state == .search) {
        cur_seg.text = try alloc_w.toOwnedSlice();
        try seg_list.append(alloc, cur_seg);
    }
    return try seg_list.toOwnedSlice(alloc);
}

test "ansiToSegments" {
    const testing = std.testing;
    testing.log_level = .debug;

    const alloc = testing.allocator;
    var slice_buf: [100]u8 = undefined;
    const db_cfg = ansi.fg.rgb(.from(@import("../art.zig").disco_blue));
    const disco_blue: []const u8 = db_cfg.buf[0..db_cfg.len];
    const slice = try fmt.bufPrint(
        slice_buf[0..],
        "{s}Bold {s}Bold Blue {f}Bold Gray {s}{s}DisCo Blue ({d}) {s}Reset",
        .{
            ansi.fmt.bold,
            ansi.fg.blue,
            ansi.fg.rgb(.from(@splat(128))),
            ansi.reset,
            disco_blue,
            db_cfg.len,
            ansi.reset,
        },
    );
    log.debug("ANSI Test Slice: {s}", .{ slice });
    const segs = try ansiToSegments(alloc, slice);
    defer {
        for (segs, 0..) |seg, idx| {
            switch (seg.style.fg) {
                .rgb => |rgb| log.debug("seg {d}: {d}, {d}, {d}", .{ idx, rgb[0], rgb[1], rgb[2] }),
                else => {},
            }
            alloc.free(seg.text);
        }
        alloc.free(segs);
    }
    log.debug("ANSI Segs: {d}", .{ segs.len });
    try testing.expect(segs.len == 5);
    try testing.expectEqualStrings("Bold ", segs[0].text);
    try testing.expect(segs[0].style.bold);
    for (segs) |seg|
        log.debug("{s}", .{ seg.text });
}
