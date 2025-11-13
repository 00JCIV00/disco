//! Logging Setup for DisCo

const builtin = @import("builtin");
const std = @import("std");
const ascii = std.ascii;
const fmt = std.fmt;
const log = std.log;
const mem = std.mem;
const Io = std.Io;

const zeit = @import("zeit");

const utils = @import("../utils.zig");
const ansi = utils.ansi;


/// Writers to Log to
pub var contexts: [10]?*Context = @splat(null);
/// Time Zone for Timestamps
pub var timezone: ?*const zeit.TimeZone = null;

/// Log Function
pub fn logFn(
    comptime level: std.log.Level,
    comptime scope: @Type(.enum_literal),
    comptime format: []const u8,
    args: anytype,
) void {
    var idx: usize = 0;
    while (contexts[idx]) |ctx| : (idx += 1) {
        ctx.logTo(
            level,
            scope,
            format,
            args,
        );
    }
}

/// File Logging Config
pub const FileConfig = struct {
    /// Directory to write Log files to.
    dir: []const u8 = ".",
    /// Prefix for Log files.
    prefix: []const u8 = "disco_",
    /// Suffix for Log files.
    suffix: []const u8 = ".log",
    /// Max File Size in Kilobytes (KB)
    /// TODO: Implement File Rollover
    max_filesize: usize = 10_000,
    /// Log Level
    min_level: log.Level = switch (builtin.mode) {
        .Debug => .debug,
        else => .info,
    },
    /// Include Timestamps
    timestamps: bool = true,
    /// Formatting for Timestamps in `strftime` Format
    time_fmt: []const u8 = "%Y%m%dT%H%M%S-%f",
    /// Include Log Level and Scope Prefix
    meta_prefix: bool = true,
    /// Align the Timestamp, Log Level, and Scope
    meta_align: bool = true,

    /// Fill out the provided Context `ctx` using this File Config.
    pub fn fillContext(self: @This(), ctx: *Context) void {
        ctx.timestamps = self.timestamps;
        ctx.time_fmt = self.time_fmt;
        ctx.min_level = self.min_level;
        ctx.meta_prefix = self.meta_prefix;
        ctx.meta_align = self.meta_align;
    }
};

/// Logging Context for a single Writer
pub const Context = struct {
    /// Underlying Writer for Log Data
    writer: *Io.Writer,
    /// Use ANSI Escape Codes for Text Formatting & Coloring
    ansi: bool = true,
    /// Include Timestamps
    timestamps: bool = true,
    /// Formatting for Timestamps in `strftime` Format
    time_fmt: []const u8 = switch (builtin.mode) {
        .Debug => "%H:%M:%S:%f",
        else => "%T",
    },
    /// Minimum Log Level
    min_level: log.Level = switch (builtin.mode) {
        .Debug => .debug,
        else => .info,
    },
    /// Include Log Level and Scope Prefix
    meta_prefix: bool = true,
    /// Align the Timestamp, Log Level, and Scope
    meta_align: bool = true,
    /// Custom Start Function
    start_fn: ?*const fn(*@This(), log.Level, []const u8) void = null,
    /// Custom End Function
    end_fn: ?*const fn(*@This(), log.Level, []const u8) void = null,


    /// Log to a specific Writer
    pub fn logTo(
        self: *@This(),
        comptime level: log.Level,
        comptime scope: @Type(.enum_literal),
        comptime format: []const u8,
        args: anytype,
    ) void {
        if (@intFromEnum(self.min_level) < @intFromEnum(level))
            return;
        // Custom Functions
        const scope_name = @tagName(scope);
        if (self.start_fn) |startFn|
            startFn(self, level, scope_name);
        defer if (self.end_fn) |endFn|
            endFn(self, level, scope_name);
        // Writer Setup
        var filter: ansi.FilterWriter = .init(self.writer);
        const writer = //
            if (self.ansi) self.writer //
            else &filter.io_writer;
        // Format Setup
        const level_color: []const u8 = switch (level) {
            .debug => ansi.fg.blue,
            .info => ansi.fg.green,
            .warn => ansi.fg.yellow,
            .err => ansi.fg.red,
        };
        var up_buf: [6]u8 = undefined;
        const level_upper: []const u8 = ascii.upperString(up_buf[0..], @tagName(level));
        var scope_buf: [32]u8 = undefined;
        const scope_fmt = fmt.bufPrint(scope_buf[0..], "({s}):", .{ scope_name }) catch return;
        // Write Log
        writer.writeAll(ansi.fmt.bold) catch return;
        if (self.timestamps) {
            const tz = timezone orelse &zeit.utc;
            const now: zeit.Instant = zeit.instant(.{ .timezone = tz }) catch @panic("Missing Time Source!");
            now.time().strftime(writer, self.time_fmt) catch return;
        }
        if (self.meta_prefix) {
            if (self.meta_align) {
                writer.print(
                    " {s}{s: <5}{s}{s} {s: <14} ",
                    .{
                        level_color,
                        level_upper,
                        ansi.reset,
                        ansi.fmt.bold,
                        scope_fmt,
                    },
                ) catch return;
            } //
            else {
                writer.print(
                    " {s}{s}{s}{s} {s} ",
                    .{
                        level_color,
                        level_upper,
                        ansi.reset,
                        ansi.fmt.bold,
                        scope_fmt,
                    },
                ) catch return;
            }
        }
        writer.writeAll(ansi.reset) catch return;
        if (level == .debug)
            writer.writeAll(ansi.fg.gray) catch return;
        writer.print(format, args) catch return;
        if (level == .debug)
            writer.writeAll(ansi.reset) catch return;
        writer.writeByte('\n') catch return;
        writer.flush() catch return;
    }
};

