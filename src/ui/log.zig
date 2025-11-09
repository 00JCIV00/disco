//! Logging Setup for DisCo

const builtin = @import("builtin");
const std = @import("std");
const ascii = std.ascii;
const log = std.log;
const mem = std.mem;
const Io = std.Io;

const zeit = @import("zeit");

const utils = @import("../utils.zig");
const ansi = utils.ansi;


/// Writers to Log to
pub var contexts: []const Context = &.{};
/// Time Zone for Timestamps
pub var timezone: ?*const zeit.TimeZone = null;

/// Log Function
pub fn logFn(
    comptime level: std.log.Level,
    comptime scope: @Type(.enum_literal),
    comptime format: []const u8,
    args: anytype,
) void {
    for (contexts) |ctx| {
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
    level: log.Level = switch (builtin.mode) {
        .Debug => .debug,
        else => .info,
    },
    /// Include Timestamps
    timestamps: bool = true,
    /// Formatting for Timestamps in `strftime` Format
    time_fmt: []const u8 = switch (builtin.mode) {
        .Debug => "%H:%M:%S:%f",
        else => "%T",
    },
};

/// Logging Context for a single Writer
pub const Context = struct {
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
    /// Custom Handler Function
    handle_fn: ?*const fn(@This(), log.Level) void = null,

    /// Log to a specific Writer
    pub fn logTo(
        self: @This(),
        comptime level: log.Level,
        comptime scope: @Type(.enum_literal),
        comptime format: []const u8,
        args: anytype,
    ) void {
        if (self.handle_fn) |handleFn|
            handleFn(self, level);
        var filter: ansi.FilterWriter = .init(self.writer);
        const writer = //
            if (self.ansi) self.writer
            else &filter.io_writer;
        if (@intFromEnum(self.min_level) < @intFromEnum(level))
            return;
        const level_color: []const u8 = switch (level) {
            .debug => ansi.fg.blue,
            .info => ansi.fg.green,
            .warn => ansi.fg.yellow,
            .err => ansi.fg.red,
        };
        var up_buf: [6]u8 = undefined;
        const level_upper: []const u8 = ascii.upperString(up_buf[0..], @tagName(level));
        writer.writeAll(ansi.fmt.bold) catch return;
        if (self.timestamps) {
            const tz = timezone orelse &zeit.utc;
            const now: zeit.Instant = zeit.instant(.{ .timezone = tz }) catch @panic("Missing Time Source!");
            now.time().strftime(writer, self.time_fmt) catch return;
        }
        writer.print(
            " {s}{s}{s}{s} ({s}): ",
            .{
                level_color,
                level_upper,
                ansi.reset,
                ansi.fmt.bold,
                @tagName(scope),
            },
        ) catch return;
        writer.writeAll(ansi.reset) catch return;
        writer.print(format, args) catch return;
        writer.writeByte('\n') catch return;
        writer.flush() catch return;
    }
};

