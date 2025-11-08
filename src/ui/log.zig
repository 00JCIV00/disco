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
    /// Log Level
    level: log.Level = switch (builtin.mode) {
        .Debug => .debug,
        else => .info,
    },

    /// Log to a specific Writer
    pub fn logTo(
        ctx: @This(),
        comptime level: std.log.Level,
        comptime scope: @Type(.enum_literal),
        comptime format: []const u8,
        args: anytype,
    ) void {
        var filter: ansi.FilterWriter = .init(ctx.writer);
        const writer = //
            if (ctx.ansi) ctx.writer
            else &filter.io_writer;
        if (@intFromEnum(ctx.level) < @intFromEnum(level))
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
        if (ctx.timestamps) {
            const now: zeit.Instant = zeit.instant(.{}) catch @panic("Missing Time Source!");
            now.time().strftime(writer, ctx.time_fmt) catch return;
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

