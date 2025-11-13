//! ANSI Escape Codes & Functions

const std = @import("std");
const ascii = std.ascii;
const s_fmt = std.fmt;
const mem = std.mem;
const Io = std.Io;
const Thread = std.Thread;


// Reset
pub const reset = "\x1b[0m";

/// Text Formatting
pub const fmt = struct {
    pub const bold = "\x1b[1m";
    pub const dim = "\x1b[2m";
    pub const italic = "\x1b[3m";
    pub const underline = "\x1b[4m";
    pub const blink = "\x1b[5m";
    pub const reverse = "\x1b[7m";
    pub const hidden = "\x1b[8m";
    pub const strikethrough = "\x1b[9m";

    pub const reset = "\x1b[22;23;24;25;27;28;29m";
    pub const reset_bold = "\x1b[22m";
    pub const reset_italic = "\x1b[23m";
    pub const reset_underline = "\x1b[24m";
    pub const reset_blink = "\x1b[25m";
    pub const reset_reverse = "\x1b[27m";
    pub const reset_hidden = "\x1b[28m";
    pub const reset_strikethrough = "\x1b[29m";
};

// Foreground Colors
pub const fg = struct {
    pub const black = "\x1b[30m";
    pub const red = "\x1b[31m";
    pub const green = "\x1b[32m";
    pub const yellow = "\x1b[33m";
    pub const blue = "\x1b[34m";
    pub const magenta = "\x1b[35m";
    pub const cyan = "\x1b[36m";
    pub const white = "\x1b[37m";
    pub const gray = "\x1b[38;5;244m";
    pub const bright_black = "\x1b[90m";
    pub const bright_red = "\x1b[91m";
    pub const bright_green = "\x1b[92m";
    pub const bright_yellow = "\x1b[93m";
    pub const bright_blue = "\x1b[94m";
    pub const bright_magenta = "\x1b[95m";
    pub const bright_cyan = "\x1b[96m";
    pub const bright_white = "\x1b[97m";

    pub const reset = "\x1b[39m";

    pub fn rgb(config: RGBConfig) RGB {
        return .init(true, config);
    }
};

// Background Colors
pub const bg = struct {
    pub const black = "\x1b[40m";
    pub const red = "\x1b[41m";
    pub const green = "\x1b[42m";
    pub const yellow = "\x1b[43m";
    pub const blue = "\x1b[44m";
    pub const magenta = "\x1b[45m";
    pub const cyan = "\x1b[46m";
    pub const white = "\x1b[47m";
    pub const gray = "\x1b[48;5;244m";
    pub const bright_black = "\x1b[100m";
    pub const bright_red = "\x1b[101m";
    pub const bright_green = "\x1b[102m";
    pub const bright_yellow = "\x1b[103m";
    pub const bright_blue = "\x1b[104m";
    pub const bright_magenta = "\x1b[105m";
    pub const bright_cyan = "\x1b[106m";
    pub const bright_white = "\x1b[107m";

    pub const reset = "\x1b[49m";

    pub fn rgb(config: RGBConfig) RGB {
        return .init(false, config);
    }
};

pub const RGBConfig = struct {
    r: u8 = 0,
    g: u8 = 0,
    b: u8 = 0,

    pub fn from(array: [3]u8) @This() {
        return .{
            .r = array[0],
            .g = array[1],
            .b = array[2],
        };
    }
};

/// A Custom RGB Escape Code
pub const RGB = struct {
    buf: [20]u8,
    len: u8,

    pub fn init(fg_color: bool, config: RGBConfig) @This() {
        var buf: [20]u8 = undefined;
        const prefix: u8 = if (fg_color) 38 else 48;
        const rgb_fmt = s_fmt.bufPrint(
            buf[0..],
            "\x1b[{d};2;{d};{d};{d}m",
            .{
                prefix,
                config.r,
                config.g,
                config.b,
            },
        ) catch "";
        return .{
            .buf = buf,
            .len = @truncate(rgb_fmt.len),
        };
    }

    pub fn format(self: @This(), writer: *Io.Writer) Io.Writer.Error!void {
        try writer.writeAll(self.buf[0..self.len]);
    }
};

/// Filter out any ANSI Escape Codes being written to the `to_writer`.
pub const FilterWriter = struct {
    io_writer: Io.Writer,
    to_writer: *Io.Writer,
    mutex: Thread.Mutex = .{},
    
    /// Initialize a new Filter
    pub fn init(writer: *Io.Writer) @This() {
        return .{
            .io_writer = .{
                .buffer = &.{},
                .vtable = &.{
                    .drain = ioDrain,
                    .flush = ioFlush,
                },
            },
            .to_writer = writer,
        };
    }

    /// Filter ANSI Codes before writing to `to_writer`.
    fn ioDrain(self: *Io.Writer, data: []const []const u8, _: usize) Io.Writer.Error!usize {
        const filter: *@This() = @fieldParentPtr("io_writer", self);
        filter.mutex.lock();
        defer filter.mutex.unlock();
        var count: usize = 0;
        for (data) |text| {
            count += text.len;
            if (text.len < 3) {
                try filter.to_writer.writeAll(text);
                continue;
            }
            var is_ansi = false;
            for (text[0..], 0..) |c, idx| {
                defer {
                    if (is_ansi)
                        is_ansi = !((c >= 'A' and c <= 'Z') or (c >= 'a' and c <= 'z'));
                }
                if (!is_ansi and idx <= text.len - 2)
                    is_ansi = mem.eql(u8, text[idx..(idx + 2)], "\x1b[");
                if (is_ansi)
                    continue;
                try filter.to_writer.writeByte(c);
            }
        }
        return count;
    }

    /// Flush the underlying `to_writer`
    fn ioFlush(self: *Io.Writer) Io.Writer.Error!void {
        const filter: *@This() = @fieldParentPtr("io_writer", self);
        filter.mutex.lock();
        defer filter.mutex.unlock();
        try filter.to_writer.flush();
    }
};
