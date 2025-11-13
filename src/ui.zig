//! UI Modules for DisCo

const std = @import("std");
const testing = std.testing;

pub const cli = @import("ui/cli.zig");
pub const log = @import("ui/log.zig");
pub const repl = @import("ui/repl.zig");
pub const tui = @import("ui/tui.zig");

pub const Mode = enum {
    /// Basic, headeless of DisCo that runs based on CLI Input & Configs.
    /// This mode has no user interaction while running.
    cli,
    /// Read, Evaluate, Print Loop (REPL) Shell for DisCo.
    /// This mode allows for Command based interactivity while running.
    repl,
    /// Text User Interface (TUI) for DisCo.
    /// This mode provides a full UI users within the Terminal.
    tui,
};


test "ui" {
    @setEvalBranchQuota(10_000);
    testing.refAllDeclsRecursive(@This());
}
