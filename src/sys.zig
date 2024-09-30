//! Functions for System settings in DisCo.

const builtin = @import("builtin");
const std = @import("std");
const log = std.log;
const os = std.os;
const posix = std.posix;


/// Set the System's Hostname
pub fn setHostName(hostname: []const u8) !void {
    const set_host_name = switch (builtin.target.os.tag) {
        .linux => switch (builtin.target.cpu.arch) {
            .arm => os.linux.syscalls.Arm.sethostname,
            .aarch64 => os.linux.syscalls.Arm64.sethostname,
            .x86 => os.linux.syscalls.X86.sethostname,
            .x86_64 => os.linux.syscalls.X64.sethostname,
            .mips, .mipsel => os.linux.syscalls.Mips.sethostname,
            .mips64, .mips64el => os.linux.syscalls.Mips64.sethostname,
            else => @compileError("Unsupported Architecture."),
        },
        else => @compileError("Unsupported OS."),
    };
    const errno = os.linux.syscall2(set_host_name, @intFromPtr(hostname.ptr), hostname.len);
    return switch (errno) {
        0 => {},
        else => return error.OSError,
    };
}


