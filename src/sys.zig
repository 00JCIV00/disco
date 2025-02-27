//! Functions for System settings in DisCo.

const builtin = @import("builtin");
const std = @import("std");
const fmt = std.fmt;
const fs = std.fs;
const io = std.io;
const log = std.log;
const mem = std.mem;
const net = std.net;
const os = std.os;
const posix = std.posix;
const time = std.time;


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

/// Get the System's Current User ID
pub fn getUID() !posix.uid_t {
    const get_uid = switch (builtin.target.os.tag) {
        .linux => switch (builtin.target.cpu.arch) {
            .arm => os.linux.syscalls.Arm.getuid,
            .aarch64 => os.linux.syscalls.Arm64.getuid,
            .x86 => os.linux.syscalls.X86.getuid,
            .x86_64 => os.linux.syscalls.X64.getuid,
            .mips, .mipsel => os.linux.syscalls.Mips.getuid,
            .mips64, .mips64el => os.linux.syscalls.Mips64.getuid,
            else => @compileError("Unsupported Architecture."),
        },
        else => @compileError("Unsupported OS."),
    };
    const uid = os.linux.syscall2(get_uid, 0, 0);
    if (uid < 0) return error.OSError;
    return @intCast(uid);
}

/// Get the System's Current User
pub fn getUser(user_buf: []u8) ?[]const u8 {
    const user = posix.getenv("USER") orelse return null;
    @memcpy(user_buf[0..user.len], user[0..]);
    return user_buf[0..user.len];
}

/// Get a PID from the provided Process Name ('proc_name').
pub fn getPID(proc_name: []const u8) !?u32 {
    var proc_dir = try fs.openDirAbsolute("/proc", .{ .iterate = true });
    defer proc_dir.close();
    var proc_iter = proc_dir.iterate();
    while (try proc_iter.next()) |entry| {
        const pid = fmt.parseInt(u32, entry.name, 10) catch continue;
        var pid_dir = try proc_dir.openDir(entry.name, .{});
        defer pid_dir.close();
        var comm = try pid_dir.openFile("comm", .{});
        defer comm.close();
        var pid_name_buf: [posix.PATH_MAX]u8 = .{ 0 } ** posix.PATH_MAX;
        const pid_name_len = try comm.readAll(pid_name_buf[0..]);
        if (mem.indexOf(u8, pid_name_buf[0..pid_name_len], proc_name) == null) continue;
        return pid;
    }
    return null;
}

/// Get a list of PIDs from the provided Process Names (`proc_names`).
pub fn getPIDs(alloc: mem.Allocator, proc_names: []const []const u8) ![]const u32 {
    var proc_dir = try fs.openDirAbsolute("/proc", .{ .iterate = true });
    defer proc_dir.close();
    var pids_list: std.ArrayListUnmanaged(u32) = .{};
    errdefer pids_list.deinit(alloc);
    var proc_iter = proc_dir.iterate();
    while (try proc_iter.next()) |entry| {
        const pid = fmt.parseInt(u32, entry.name, 10) catch continue;
        var pid_dir = proc_dir.openDir(entry.name, .{}) catch continue;
        defer pid_dir.close();
        var comm = pid_dir.openFile("comm", .{}) catch continue;
        defer comm.close();
        var pid_name_buf: [posix.PATH_MAX]u8 = .{ 0 } ** posix.PATH_MAX;
        const pid_name_len = comm.readAll(pid_name_buf[0..]) catch continue;
        for (proc_names) |proc_name| {
            if (mem.indexOf(u8, pid_name_buf[0..pid_name_len], proc_name) == null) continue;
            try pids_list.append(alloc, pid);
        }
    }
    return try pids_list.toOwnedSlice(alloc);
}

