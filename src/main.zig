const std = @import("std");
const fmt = std.fmt;
const heap = std.heap;
const io = std.io;
const json = std.json;
const log = std.log;
const os = std.os;
const posix = std.posix;
const process = std.process;

const cova = @import("cova");
const cli = @import("cli.zig");

const art = @import("art.zig");
const nl = @import("nl.zig");
const wpa = @import("wpa.zig");

const NetworkInterface = @import("NetworkInterface.zig");

pub fn main() !void {
    const stdout_file = io.getStdOut().writer();
    var stdout_bw = io.bufferedWriter(stdout_file);
    defer stdout_bw.flush() catch log.warn("Couldn't flush stdout before exiting!", .{});
    const stdout = stdout_bw.writer().any();

    var gpa = heap.GeneralPurposeAllocator(.{ .thread_safe = true }){};
    defer if (gpa.detectLeaks()) log.err("Memory leak detected!", .{});
    const alloc = gpa.allocator();

    // Parse Args
    var main_cmd = try cli.setup_cmd.init(alloc, .{});
    defer main_cmd.deinit();
    var args_iter = try cova.ArgIteratorGeneric.init(alloc);
    defer args_iter.deinit();
    cova.parseArgs(
        &args_iter,
        cli.CommandT,
        main_cmd,
        stdout,
        .{},
    ) catch |err| {
        try stdout_bw.flush();
        switch (err) {
            error.UsageHelpCalled => return,
            error.TooManyValues,
            error.UnrecognizedArgument,
            error.UnexpectedArgument,
            error.CouldNotParseOption => {},
            error.ExpectedMoreValues => {
                try stdout_file.print("DisCo needs to know which interface to use. (Ex: disco wlan0)\n", .{});
                return;
            },
            else => |parse_err| return parse_err,
        }
    };


    //const main_opts = try main_cmd.getOpts(.{});
    const main_vals = try main_cmd.getVals(.{});

    // Interface
    const if_name = try (main_vals.get("interface").?).getAs([]const u8);
    var net_if = NetworkInterface.get(if_name) catch |err| switch (err) {
        error.NoInterfaceFound => {
            log.err("Netlink request timed out. Could not find the '{s}' interface.", .{ if_name });
            return;
        },
        else => return err,
    };

    // Single Use
    // - Change
    if (main_cmd.matchSubCmd("change")) |change_cmd| {
        rootCheck(stdout_file.any());
        const change_opts = try change_cmd.getOpts(.{});
        if (change_opts.get("mac")) |mac_opt| changeMAC: {
            try stdout_file.print("Changing the MAC for {s}...\n", .{ if_name });
            const new_mac = mac_opt.val.getAs([6]u8) catch break :changeMAC;
            nl.changeMAC(net_if.idx, new_mac) catch |err| switch (err) {
                error.BUSY => {
                    log.err("The interface '{s}' is busy so the MAC could not be changed.", .{ if_name });
                    return;
                },
                else => {
                    log.err("Netlink request error. The MAC for interface '{s}' could not be changed.", .{ if_name });
                    return;
                },
            };
            var mac_buf: [17]u8 = .{ ':' } ** 17;
            for (new_mac, 0..6) |byte, idx| {
                const start = if (idx == 0) 0 else idx * 3;
                const end = start + 2;
                _ = try fmt.bufPrint(mac_buf[start..end], "{X:0>2}", .{ byte });
            }
            try stdout_file.print("Changed the MAC for {s} to {s}.\n", .{ if_name, mac_buf });
        }
        if (change_opts.get("state")) |state_opt| changeState: {
            try stdout_file.print("Changing the State for {s}...\n", .{ if_name });
            const new_state = state_opt.val.getAs(nl.IFF) catch break :changeState;
            nl.setState(net_if.idx, new_state) catch |err| switch (err) {
                error.BUSY => {
                    log.err("The interface '{s}' is busy so the State could not be changed.", .{ if_name });
                    return;
                },
                else => {
                    log.err("Netlink request error. The State for interface '{s}' could not be changed.", .{ if_name });
                    return;
                },
            };
            try stdout_file.print("Changed the State for {s} to {s}.\n", .{ if_name, @tagName(new_state) });
        }
        net_if = try NetworkInterface.get(if_name);
    }
    // - Generate Key
    if (main_cmd.matchSubCmd("gen-key")) |gen_key_cmd| {
        const gen_key_vals = try gen_key_cmd.getVals(.{});
        const key = try gen_key_cmd.callAs(wpa.genKey, null, [32]u8);
        try stdout.print(
            \\Generated Key:
            \\ - Protocol:   {s}
            \\ - SSID:       {s}
            \\ - Passphrase: {s}
            \\
            , .{
                @tagName(try (gen_key_vals.get("val-02").?).getAs(wpa.Protocol)),
                try (gen_key_vals.get("val-00").?).getAs([]const u8),
                try (gen_key_vals.get("val-01").?).getAs([]const u8),
            }
        );
        var key_buf: [64]u8 = undefined;
        for (key[0..], 0..) |byte, idx| _ = try fmt.bufPrint(key_buf[(idx * 2)..(idx * 2 + 2)], "{X:0<2}", .{ byte });
        try stdout.print(" - Key:        {s}\n\n", .{ key_buf[0..] });
        try stdout_bw.flush();
    }

    // Interface Details
    try stdout.print("{s} Interface Details:\n", .{ if_name });
    try json.stringify(net_if, .{ .whitespace = .indent_4, .emit_null_optional_fields = false }, stdout);
    //try stdout.print("{}", .{ net_if });
    try stdout.print("\n", .{});
    try stdout_bw.flush();

}

/// Root Check
fn rootCheck(stdout: io.AnyWriter) void {
    if (os.linux.getuid() != 0) {
        stdout.print("{s}\n\n                          DisCo must be run as sudo!\n", .{ art.sudo }) catch { 
            log.err("DisCo must be run as sudo! (There was also an issue writing to stdout.)", .{});
        };
        process.exit(1);
    }
}
