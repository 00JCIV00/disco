//! Cova Commands for the DisCo CLI.

const builtin = @import("builtin");
const std = @import("std");
const ascii = std.ascii;
const fmt = std.fmt;
const fs = std.fs;
const heap = std.heap;
const io = std.io;
const json = std.json;
const log = std.log;
const mem = std.mem;
const meta = std.meta;
const net = std.net;
const testing = std.testing;
const time = std.time;

const cova = @import("cova");
const nl = @import("nl.zig");
const wpa = @import("wpa.zig");

/// The Cova Command Type for DisCo.
pub const CommandT = cova.Command.Custom(.{
    .global_help_prefix = "DisCo",
    .help_category_order = &.{ .Prefix, .Usage, .Header, .Aliases, .Examples, .Values, .Options, .Commands },
    .val_config = .{
        .custom_types = &.{
            net.Address,
            fs.File,
            [6]u8,
            nl.IFF,
            wpa.Protocol,
        },
        .child_type_parse_fns = &.{
            .{
                .ChildT = net.Address,
                .parse_fn = struct{
                    pub fn parseIP(addr: []const u8, _: mem.Allocator) !net.Address {
                        var iter = mem.splitScalar(u8, addr, ':');
                        return net.Address.parseIp(
                            iter.first(),
                            try fmt.parseInt(u16, iter.next() orelse "-", 10)
                        ) catch |err| {
                            log.err("The provided destination address '{s}' is invalid.", .{ addr });
                            return err;
                        };
                    }
                }.parseIP,
            },
            .{
                .ChildT = fs.File,
                .parse_fn = struct{
                    pub fn parseFilePath(path: []const u8, _: mem.Allocator) !fs.File {
                        var cwd = fs.cwd();
                        return cwd.openFile(path, .{ .lock = .shared }) catch |err| {
                            log.err("The provided path to the File '{s}' is invalid.", .{ path });
                            return err;
                        };
                    }
                }.parseFilePath,
            },
        },
        .child_type_aliases = &.{
            .{ .ChildT = fs.File, .alias = "filepath" },
            .{ .ChildT = net.Address, .alias = "ip_address:port" },
            .{ .ChildT = bool, .alias = "toggle" },
            .{ .ChildT = []const u8, .alias = "text" },
            .{ .ChildT = [6]u8, .alias = "mac_address" },
            .{ .ChildT = nl.IFF, .alias = "interface_state" },
            .{ .ChildT = wpa.Protocol, .alias = "security_protocol" },
        }
    }
});
const ValueT = CommandT.ValueT;

/// The Root Setup Command for Coordz
pub const setup_cmd = CommandT{
    .name = "disco",
    .description = "Discreetly Connect to networks.",
    .examples = &.{
        "disco wlan0",
        "disco wlan0 set if --mac 00:11:22:aa:bb:cc",
    },
    .sub_cmds_mandatory = false,
    .vals_mandatory = false,
    .sub_cmds = &.{
        .{
            .name = "set",
            .description = "Set a Connection attribute.",
            .sub_cmds_mandatory = false,
            .sub_cmds = &.{
                .{
                    .name = "if",
                    .description = "Set a Connection attribute for the specified Interface.",
                    .opts = &.{
                        .{
                            .name = "mac",
                            .description = "Set the MAC Address of the given Interface.",
                            .long_name = "mac",
                            .short_name = 'm',
                            .val = ValueT.ofType([6]u8, .{
                                .name = "address",
                                .parse_fn = struct{
                                    pub fn macParseFn(arg: []const u8, _: mem.Allocator) ![6]u8 {
                                        if (arg.len < 12 or arg.len > 17)
                                            return error.AddressNotValid;
                                        var text_buf: [12]u8 = undefined;
                                        var idx: usize = 0;
                                        for (arg) |c| {
                                            if (mem.indexOfScalar(u8, "-_: ", c) != null) 
                                                continue;
                                            if (mem.indexOfScalar(u8, "0123456789abcdefABCDEF", c) == null) 
                                                return error.InvalidMAC;
                                            text_buf[idx] = if (c >= 'A' or c < 'a') c else c + 32;
                                            idx += 1;
                                        }
                                        var addr_buf: [6]u8 = undefined;
                                        for (addr_buf[0..], 0..) |*byte, addr_idx| {
                                            const start = addr_idx * 2;
                                            const end = start + 2;
                                            byte.* = try fmt.parseInt(u8, text_buf[start..end], 16);
                                        }
                                        return addr_buf;
                                    }
                                }.macParseFn,
                            })
                        },
                        .{
                            .name = "state",
                            .description = "Set the State of the given Interface. (UP or DOWN)",
                            .long_name = "state",
                            .short_name = 's',
                            .val = ValueT.ofType(nl.IFF, .{
                                .parse_fn = struct {
                                    pub fn parseIFF(arg: []const u8, _: mem.Allocator) !nl.IFF {
                                        var state_buf: [12]u8 = undefined;
                                        if (ascii.isUpper(arg[0]) and ascii.isUpper(arg[1])) return meta.stringToEnum(nl.IFF, arg) orelse error.InvalidState;
                                        const state = ascii.upperString(state_buf[0..], arg[0..@min(arg.len, 12)]);
                                        return meta.stringToEnum(nl.IFF, state) orelse error.InvalidState;
                                    }
                                }.parseIFF,
                            }),
                        },
                    },
                },
            },
            .opts = &.{
                .{
                    .name = "hostname",
                    .description = "Set a new Hostname.",
                    .long_name = "hostname",
                    .short_name = 'H',
                    .val = ValueT.ofType([]const u8, .{}),
                }
            }
        },
        .{
            .name = "connect",
            .description = "Connect to a WiFi Network.",
            .opts = &.{
                .{
                    .name = "security",
                    .description = "Set the WiFi Secruity Protocol.",
                    .long_name = "security",
                    .short_name = 's',
                    .val = ValueT.ofType(wpa.Protocol, .{ .default_val = .wpa2 }),
                }
            },
        },
        CommandT.from(@TypeOf(wpa.genKey), .{
            .cmd_name = "gen-key",
            .cmd_description = "Generate a WPA Key.",
            .sub_descriptions = &.{
                .{ "protocol", "WiFi Network Security Protocol." },
                .{ "ssid", "WiFi Network SSID." },
                .{ "passphrase", "WiFi Network Passphrase." },
            },
        }),
    },
    .opts = &.{
        .{
            .name = "log-path",
            .description = "Save the JSON output to the specified Log Path.",
            .short_name = 'l',
            .long_name = "log-path",
            .val = CommandT.ValueT.ofType(fs.File, .{
                .name = "log_path",
                .description = "Path to the save JSON Log File.",
            }),
        },
        .{
            .name = "no-tui",
            .description = "Run coordz without a TUI.",
            .short_name = 'n',
            .long_name = "no-tui",
        },
        .{
            .name = "no-mouse",
            .description = "Disable mouse events for the TUI.",
            .long_name = "no-mouse",
        },
    },
    .vals = &.{
        ValueT.ofType([]const u8, .{
            .name = "interface",
            .description = "The Network Interface to use. (This is mandatory)"
        }),
    },
};

