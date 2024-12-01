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
const netdata = @import("netdata.zig");
const address = netdata.address;
const wpa = @import("wpa.zig");

/// The Cova Command Type for DisCo.
pub const CommandT = cova.Command.Custom(.{
    .global_help_prefix = "DisCo",
    .help_category_order = &.{ .Prefix, .Usage, .Header, .Aliases, .Examples, .Values, .Options, .Commands },
    .allow_abbreviated_cmds = true,
    .abbreviated_min_len = 1,
    .val_config = .{
        .custom_types = &.{
            net.Address,
            fs.File,
            [6]u8,
            [4]u8,
            nl.route.IFF,
            nl._80211.IFTYPE,
            nl._80211.CHANNEL_WIDTH,
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
            .{ .ChildT = [4]u8, .alias = "ip_address" },
            .{ .ChildT = nl.route.IFF, .alias = "interface_state" },
            .{ .ChildT = nl._80211.CHANNEL_WIDTH, .alias = "channel_width" },
            .{ .ChildT = wpa.Protocol, .alias = "security_protocol" },
        },
    }
});
const OptionT = CommandT.OptionT;
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
            .alias_names = &.{ "change" },
            .description = "Set a Connection attribute.",
            .sub_cmds_mandatory = false,
            .sub_cmds = &.{
                .{
                    .name = "interface",
                    .alias_names = &.{ "if" },
                    .description = "Set a Connection attribute for the specified Interface.",
                    .opts = &.{
                        .{
                            .name = "channel",
                            .description = "Set the Channel of the given Interface. (Note, this will set the card to Up in Monitor mode)",
                            .long_name = "channel",
                            .short_name = 'c',
                            .val = ValueT.ofType(usize, .{
                                .name = "chan",
                                .valid_fn = struct{
                                    pub fn valCh(ch: usize, _: mem.Allocator) bool {
                                        return nl._80211.validateChannel(ch);
                                    }
                                }.valCh,
                            }),
                        },
                        .{
                            .name = "channel-width",
                            .description = "Set the Channel/Frequency Width (in MHZ & Throughput) of the given Interface. (Note, this only works in conjunction with --channel or --freq)",
                            .long_name = "channel-width",
                            .alias_long_names = &.{ "ch-width", "frequency-width", "freq-width" },
                            .short_name = 'C',
                            .val = ValueT.ofType(nl._80211.CHANNEL_WIDTH, .{}),
                        },
                        .{
                            .name = "frequency",
                            .description = "Set the frequency (in MHz) of the given Interface. (Note, this will set the card to Up in Monitor mode)",
                            .long_name = "frequency",
                            .short_name = 'f',
                            .val = ValueT.ofType(usize, .{
                                .name = "freq",
                                .valid_fn = struct{
                                    pub fn valFreq(freq: usize, _: mem.Allocator) bool {
                                        return nl._80211.validateFreq(freq);
                                    }
                                }.valFreq,
                            }),
                        },
                        .{
                            .name = "mac",
                            .description = "Set the MAC Address of the given Interface.",
                            .long_name = "mac",
                            .short_name = 'm',
                            .val = ValueT.ofType([6]u8, .{
                                .name = "address",
                                // TODO Add random/vendor support
                                .parse_fn = address.parseMAC,
                            })
                        },
                        .{
                            .name = "state",
                            .description = "Set the State of the given Interface. (UP, DOWN, BROADCAST, etc). (Note, multiple flags can be set simultaneously)",
                            .long_name = "state",
                            .short_name = 's',
                            .val = ValueT.ofType(nl.route.IFF, .{
                                .set_behavior = .Multi,
                                .max_entries = 32,
                                .parse_fn = struct {
                                    pub fn parseIFF(arg: []const u8, _: mem.Allocator) !nl.route.IFF {
                                        var state_buf: [12]u8 = undefined;
                                        if (ascii.isUpper(arg[0]) and ascii.isUpper(arg[1])) return meta.stringToEnum(nl.route.IFF, arg) orelse error.InvalidState;
                                        const state = ascii.upperString(state_buf[0..], arg[0..@min(arg.len, 12)]);
                                        return meta.stringToEnum(nl.route.IFF, state) orelse error.InvalidState;
                                    }
                                }.parseIFF,
                            }),
                        },
                        .{
                            .name = "mode",
                            .description = "Set the Mode of the given Interface. (MONITOR, STATION, AP, etc)",
                            .long_name = "mode",
                            .short_name = 'M',
                            .val = ValueT.ofType(nl._80211.IFTYPE, .{
                                .parse_fn = struct {
                                    pub fn parseIFF(arg: []const u8, _: mem.Allocator) !nl._80211.IFTYPE {
                                        var mode_buf: [12]u8 = undefined;
                                        if (ascii.isUpper(arg[0]) and ascii.isUpper(arg[1])) return meta.stringToEnum(nl._80211.IFTYPE, arg) orelse error.Invalidmode;
                                        const mode = ascii.upperString(mode_buf[0..], arg[0..@min(arg.len, 12)]);
                                        return meta.stringToEnum(nl._80211.IFTYPE, mode) orelse error.InvalidMode;
                                    }
                                }.parseIFF,
                            }),
                        }
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
                channels_opt,
                .{
                    .name = "passphrase",
                    .description = "Set the Passhprase for the Network. (Between 8-63 characters)",
                    .long_name = "passphrase",
                    .alias_long_names = &.{ "password", "pwd" },
                    .short_name = 'p',
                    .val = ValueT.ofType([]const u8, .{
                        .valid_fn = struct {
                            pub fn validPass(arg: []const u8, _: mem.Allocator) bool {
                                return arg.len >= 8 and arg.len <= 63;
                            }
                        }.validPass,
                    }),
                },
                .{
                    .name = "security",
                    .description = "Set the WiFi Secruity Protocol. (open, wep, or wpa2 | Default = wpa2)",
                    .long_name = "security",
                    .short_name = 's',
                    .val = ValueT.ofType(wpa.Protocol, .{ .default_val = .wpa2 }),
                },
                .{
                    .name = "dhcp",
                    .description = "Obtain an IP Address via DHCP upon successful connection.",
                    .long_name = "dhcp",
                    .short_name = 'd',
                },
                .{
                    .name = "gateway",
                    .description = "Automatically set the Gateway after obtaining an IP Address.",
                    .long_name = "gateway",
                    .short_name = 'g',
                },
            },
            .vals = &.{
                ValueT.ofType([]const u8, .{
                    .name = "ssid",
                    .description = "Set the SSID of the Network. (Up to 32 characters)",
                    .valid_fn = struct {
                        pub fn validPass(arg: []const u8, _: mem.Allocator) bool {
                            return arg.len > 0 and arg.len <= 32;
                        }
                    }.validPass,
                }),
            },
        },
        .{
            .name = "add",
            .description = "Add a Connection attribute.",
            .opts = &.{
                .{
                    .name = "ip",
                    .description = "Add an IP Address to the given Interface.",
                    .long_name = "ip",
                    .val = ValueT.ofType([4]u8, .{
                        .parse_fn = address.parseIP,
                    }),
                },
                .{
                    .name = "route",
                    .description = "Add a Route to the given Interface.",
                    .long_name = "route",
                    .alias_long_names = &.{ "rt" },
                    .short_name = 'r',
                    .val = ValueT.ofType([4]u8, .{
                        .parse_fn = address.parseIP,
                    }),
                },
                .{
                    .name = "subnet",
                    .description = "Specify a Subnet Mask (in CIDR or IP notation) for the IP Address or Route being added to given Interface. (Used in conjunction with `--ip` or `--route`. Default = 24)",
                    .long_name = "subnet",
                    .short_name = 's',
                    .val = ValueT.ofType(u8, .{
                        .default_val = 24,
                        .parse_fn = address.parseCIDR,
                    }),
                },
            },
        },
        .{
            .name = "delete",
            .alias_names = &.{ "remove", "rm" },
            .description = "Delete/Remove a Connection attribute.",
            .opts = &.{
                .{
                    .name = "ip",
                    .description = "Remove an IP Address from the given Interface.",
                    .long_name = "ip",
                    .val = ValueT.ofType([4]u8, .{
                        .parse_fn = address.parseIP,
                    }),
                },
                .{
                    .name = "route",
                    .description = "Remove a Route from the given Interface.",
                    .long_name = "route",
                    .alias_long_names = &.{ "rt" },
                    .short_name = 'r',
                    .val = ValueT.ofType([4]u8, .{
                        .parse_fn = address.parseIP,
                    }),
                },
                .{
                    .name = "subnet",
                    .description = "Specify a Subnet Mask to identify the IP Address or Route being removed from the given Interface. (Used in conjunction with `--ip` or `--route`)",
                    .long_name = "subnet",
                    .short_name = 's',
                    .val = ValueT.ofType(u8, .{
                        .default_val = 24,
                        .parse_fn = address.parseCIDR,
                    }),
                },
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
            .val = ValueT.ofType(fs.File, .{
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


// Multi-use Arguments
/// Channels
const channels_opt: OptionT = .{
    .name = "channels",
    .description = "Specify channels to be used. (By default, all channels will be used.)",
    .short_name = 'c',
    .long_name = "channels",
    .val = ValueT.ofType(usize, .{
        .set_behavior = .Multi,
        .max_entries = 50,
        .valid_fn = struct {
            pub fn valCh(ch: usize, _: mem.Allocator) bool {
                return nl._80211.validateChannel(ch);
            }
        }.valCh,
    }),
};

