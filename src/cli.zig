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
const core = @import("core.zig");
const serve = core.serve;
const nl = @import("netlink.zig");
const netdata = @import("netdata.zig");
const address = netdata.address;
const oui = netdata.oui;
const proto = @import("protocols.zig");
const wpa = proto.wpa;

/// The Cova Command Type for DisCo.
pub const CommandT = cova.Command.Custom(.{
    .global_help_prefix = "DisCo",
    .help_category_order = &.{ .Prefix, .Usage, .Header, .Aliases, .Examples, .Values, .Options, .Commands },
    .global_allow_inheritable_opts = false,
    .allow_abbreviated_cmds = true,
    .abbreviated_min_len = 1,
    .val_config = .{
        .max_children = 50,
        .custom_types = &.{
            net.Address,
            fs.File,
            fs.Dir,
            [6]u8,
            [4]u8,
            [3]u8,
            address.IPv4,
            address.RandomMACKind,
            core.profiles.Mask,
            core.connections.Config,
            core.serve.Protocol,
            nl.route.IFF,
            nl._80211.IFTYPE,
            nl._80211.CHANNEL_WIDTH,
            nl._80211.SecurityType,
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
            .{
                .ChildT = fs.Dir,
                .parse_fn = struct{
                    pub fn parseDirPath(path: []const u8, _: mem.Allocator) !fs.Dir {
                        var cwd = fs.cwd();
                        return cwd.openDir(path, .{ .iterate = true }) catch |err| {
                            log.err("The provided path to the Dir '{s}' is invalid.", .{ path });
                            return err;
                        };
                    }
                }.parseDirPath,
            },
        },
        .child_type_aliases = &.{
            .{ .ChildT = bool, .alias = "toggle" },
            .{ .ChildT = []const u8, .alias = "text" },
            .{ .ChildT = usize, .alias = "positive_number" },
            .{ .ChildT = fs.File, .alias = "filepath" },
            .{ .ChildT = fs.Dir, .alias = "directory" },
            .{ .ChildT = net.Address, .alias = "ip_address:port" },
            .{ .ChildT = [6]u8, .alias = "mac_address" },
            .{ .ChildT = [4]u8, .alias = "ip_address" },
            .{ .ChildT = [3]u8, .alias = "oui" },
            .{ .ChildT = address.IPv4, .alias = "ip_address/cidr" },
            .{ .ChildT = core.profiles.Mask, .alias = "profile_mask" },
            .{ .ChildT = core.connections.Config, .alias = "connection_info" },
            .{ .ChildT = nl.route.IFF, .alias = "interface_state" },
            .{ .ChildT = nl._80211.CHANNEL_WIDTH, .alias = "channel_width" },
            .{ .ChildT = nl._80211.SecurityType, .alias = "security_protocol" },
        },
    }
});
const OptionT = CommandT.OptionT;
const ValueT = CommandT.ValueT;

/// The Root Setup Command for DisCo
pub const setup_cmd: CommandT = .{
    .name = "disco",
    .description = "Discreetly Connect to networks.",
    .examples = &.{
        "disco -c config.json",
        "disco -i wlan0",
        "disco -i wlan0 --mask \"google pixel 6\"",
        "disco -i wlan0 connect \"NetworkSSID\" -p \"network_passphrase\"",
        "disco -i wlan0 set --mac 00:11:22:aa:bb:cc",
        "disco -i wlan0 add --ip 192.168.10.10",
        "disco -i wlan0 del --route 192.168.0.0/16",
        "disco sys set --hostname 'shaggy'",
        "disco serve --dir '/tmp'",
    },
    .cmd_groups = &.{ "ACTIVE", "INTERFACE", "SETTINGS" },
    .opt_groups = &.{ "ACTIVE", "MASK", "SETTINGS" },
    .sub_cmds_mandatory = false,
    .vals_mandatory = false,
    .allow_inheritable_opts = true,
    .opts = &.{
        .{
            .name = "config",
            .description =
                \\Provide a JSON Config for DisCo.
                \\            Note, using CLI Options will supercede parts of this Config.
                \\            Fields can be viewed w/ `list --config`.
            ,
            .opt_group = "ACTIVE",
            .short_name = 'c',
            .long_name = "config",
            .val = .ofType(fs.File, .{}),
        },
        .{
            .name = "interfaces",
            .description = "The WiFi Interface(s) available for DisCo to use. (Multiple Interfaces can be provided.)",
            .opt_group = "ACTIVE",
            .short_name = 'i',
            .long_name = "interfaces",
            .val = .ofType([]const u8, .{
                .set_behavior = .Multi,
                .max_entries = 32,
            }),
        },
        .{
            .name = "ssids",
            .description = "Provide SSIDs to focus on. (Up to 10 SSIDs.)",
            .opt_group = "ACTIVE",
            .short_name = 's',
            .long_name = "ssids",
            .val = ssids_val,
        },
        channels_opt,
        bands_opt,
        .{
            .name = "connect_info",
            .description = 
                \\Provide Connection Info for a specific Network in JSON format. 
                \\            Ex: '{ "ssid": "SomeNetwork", "passphrase": "somepassphrase1" }'
                \\            A list of fields can be viewed w/ `list --config` under "Connect".
            ,
            .opt_group = "ACTIVE",
            .short_name = 'N',
            .long_name = "connect-info",
            .alias_long_names = &.{ "connection", "network" },
            .val = .ofType(core.connections.Config, .{
                .set_behavior = .Multi,
                .max_entries = 32,
                .arg_delims = ";",
                .parse_fn = struct {
                    pub fn parseConnInfo(raw_info: []const u8, alloc: mem.Allocator) !core.connections.Config {
                        return json.parseFromSliceLeaky(
                            core.connections.Config,
                            alloc,
                            raw_info,
                            .{
                                .duplicate_field_behavior = .use_first,
                                .ignore_unknown_fields = true,
                                .allocate = .alloc_always,
                            },
                        ) catch |err| {
                            log.err("Couldn't parse the Connection Info: {t}", .{ err });
                            return err;
                        };
                    }
                }.parseConnInfo,
            }),
        },
        conn_gw_opt,
        .{
            .name = "mask",
            .description = "Choose a Profile Mask to hide your system. (A list of masks can be viewed w/ `list --masks`)",
            .opt_group = "MASK",
            .short_name = 'm',
            .long_name = "mask",
            .val = .ofType(core.profiles.Mask, .{
                .parse_fn = struct {
                    pub fn parseMask(raw_name: []const u8, _: mem.Allocator) !core.profiles.Mask {
                        const map = core.profiles.Mask.map;
                        var lower_buf: [50]u8 = undefined;
                        const name = mem.trim(u8, ascii.lowerString(lower_buf[0..], raw_name), ascii.whitespace[0..]);
                        return map.get(name) orelse getClosest: {
                            for (map.keys()) |key| {
                                if (mem.indexOf(u8, key, name) == null) continue;
                                break :getClosest map.get(key).?;
                            }
                            break :getClosest error.NoMatchingProfileMask;
                        };
                    }
                }.parseMask,
            }),
        },
        .{
            .name = "no_mask",
            .description = "Explicitly opt out of using a Profile Mask. (By default, a random mask will be used if one isn't set.)",
            .opt_group = "MASK",
            .long_name = "no-mask",
        },
        .{
            .name = "mask_oui",
            .description = "Provide an OUI or Manufacturer to hide your WiFi Interfaces. (This will provide a Link Local Random OUI if one can't be found.)",
            .opt_group = "MASK",
            .long_name = "mask-oui",
            .val = .ofType([3]u8, .{
                .parse_fn = struct {
                    pub fn parseOUI(oui_arg: []const u8, alloc: mem.Allocator) ![3]u8 {
                        return
                            getOUI(oui_arg, alloc) catch
                            oui.getOUI(oui_arg) catch
                            address.getRandomMAC(.ll)[0..3].*;
                    }
                }.parseOUI,
            }),
        },
        .{
            .name = "mask_hostname",
            .description = "Provide a Hostname to hide your System when connected to a network.",
            .opt_group = "MASK",
            .long_name = "mask-hostname",
            .alias_long_names = &.{ "mask-hn" },
            .val = .ofType([]const u8, .{}),
        },
        .{
            .name = "mask_ttl",
            .description = "Provide a Time-to-Live (TTL) value to hide your System when connected to a network.",
            .opt_group = "MASK",
            .long_name = "mask-ttl",
            .val = .ofType(u8, .{}),
        },
        .{
            .name = "mask_user_agent",
            .description = "Provide a User Agent (UA) String to hide your System when connected to a network. (This only applies to HTTP traffic from DisCo.)",
            .opt_group = "MASK",
            .long_name = "mask-user-agent",
            .alias_long_names = &.{ "mask-ua" },
            .val = .ofType([]const u8, .{}),
        },
        // TODO Implement these Base Options
        .{
            .name = "log_path",
            .description = "Save the JSON output to the specified Log Path.",
            .short_name = 'l',
            .long_name = "log-path",
            .val = .ofType(fs.File, .{
                .name = "log_path",
                .description = "Path to the save JSON Log File.",
            }),
        },
        .{
            .name = "no_tui",
            .description = "Run DisCo without a TUI.",
            .short_name = 'n',
            .long_name = "no-tui",
        },
        .{
            .name = "no_mouse",
            .description = "Disable mouse events for the TUI.",
            .long_name = "no-mouse",
        },
        .{
            .name = "no_conflict_pids",
            .description = "Ignore Conflict PIDs",
            .long_name = "no-conflict-pids",
        },
        .{
            .name = "no_default_config",
            .description = "Ignore any Default Configs",
            .long_name = "no-default-config",
        }
    },
    .sub_cmds = &.{
        .{
            .name = "connect",
            .description = "Connect to a WiFi Network using the specified Interface.",
            .cmd_group = "ACTIVE",
            .vals = &.{
                .ofType([]const u8, .{
                    .name = "ssid",
                    .description = "Set the SSID of the Network. (Up to 32 characters)",
                    .default_val = "",
                    .valid_fn = struct {
                        pub fn validSSID(arg: []const u8, _: mem.Allocator) bool {
                            return arg.len > 0 and arg.len <= 32;
                        }
                    }.validSSID,
                }),
            },
            .opts = &.{
                channels_opt,
                .{
                    .name = "passphrase",
                    .description = "Set the Passhprase for the Network. (Between 8-63 characters)",
                    .long_name = "passphrase",
                    .alias_long_names = &.{ "password", "pwd" },
                    .short_name = 'p',
                    .val = .ofType([]const u8, .{
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
                    .val = .ofType(nl._80211.SecurityType, .{}),
                },
                .{
                    .name = "dhcp",
                    .description = "Obtain an IP Address via DHCP upon successful connection.",
                    .long_name = "dhcp",
                    .short_name = 'd',
                },
                conn_gw_opt,
            },
        },
        .{
            .name = "scan",
            .description = "Scan for WiFi Networks.",
            .cmd_group = "ACTIVE",
            .allow_inheritable_opts = true,
        },
        .{
            .name = "list",
            .alias_names = &.{ "view" },
            .description = "List various System or DisCo properties.",
            .cmd_group = "SETTINGS",
            .vals_mandatory = false,
            .opts = &.{
                .{
                    .name = "masks",
                    .description = "List available Profile Masks.",
                    .long_name = "masks",
                },
                .{
                    .name = "conflict_pids",
                    .description = "List available Profile Masks.",
                    .long_name = "conflict-pids",
                    .alias_long_names = &.{ "pids", "conflicts", "procs", "processes" },
                },
                .{
                    .name = "config",
                    .description = "List the Config Fields.",
                    .long_name = "config",
                    .alias_long_names = &.{ "fields" },
                },
                .{
                    .name = "interfaces",
                    .description = "List the WiFi Interfaces of the system.",
                    .long_name = "interfaces",
                },
            },
            .vals = &.{
                .ofType([]const u8, .{
                    .name = "item_list",
                    .description = "List available Items from the provided List. (Look at the Options for this Command for valid Values.)",
                    .set_behavior = .Multi,
                    .max_entries = 10,
                    .parse_fn = struct {
                        pub fn parseList(arg: []const u8, alloc: mem.Allocator) ![]const u8 {
                            const lower = try ascii.allocLowerString(alloc, arg);
                            inline for (&.{ 
                                "masks", 
                                "pids", 
                                "conflict-pids", 
                                "conflicts", 
                                "procs", 
                                "processes",
                                "config",
                                "fields",
                            }) |list| {
                                if (mem.eql(u8, lower, list)) return lower;
                            }
                            return error.InvalidList;
                        }
                    }.parseList,
                }),
            }
        },
        .{
            .name = "serve",
            .description = "Serve files from the provided `--directory` on the designated `--port` using HTTP and TFTP.",
            .cmd_group = "ACTIVE",
            .opts = &.{
                .{
                    .name = "ip",
                    .description = "IP Address to serve on. (Default: 0.0.0.0)",
                    .long_name = "ip",
                    .short_name = 'i',
                    .val = .ofType(address.IPv4, .{
                        .default_val = .{ .addr = .{ 0, 0, 0, 0 } },
                        .parse_fn = parseIPv4,
                    }),
                },
                .{
                    .name = "port",
                    .description = "Port to serve on. (Default: 12070)",
                    .long_name = "port",
                    .short_name = 'p',
                    .val = .ofType(u16, .{ .default_val = 12070 }),
                },
                .{
                    .name = "directory",
                    .description = "Directory to serve. (Default: Current Directory '.')",
                    .long_name = "directory",
                    .short_name = 'd',
                    .val = .ofType([]const u8, .{
                        .default_val = ".",
                        .alias_child_type= "path",
                        .valid_fn = struct{
                            pub fn validatePath(path: []const u8, _: mem.Allocator) bool {
                                var dir = fs.openDirAbsolute(path, .{}) catch return false;
                                defer dir.close();
                                return true;
                            }
                        }.validatePath,
                    }),
                },
                .{
                    .name = "protocols",
                    .description = "Protocols to serve on. (http, tftp, or all)",
                    .long_name = "protocols",
                    .short_name = 'P',
                    .val = .ofType(core.serve.Protocol, .{
                        .default_val = .all,
                        .alias_child_type = "file_serve_protocol",
                        .max_entries = 10,
                        .set_behavior = .Multi,
                    }),
                }
            },
        },
        .{
            .name = "set",
            .alias_names = &.{ "change" },
            .description = "Set/Change a Connection attribute for the specified Interface.",
            .cmd_group = "INTERFACE",
            .opt_groups = &.{ "CHANNEL", "MAC", "INTERFACE" },
            .sub_cmds_mandatory = false,
            .opts = &.{
                .{
                    .name = "channel",
                    .description = "Set the Channel of the given Interface. (Note, this will set the card to Up in Monitor mode)",
                    .opt_group = "CHANNEL",
                    .long_name = "channel",
                    .short_name = 'c',
                    .val = .ofType(usize, .{
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
                    .description = "Set the Channel/Frequency Width (in MHz & Throughput) of the given Interface. (Note, this only works in conjunction with `--channel` or `--freq`)",
                    .opt_group = "CHANNEL",
                    .long_name = "channel-width",
                    .alias_long_names = &.{ "ch-width", "frequency-width", "freq-width" },
                    .short_name = 'C',
                    .val = .ofType(nl._80211.CHANNEL_WIDTH, .{}),
                },
                .{
                    .name = "frequency",
                    .description = "Set the frequency (in MHz) of the given Interface. (Note, this will set the card to Up in Monitor mode)",
                    .opt_group = "CHANNEL",
                    .long_name = "frequency",
                    .short_name = 'f',
                    .val = .ofType(usize, .{
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
                    .opt_group = "MAC",
                    .long_name = "mac",
                    .short_name = 'm',
                    .allow_empty = true,
                    .val = .ofType([6]u8, .{
                        .name = "address",
                        .parse_fn = parseMAC,
                    }),
                },
                .{
                    .name = "random_mac",
                    .description = "Set a Random MAC Address type for `--mac`. (Settings: `ll` = Link Local [default], `full` = Full Random, `oui` = Random Real OUI)",
                    .opt_group = "MAC",
                    .long_name = "random",
                    .short_name = 'r',
                    .allow_empty = true,
                    .val = .ofType(address.RandomMACKind, .{ .default_val = .ll }),
                },
                .{
                    .name = "oui",
                    .description = "Set an OUI Manufacturer type for `--mac`. (This based on the Manufacturer Column of the Wireshark MAC list. Default 'Intel')",
                    .opt_group = "MAC",
                    .long_name = "oui",
                    .short_name = 'o',
                    .val = .ofType([3]u8, .{
                        .default_val = .{ 0xF8, 0x63, 0xD9 },
                        .parse_fn = getOUI,
                    }),
                },
                .{
                    .name = "state",
                    .description = "Set the State of the given Interface. (UP, DOWN, BROADCAST, etc). (Note, multiple flags can be set simultaneously)",
                    .opt_group = "INTERFACE",
                    .long_name = "state",
                    .short_name = 's',
                    .val = .ofType(nl.route.IFF, .{
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
                    .opt_group = "INTERFACE",
                    .long_name = "mode",
                    .short_name = 'M',
                    .val = .ofType(nl._80211.IFTYPE, .{
                        .parse_fn = struct {
                            pub fn parseIFF(arg: []const u8, _: mem.Allocator) !nl._80211.IFTYPE {
                                var mode_buf: [12]u8 = undefined;
                                if (ascii.isUpper(arg[0]) and ascii.isUpper(arg[1])) return meta.stringToEnum(nl._80211.IFTYPE, arg) orelse error.InvalidMode;
                                const mode = ascii.upperString(mode_buf[0..], arg[0..@min(arg.len, 12)]);
                                return meta.stringToEnum(nl._80211.IFTYPE, mode) orelse error.InvalidMode;
                            }
                        }.parseIFF,
                    }),
                },
            },
        },
        .{
            .name = "add",
            .description = "Add a Connection attribute to the specified Interface.",
            .cmd_group = "INTERFACE",
            .opts = &.{
                .{
                    .name = "ip",
                    .description = "Add an IP Address to the given Interface.",
                    .long_name = "ip",
                    .val = .ofType(address.IPv4, .{
                        .parse_fn = parseIPv4,
                    }),
                },
                .{
                    .name = "route",
                    .description = "Add a Route to the given Interface. (A default gateway, '0.0.0.0', can be added using `default`)",
                    .long_name = "route",
                    .alias_long_names = &.{ "rt" },
                    .short_name = 'r',
                    .val = .ofType(address.IPv4, .{
                        .parse_fn = parseIPv4,
                    }),
                },
                .{
                    .name = "gateway",
                    .description = "Add a Gateway for the provided Route. (Used in conjuction with `--route`)",
                    .long_name = "gateway",
                    .alias_long_names = &.{ "gw", "via" },
                    .short_name = 'g',
                    .val = .ofType(address.IPv4, .{
                        .parse_fn = parseIPv4,
                    }),
                },
            },
        },
        .{
            .name = "delete",
            .alias_names = &.{ "remove", "rm" },
            .description = "Delete/Remove a Connection attribute from the specified Interface.",
            .cmd_group = "INTERFACE",
            .opts = &.{
                .{
                    .name = "ip",
                    .description = "Remove an IP Address from the given Interface.",
                    .long_name = "ip",
                    .val = .ofType(address.IPv4, .{
                        .parse_fn = parseIPv4,
                    }),
                },
                .{
                    .name = "route",
                    .description = "Remove a Route from the given Interface.",
                    .long_name = "route",
                    .alias_long_names = &.{ "rt" },
                    .short_name = 'r',
                    .val = .ofType(address.IPv4, .{
                        .parse_fn = parseIPv4,
                    }),
                },
                .{
                    .name = "gateway",
                    .description = "Add a Gateway for the provided Route. (Used in conjuction with `--route`)",
                    .long_name = "gateway",
                    .alias_long_names = &.{ "gw", "via" },
                    .short_name = 'g',
                    .val = .ofType(address.IPv4, .{
                        .parse_fn = parseIPv4,
                    }),
                },
            },
        },
        .{
            .name = "system",
            .description = "Manage System properties.",
            .cmd_group = "SETTINGS",
            .sub_cmds = &.{
                .{
                    .name = "set",
                    .description = "Set System properties.",
                    .opts = &.{
                        .{
                            .name = "hostname",
                            .description = "Set a new Hostname.",
                            .long_name = "hostname",
                            .short_name = 'H',
                            .val = .ofType([]const u8, .{}),
                        },
                    },
                },
            },
        },
        CommandT.from(@TypeOf(wpa.genKey), .{
            .cmd_name = "gen-key",
            .cmd_description = "Generate a WPA Key.",
            .cmd_group = "SETTINGS",
            .sub_descriptions = &.{
                .{ "protocol", "WiFi Network Security Protocol." },
                .{ "ssid", "WiFi Network SSID." },
                .{ "passphrase", "WiFi Network Passphrase." },
            },
        }),
    },
};


// Multi-use Arguments
/// Channels
const channels_opt: OptionT = .{
    .name = "channels",
    .description = "Specify channels to be used. (By default, all channels will be used.)",
    .opt_group = "ACTIVE",
    .short_name = 'C',
    .long_name = "channels",
    .inheritable = true,
    .val = .ofType(usize, .{
        .set_behavior = .Multi,
        .max_entries = 50,
        .valid_fn = struct {
            pub fn valCh(ch: usize, _: mem.Allocator) bool {
                return nl._80211.validateChannel(ch);
            }
        }.valCh,
    }),
};
/// Bands
const bands_opt: OptionT = .{
    .name = "bands",
    .description = "Specify bands to be used. (Choices: 2, 5, and 6. By default, 2 and 5 will be used as able.)",
    .opt_group = "ACTIVE",
    .short_name = 'b',
    .long_name = "bands",
    .inheritable = true,
    .val = .ofType(u8, .{
        .set_behavior = .Multi,
        .max_entries = 3,
        .valid_fn = struct {
            pub fn valBand(band: u8, _: mem.Allocator) bool {
                return mem.indexOfScalar(u8, &.{ 2, 5, 6 }, band) != null;
            }
        }.valBand,
    }),
};
/// SSIDs
const ssids_val: ValueT = .ofType([]const u8, .{
    .name = "ssid",
    .description = "Set the SSID of the Network. (Up to 32 characters)",
    .set_behavior = .Multi,
    .max_entries = 10,
    .default_val = "",
    .valid_fn = struct {
        pub fn validSSID(arg: []const u8, _: mem.Allocator) bool {
            return arg.len > 0 and arg.len <= 32;
        }
    }.validSSID,
});
/// Connection Gateway
const conn_gw_opt: OptionT = .{
    .name = "gateway",
    .description = "Automatically set the Gateway after obtaining an IP Address.",
    .long_name = "gateway",
    .alias_long_names = &.{ "gw" },
    .short_name = 'g',
};

// Function Wrappers
fn parseIPv4(arg: []const u8, _: mem.Allocator) !address.IPv4 {
    return try address.IPv4.fromStr(arg);
}

fn parseMAC(arg: []const u8, _: mem.Allocator) ![6]u8 {
    return try address.parseMAC(arg);
}

fn getOUI(arg: []const u8, _: mem.Allocator) ![3]u8 {
    return try oui.getOUI(arg);
}
