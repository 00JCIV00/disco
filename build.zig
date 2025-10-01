const std = @import("std");

pub fn build(b: *std.Build) void {
    //const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{
        .preferred_optimize_mode = .ReleaseSafe,
    });
    const target = b.standardTargetOptions(.{
        .default_target = .{
            .cpu_model = //
                if (optimize == .Debug)  .determined_by_arch_os //
                else .baseline,
        },
    });

    // Cova
    const cova_dep = b.dependency("cova", .{ .target = target, .optimize = optimize });
    const cova_mod = cova_dep.module("cova");
    // Vaxis
    //const vaxis_dep = b.dependency("vaxis", .{ .target = target, .optimize = optimize });
    //const vaxis_mod = vaxis_dep.module("vaxis");
    // Zeit
    const zeit_dep = b.dependency("zeit", .{ .target = target, .optimize = optimize });
    const zeit_mod = zeit_dep.module("zeit");
    // OUI Table
    const oui_lookup_mod = b.createModule(.{ .root_source_file = b.path("resources/oui_lookup") });
    // Config Fields
    const config_fields_mod = b.createModule(.{ .root_source_file = b.path("resources/config_fields") });

    const exe_name = exeName: {
        const default_name = b.allocator.dupe(u8, "disco") catch @panic("OOM");
        const cpu_arch = target.query.cpu_arch orelse break :exeName default_name;
        const os_tag = target.query.os_tag orelse break :exeName default_name;
        break :exeName std.fmt.allocPrint(b.allocator, "disco_{s}-{s}", .{ @tagName(os_tag), @tagName(cpu_arch) }) catch @panic("OOM or Fmt");
    };
    defer b.allocator.free(exe_name);
    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = //
            if (optimize == .Debug) target //
            else target,
        .optimize = optimize,
    });
    const exe = b.addExecutable(.{
        .name = exe_name,
        .root_module = exe_mod,
        .use_llvm = true,
        //.sanitize_thread = if (optimize == .Debug) true else null,
    });
    exe.root_module.addImport("cova", cova_mod);
    //exe.root_module.addImport("vaxis", vaxis_mod);
    exe.root_module.addImport("zeit", zeit_mod);
    exe.root_module.addImport("oui_table", oui_lookup_mod);
    exe.root_module.addImport("config_fields", config_fields_mod);
    b.installArtifact(exe);

    // Exe Testing
    var test_mod = exe_mod;
    test_mod.strip = optimize != .Debug;
    const exe_unit_tests = b.addTest(.{
        .root_module = test_mod,
    });
    const run_exe_unit_tests = b.addRunArtifact(exe_unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_exe_unit_tests.step);

    // Library Modules
    _ = b.addModule("dbus", .{ .root_source_file = b.path("src/dbus.zig") });
    _ = b.addModule("netdata", .{ .root_source_file = b.path("src/netdata.zig") });
    _ = b.addModule("netlink", .{ .root_source_file = b.path("src/netlink.zig") });
    _ = b.addModule("netprotocols", .{ .root_source_file = b.path("src/protocols.zig") });
    _ = b.addModule("sys", .{ .root_source_file = b.path("src/sys.zig") });
}
