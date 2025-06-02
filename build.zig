const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{
        .preferred_optimize_mode = .ReleaseSafe,
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
    const exe = b.addExecutable(.{
        .name = exe_name,
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        //.use_llvm = false,
        //.sanitize_thread = if (optimize == .Debug) true else null,
    });
    exe.root_module.addImport("cova", cova_mod);
    //exe.root_module.addImport("vaxis", vaxis_mod);
    exe.root_module.addImport("zeit", zeit_mod);
    exe.root_module.addImport("oui_table", oui_lookup_mod);
    exe.root_module.addImport("config_fields", config_fields_mod);
    b.installArtifact(exe);

    const exe_unit_tests = b.addTest(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .strip = optimize != .Debug,
    });

    const run_exe_unit_tests = b.addRunArtifact(exe_unit_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_exe_unit_tests.step);
}
