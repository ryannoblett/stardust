const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Resolve the yaml dependency once; all modules share it
    const yaml = b.dependency("yaml", .{
        .target = target,
        .optimize = optimize,
    });
    const yaml_mod = yaml.module("yaml");

    // Resolve the vaxis dependency (SSH admin TUI)
    const vaxis_dep = b.dependency("vaxis", .{
        .target = target,
        .optimize = optimize,
    });
    const vaxis_mod = vaxis_dep.module("vaxis");

    const main_mod = b.createModule(.{
        .root_source_file = b.path("main.zig"),
        .target = target,
        .optimize = optimize,
    });
    main_mod.addImport("yaml", yaml_mod);
    main_mod.addImport("vaxis", vaxis_mod);

    // Run step
    const exe = b.addExecutable(.{
        .name = "stardust",
        .root_module = main_mod,
    });
    exe.linkSystemLibrary("ssh");
    exe.linkLibC();
    b.installArtifact(exe);
    const run_cmd = b.addRunArtifact(exe);
    if (b.args) |args| run_cmd.addArgs(args);
    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    // Dev step (debug optimizations)
    const dev_mod = b.createModule(.{
        .root_source_file = b.path("main.zig"),
        .target = target,
        .optimize = .Debug,
    });
    dev_mod.addImport("yaml", yaml_mod);
    dev_mod.addImport("vaxis", vaxis_mod);
    const dev_exe = b.addExecutable(.{
        .name = "stardust-dev",
        .root_module = dev_mod,
    });
    dev_exe.linkSystemLibrary("ssh");
    dev_exe.linkLibC();
    const dev_step = b.step("dev", "Run with debug optimizations");
    dev_step.dependOn(&b.addRunArtifact(dev_exe).step);

    // Test step
    const unit_tests = b.addTest(.{
        .root_module = main_mod,
    });
    unit_tests.linkSystemLibrary("ssh");
    unit_tests.linkLibC();
    if (b.option([]const u8, "test_filter", "Filter tests by name")) |f| {
        unit_tests.filters = &.{f};
    }
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&b.addRunArtifact(unit_tests).step);

    // Check step (type-check without emitting a binary)
    const check_exe = b.addExecutable(.{
        .name = "check",
        .root_module = main_mod,
    });
    check_exe.linkSystemLibrary("ssh");
    check_exe.linkLibC();
    const check_step = b.step("check", "Type-check the codebase");
    check_step.dependOn(&check_exe.step);
}
