const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const main_mod = b.createModule(.{
        .root_source_file = b.path("main.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Run step
    const exe = b.addExecutable(.{
        .name = "stardust",
        .root_module = main_mod,
    });
    // Add yaml 
    const yaml = b.dependency("yaml", .{
      .target = target,
      .optimize = optimize,
    });
    exe.root_module.addImport("yaml", yaml.module("yaml"));
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
    const dev_exe = b.addExecutable(.{
        .name = "stardust-dev",
        .root_module = dev_mod,
    });
    const dev_step = b.step("dev", "Run with debug optimizations");
    dev_step.dependOn(&b.addRunArtifact(dev_exe).step);

    // Test step
    const unit_tests = b.addTest(.{
        .root_module = main_mod,
    });
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&b.addRunArtifact(unit_tests).step);

}
