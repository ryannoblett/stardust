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

    // Optional: path to a Nix-built (or manually assembled) bundle directory
    // containing lib/{libssh,libssl,libcrypto,libz}.a and include/libssh/*.h.
    // Example: -Dlibssh_dir=$(nix build .#libssh-aarch64-musl --no-link --print-out-paths)
    // When omitted, falls back to pkg-config / system library paths.
    const libssh_dir = b.option(
        []const u8,
        "libssh_dir",
        "Bundle directory with lib/ and include/ for libssh cross-compilation (bypasses pkg-config)",
    );

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
    // Prefer static libssh for the production binary (scratch Docker image has no .so).
    // Cross-compilation uses -Dlibssh_dir pointing to a Nix-built bundle.
    // Native dev builds fall back to pkg-config (libssh-dev on Ubuntu/Debian).
    linkLibssh(b, exe, libssh_dir);
    b.installArtifact(exe);
    const run_cmd = b.addRunArtifact(exe);
    if (b.args) |args| run_cmd.addArgs(args);
    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    // Relay agent binary — lightweight, no vaxis/libssh dependencies.
    const relay_mod = b.createModule(.{
        .root_source_file = b.path("relay_main.zig"),
        .target = target,
        .optimize = optimize,
    });
    relay_mod.addImport("yaml", yaml_mod);
    const relay_exe = b.addExecutable(.{
        .name = "stardust-relay",
        .root_module = relay_mod,
    });
    relay_exe.linkLibC();
    b.installArtifact(relay_exe);
    const relay_run_cmd = b.addRunArtifact(relay_exe);
    if (b.args) |args| relay_run_cmd.addArgs(args);
    const relay_run_step = b.step("run-relay", "Run the DHCP relay agent");
    relay_run_step.dependOn(&relay_run_cmd.step);

    // Relay test step
    const relay_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("relay_main.zig"),
            .target = target,
            .optimize = .Debug,
        }),
    });
    relay_tests.root_module.addImport("yaml", yaml_mod);
    relay_tests.linkLibC();
    const relay_test_step = b.step("test-relay", "Run relay unit tests");
    relay_test_step.dependOn(&b.addRunArtifact(relay_tests).step);

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
    linkLibssh(b, dev_exe, libssh_dir);
    const dev_step = b.step("dev", "Run with debug optimizations");
    dev_step.dependOn(&b.addRunArtifact(dev_exe).step);

    // Test step
    const unit_tests = b.addTest(.{
        .root_module = main_mod,
    });
    linkLibssh(b, unit_tests, libssh_dir);
    if (b.option([]const u8, "test_filter", "Filter tests by name")) |f| {
        // Allocate on the build arena so the slice outlives the build() function frame.
        const filter_slice = b.allocator.dupe([]const u8, &.{f}) catch @panic("OOM");
        unit_tests.filters = filter_slice;
    }
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&b.addRunArtifact(unit_tests).step);

    // Check step (type-check without emitting a binary)
    const check_exe = b.addExecutable(.{
        .name = "check",
        .root_module = main_mod,
    });
    linkLibssh(b, check_exe, libssh_dir);
    const check_step = b.step("check", "Type-check the codebase");
    check_step.dependOn(&check_exe.step);
}

/// Link libssh and its static dependencies.
///
/// When `dir` is provided it points to a Nix-built bundle with layout:
///   <dir>/lib/   — libssh.a, libssl.a, libcrypto.a, libz.a
///   <dir>/include/ — libssh/*.h headers
/// We add both paths explicitly and bypass pkg-config, which cannot find
/// musl-linked libraries for foreign architectures on the build host.
///
/// When `dir` is null, pkg-config discovers everything automatically,
/// which is correct for native builds (dev workstation, CI test runner).
fn linkLibssh(b: *std.Build, step: *std.Build.Step.Compile, dir: ?[]const u8) void {
    if (dir) |d| {
        step.addLibraryPath(.{ .cwd_relative = b.pathJoin(&.{ d, "lib" }) });
        step.addIncludePath(.{ .cwd_relative = b.pathJoin(&.{ d, "include" }) });
        // Bypass pkg-config; explicitly name libssh and its static deps.
        inline for (.{ "ssh", "ssl", "crypto", "z" }) |lib| {
            step.linkSystemLibrary2(lib, .{
                .preferred_link_mode = .static,
                .use_pkg_config = .no,
            });
        }
    } else {
        step.linkSystemLibrary2("ssh", .{ .preferred_link_mode = .static });
    }
    step.linkLibC();
}
