const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mod = b.createModule(.{
        .root_source_file = b.path("src/Ulid.zig"),
        .target = target,
        .optimize = optimize,
    });

    const lib = b.addStaticLibrary(.{
        .name = "ulid",
        .root_module = mod,
    });

    var lib_headers = b.addInstallHeaderFile(lib.getEmittedH(), "ulid.h");
    b.getInstallStep().dependOn(&lib_headers.step);

    b.installArtifact(lib);

    const tests = b.addTest(.{ .root_module = mod });
    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_tests.step);

    const example = b.addExecutable(.{
        .name = "example",
        .root_source_file = b.path("src/example.zig"),
        .target = target,
        .optimize = optimize,
    });
    example.root_module.addImport("ulid", mod);
    b.installArtifact(example);

    const run_example = b.addRunArtifact(example);
    const example_step = b.step("example", "Run example");
    example_step.dependOn(&run_example.step);
}
