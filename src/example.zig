const std = @import("std");

const Ulid = @import("ulid");

pub fn main() !void {
    // Create a PRNG
    var defaultPrng = std.Random.DefaultPrng.init(0);
    const prng = defaultPrng.random();

    // Create a factory
    var rf = Ulid.Factory.RandomFactory.init(prng);
    var random = rf.factory();

    // Generate a ULID
    std.log.info("ULID: {}", .{try random.next()});
    std.log.info("ULID: `{s}`", .{try random.next()});
    std.log.info("ULID: {d}", .{try random.next()});
    std.log.info("ULID: 0x{X}", .{try random.next()});

    // Create a monotonic factory
    var mf = Ulid.Factory.MonotonicFactory.init(prng, std.time.milliTimestamp);
    var monotonic = mf.factory();

    // Generate a ULID
    std.log.info("ULID: {}", .{try monotonic.next()});
    std.log.info("ULID: {}", .{try monotonic.next()});
    std.log.info("ULID: {}", .{try monotonic.next()});
    std.log.info("ULID: {}", .{try monotonic.next()});

    std.log.debug("TEXT: {c}", .{"1234"});
}
