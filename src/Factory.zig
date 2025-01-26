//! Common interface for ULID factories
const std = @import("std");

const Factory = @This();
const Ulid = @import("Ulid.zig");

ptr: *anyopaque,
vtable: *const VTable,

pub const VTable = struct {
    /// Generate a new ULID using this factory
    next: *const fn (ctx: *anyopaque) Ulid.Error!Ulid,
};

pub fn next(self: *Factory) Ulid.Error!Ulid {
    return self.vtable.next(self.ptr);
}

/// Generic function to implement `Factory` from a custom factory instance
pub fn impl(pointer: anytype) Factory {
    const T = @TypeOf(pointer);
    const ptr_info = @typeInfo(T);

    if (ptr_info != .pointer) @compileError("pointer must be a pointer");
    if (ptr_info.pointer.size != .one) @compileError("pointer must be a single item pointer");

    const translate = struct {
        fn next(ctx: *anyopaque) Ulid.Error!Ulid {
            const self: T = @ptrCast(@alignCast(ctx));
            return ptr_info.pointer.child.next(self);
        }
    };

    return .{
        .ptr = pointer,
        .vtable = &.{ .next = translate.next },
    };
}

const StubPrng = struct {
    stub: u8 = 0,

    pub fn fill(self: *@This(), buf: []u8) void {
        @memset(buf, self.stub);
    }

    pub fn random(self: *@This()) std.Random {
        return std.Random.init(self, fill);
    }
};

const StubTime = struct {
    const timestamp: i64 = 1469918176385;
    fn constanttime() i64 {
        return timestamp;
    }
};

/// Basic random ULID factory
pub const RandomFactory = struct {
    random: std.Random,

    pub fn init(random: std.Random) RandomFactory {
        return .{ .random = random };
    }

    pub fn factory(self: *RandomFactory) Factory {
        return Factory.impl(self);
    }

    /// Implementation of the next method required by Factory interface
    pub fn next(self: *RandomFactory) Ulid.Error!Ulid {
        var result = Ulid.zero();

        const now_ms = std.time.milliTimestamp();
        std.debug.assert(now_ms <= Ulid.TIME_MAX);
        result.time = @intCast(now_ms);

        result.random = self.random.int(u80);

        return result;
    }

    export fn c_generate_random_ulid() u128 {
        var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
        var rf = RandomFactory.init(prng.random());
        var f = rf.factory();

        const ulid = f.next() catch return 0;

        return ulid.toInt();
    }
};

test RandomFactory {
    var prng = std.Random.DefaultPrng.init(std.testing.random_seed);
    var rf = RandomFactory.init(prng.random());
    var factory = rf.factory();

    // Generate two ULIDs and verify they're different
    const start = std.time.milliTimestamp();
    const ulid1 = try factory.next();
    const ulid2 = try factory.next();
    const end = std.time.milliTimestamp();

    // Verify ULIDs are different
    try std.testing.expect(ulid1.toInt() != ulid2.toInt());

    // Verify timestamps are within the time range
    try std.testing.expect(ulid1.time >= @as(u48, @intCast(start)));
    try std.testing.expect(ulid1.time <= @as(u48, @intCast(end)));
}

/// Monotonic ULID factory
pub const MonotonicFactory = struct {
    random: std.Random,
    time: *const fn () i64,
    last_ms: u48,
    last_rand: u80,

    pub fn init(random: std.Random, time: fn () i64) MonotonicFactory {
        return .{
            .random = random,
            .time = time,
            .last_ms = 0,
            .last_rand = 0,
        };
    }

    pub fn factory(self: *MonotonicFactory) Factory {
        return Factory.impl(self);
    }

    /// Implementation of the next method required by Factory interface
    pub fn next(self: *MonotonicFactory) Ulid.Error!Ulid {
        var result = Ulid.zero();
        const now_ms = self.time();

        if (now_ms > self.last_ms) {
            result.time = @intCast(now_ms);
            result.random = self.random.int(u80);
            self.last_ms = @intCast(now_ms);
            self.last_rand = result.random;
        } else {
            self.last_rand +%= 1;
            if (self.last_rand == 0) return error.Overflow;
            result.time = @intCast(self.last_ms);
        }

        result.random = self.last_rand;
        return result;
    }
};

test MonotonicFactory {
    var prng = StubPrng{ .stub = 42 };
    var mf = MonotonicFactory.init(prng.random(), StubTime.constanttime);
    var factory = mf.factory();

    // Generate multiple ULIDs and verify they're monotonically increasing
    const ulid1 = try factory.next();
    const ulid2 = try factory.next();
    const ulid3 = try factory.next();

    try std.testing.expect(ulid1.toInt() < ulid2.toInt());
    try std.testing.expect(ulid2.toInt() < ulid3.toInt());

    try std.testing.expect(ulid1.time == StubTime.timestamp);
    try std.testing.expect(ulid2.time == StubTime.timestamp);
    try std.testing.expect(ulid3.time == StubTime.timestamp);

    // Manually set last_ms to simulate same millisecond
    const now_ms = std.time.milliTimestamp();
    mf.last_ms = @intCast(now_ms);
    mf.last_rand = 0xFFFFFFFFFFFFFFFFFF; // Near overflow

    // Generate ULIDs in same millisecond
    const ulid4 = try mf.next();
    const ulid5 = try mf.next();

    try std.testing.expect(ulid4.toInt() < ulid5.toInt());
    try std.testing.expect(ulid4.time == ulid5.time);

    // Set up conditions for overflow
    mf.last_rand = std.math.maxInt(u80);
    mf.last_ms = std.math.maxInt(u48);

    // Next generation should return overflow error
    try std.testing.expectError(error.Overflow, mf.next());
}
