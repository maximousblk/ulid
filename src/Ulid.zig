//! A ULID is a 16 byte Universally Unique Lexicographically Sortable Identifier
//!
//!     The components are encoded as 16 octets.
//!     Each component is encoded with the MSB first (network byte order).
//!
//!     0                   1                   2                   3
//!     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//!     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!     |                      32_bit_uint_time_high                    |
//!     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!     |     16_bit_uint_time_low      |       16_bit_uint_random      |
//!     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!     |                       32_bit_uint_random                      |
//!     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!     |                       32_bit_uint_random                      |
//!     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!
const Ulid = @This();

const std = @import("std");
const builtin = @import("builtin");

pub const Factory = @import("Factory.zig");

test {
    std.testing.refAllDecls(Ulid);
    std.testing.refAllDecls(Factory);
}

/// Length of a string-encoded ULID
pub const ULID_STRING_LENGTH = 26;

/// Crockford's Base32 alphabet (human-friendly, case-insensitive, no padding)
/// Excludes: I, L, O, U (to avoid confusion with 1, 0, and offensive words)
pub const ALPHABET: *const [ALPHABET_SIZE]u8 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
pub const ALPHABET_SIZE = 32;
pub const TIME_MAX: i64 = std.math.pow(i64, 2, 48) - 1; // 2^48 - 1
pub const RANDOM_MAX: u128 = std.math.pow(u128, 2, 80) - 1; // 2^80 - 1
pub const TIME_BYTE_LEN = 10;
pub const RANDOM_BYTE_LEN = 16;

/// ASCII lookup table for decoding Crockford's Base32 characters.
/// Maps ASCII values (0–255) to their Base32 index (0–31) or NULL for invalid characters.
/// - '0'–'9'  →  0x00–0x09
/// - 'A'–'Z'  →  0x0A–0x1F (excluding I, L, O, U for readability)
/// - 'a'–'z'  →  Mapped identically to 'A'–'Z' (case-insensitive decoding)
/// - All other values set to 0xFF (invalid characters).
/// - 256 entries ensure safe lookup for any 8-bit input.
const ASCII_LOOKUP = lookup: {
    var table: [256]u8 = undefined;

    for (table, 0..) |_, i| table[i] = 0xFF;

    for (ALPHABET, 0..) |c, i| {
        table[c] = @intCast(i);
        if (c < '0' or '9' < c) table[c + 32] = @intCast(i);
    }

    break :lookup table;
};

pub const Error = error{
    BufferTooSmall,
    Overflow,
    InvalidChar,
    InvalidLength,
};

pub fn errMessage(e: Error) []const u8 {
    return switch (e) {
        Error.BufferTooSmall => "buffer too small",
        Error.Overflow => "overflow",
        else => |other| @errorName(other),
    };
}

time: u48,
random: u80,

/// Creates a new ULID with zero values for both time and random components
pub fn zero() Ulid {
    return Ulid{
        .time = 0,
        .random = 0,
    };
}

test zero {
    const ulid = Ulid.zero();
    try std.testing.expectEqual(ulid.time, 0);
    try std.testing.expectEqual(ulid.random, 0);
}

/// Converts the ULID to its u128 integer representation
/// The time component occupies the most significant 48 bits,
/// followed by the 80-bit random component
pub inline fn toInt(self: Ulid) u128 {
    return (@as(u128, self.time) << 80) | self.random;
}

test toInt {
    var ulid = Ulid.zero();

    // Min
    ulid.time = 0;
    ulid.random = 0;
    try std.testing.expectEqual(0, ulid.toInt());

    // Max
    ulid.time = TIME_MAX;
    ulid.random = RANDOM_MAX;
    try std.testing.expectEqual(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF, ulid.toInt());

    // Max time, zero random
    ulid.time = TIME_MAX;
    ulid.random = 0;
    try std.testing.expectEqual(0xFFFFFFFFFFFF00000000000000000000, ulid.toInt());

    // Zero time, max random
    ulid.time = 0;
    ulid.random = RANDOM_MAX;
    try std.testing.expectEqual(0x000000000000FFFFFFFFFFFFFFFFFFFF, ulid.toInt());

    // random sample
    ulid.time = 0xDF8D52319C55;
    ulid.random = 0x41C3A6B1CBB27CFBE140;
    try std.testing.expectEqual(0xDF8D52319C5541C3A6B1CBB27CFBE140, ulid.toInt());
}

/// Initializes the ULID from a u128 integer representation
/// The most significant 48 bits are used for the time component,
/// and the least significant 80 bits for the random component
pub inline fn fromInt(value: u128) Ulid {
    return Ulid{
        .time = @intCast((value >> 80) & TIME_MAX),
        .random = @intCast(value & RANDOM_MAX),
    };
}

test fromInt {
    var expected: Ulid = undefined;

    // Min
    expected.time = 0;
    expected.random = 0;
    try std.testing.expectEqual(expected, Ulid.fromInt(0));

    // Max
    expected.time = TIME_MAX;
    expected.random = RANDOM_MAX;
    try std.testing.expectEqual(expected, Ulid.fromInt(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF));

    // Max time, zero random
    expected.time = TIME_MAX;
    expected.random = 0;
    try std.testing.expectEqual(expected, Ulid.fromInt(0xFFFFFFFFFFFF00000000000000000000));

    // Zero time, max random
    expected.time = 0;
    expected.random = RANDOM_MAX;
    try std.testing.expectEqual(expected, Ulid.fromInt(0x000000000000FFFFFFFFFFFFFFFFFFFF));

    // random sample
    expected.time = 0xDF8D52319C55;
    expected.random = 0x41C3A6B1CBB27CFBE140;
    try std.testing.expectEqual(expected, Ulid.fromInt(0xDF8D52319C5541C3A6B1CBB27CFBE140));

    // vice versa
    const ulidFromRandomSample = Ulid.fromInt(0xDF8D52319C5541C3A6B1CBB27CFBE140);
    try std.testing.expectEqual(ulidFromRandomSample.time, expected.time);
    try std.testing.expectEqual(ulidFromRandomSample.random, expected.random);
}

/// Converts the ULID to its binary representation as a 16-byte array
/// Format: [time(6 bytes)][random(10 bytes)]
/// Each component is encoded in network byte order (MSB first)
pub fn toBytesAlloc(self: Ulid, allocator: std.mem.Allocator) !*[16]u8 {
    var bytes = try allocator.alloc(u8, 16);

    const time = std.mem.nativeToBig(u48, self.time); // Time component (48 bits = 6 bytes)
    bytes[0x0] = @intCast((time >> 0x00) & 0xFF);
    bytes[0x1] = @intCast((time >> 0x08) & 0xFF);
    bytes[0x2] = @intCast((time >> 0x10) & 0xFF);
    bytes[0x3] = @intCast((time >> 0x18) & 0xFF);
    bytes[0x4] = @intCast((time >> 0x20) & 0xFF);
    bytes[0x5] = @intCast((time >> 0x28) & 0xFF);

    // Random component (80 bits = 10 bytes)
    const random = std.mem.nativeToBig(u80, self.random);
    bytes[0x6] = @intCast((random >> 0x00) & 0xFF);
    bytes[0x7] = @intCast((random >> 0x08) & 0xFF);
    bytes[0x8] = @intCast((random >> 0x10) & 0xFF);
    bytes[0x9] = @intCast((random >> 0x18) & 0xFF);
    bytes[0xA] = @intCast((random >> 0x20) & 0xFF);
    bytes[0xB] = @intCast((random >> 0x28) & 0xFF);
    bytes[0xC] = @intCast((random >> 0x30) & 0xFF);
    bytes[0xD] = @intCast((random >> 0x38) & 0xFF);
    bytes[0xE] = @intCast((random >> 0x40) & 0xFF);
    bytes[0xF] = @intCast((random >> 0x48) & 0xFF);

    return @ptrCast(bytes[0..16]);
}

test toBytesAlloc {
    var ulid = Ulid.zero();
    var expected: [16]u8 = undefined;

    // Min
    ulid.time = 0;
    ulid.random = 0;
    const minBytes = try ulid.toBytesAlloc(std.testing.allocator);
    defer std.testing.allocator.free(minBytes);
    expected = .{
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    };
    try std.testing.expectEqualSlices(u8, &expected, minBytes);

    // Max
    ulid.time = TIME_MAX;
    ulid.random = RANDOM_MAX;
    const maxBytes = try ulid.toBytesAlloc(std.testing.allocator);
    defer std.testing.allocator.free(maxBytes);
    expected = .{
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
    };
    try std.testing.expectEqualSlices(u8, &expected, maxBytes);

    // Max time, zero random
    ulid.time = TIME_MAX;
    ulid.random = 0;
    const maxTimeZeroRandomBytes = try ulid.toBytesAlloc(std.testing.allocator);
    defer std.testing.allocator.free(maxTimeZeroRandomBytes);
    expected = .{
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    };
    try std.testing.expectEqualSlices(u8, &expected, maxTimeZeroRandomBytes);

    // zero time, max random
    ulid.time = 0;
    ulid.random = RANDOM_MAX;
    const zeroTimeMaxRandomBytes = try ulid.toBytesAlloc(std.testing.allocator);
    defer std.testing.allocator.free(zeroTimeMaxRandomBytes);
    expected = .{
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
    };
    try std.testing.expectEqualSlices(u8, &expected, zeroTimeMaxRandomBytes);

    // random sample
    ulid.time = 0xDF8D52319C55;
    ulid.random = 0x41C3A6B1CBB27CFBE140;
    const randomSampleBytes = try ulid.toBytesAlloc(std.testing.allocator);
    defer std.testing.allocator.free(randomSampleBytes);
    expected = .{
        // DF:8D:52:31:9C:55:01:C3:26:B1:CB:B2:7C:FB:E1:40
        0xDF, 0x8D, 0x52, 0x31,
        0x9C, 0x55, 0x41, 0xC3,
        0xA6, 0xB1, 0xCB, 0xB2,
        0x7C, 0xFB, 0xE1, 0x40,
    };
    try std.testing.expectEqualSlices(u8, &expected, randomSampleBytes);

    // vice versa
    const ulidFromRandomSampleBytes = Ulid.fromBytes(randomSampleBytes);
    try std.testing.expectEqual(ulidFromRandomSampleBytes.time, ulid.time);
    try std.testing.expectEqual(ulidFromRandomSampleBytes.random, ulid.random);
}

/// Initializes the ULID from a 16-byte binary representation
/// Expected format: [time(6 bytes)][random(10 bytes)]
/// Each component should be in network byte order (MSB first)
pub fn fromBytes(bytes: *const [16]u8) Ulid {
    std.debug.assert(bytes.len == 16);

    var time: u48 = 0; // Time component (48 bits)
    time = (@as(u48, bytes[0x0]) << 0x00) | time;
    time = (@as(u48, bytes[0x1]) << 0x08) | time;
    time = (@as(u48, bytes[0x2]) << 0x10) | time;
    time = (@as(u48, bytes[0x3]) << 0x18) | time;
    time = (@as(u48, bytes[0x4]) << 0x20) | time;
    time = (@as(u48, bytes[0x5]) << 0x28) | time;

    var random: u80 = 0; // Random component (80 bits)
    random = (@as(u80, bytes[0x6]) << 0x00) | random;
    random = (@as(u80, bytes[0x7]) << 0x08) | random;
    random = (@as(u80, bytes[0x8]) << 0x10) | random;
    random = (@as(u80, bytes[0x9]) << 0x18) | random;
    random = (@as(u80, bytes[0xA]) << 0x20) | random;
    random = (@as(u80, bytes[0xB]) << 0x28) | random;
    random = (@as(u80, bytes[0xC]) << 0x30) | random;
    random = (@as(u80, bytes[0xD]) << 0x38) | random;
    random = (@as(u80, bytes[0xE]) << 0x40) | random;
    random = (@as(u80, bytes[0xF]) << 0x48) | random;

    return Ulid{
        .time = std.mem.bigToNative(u48, time),
        .random = std.mem.bigToNative(u80, random),
    };
}

test fromBytes {
    var expected: Ulid = undefined;

    // Min
    expected.time = 0;
    expected.random = 0;
    const minBytes = &[16]u8{
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    };
    expected = Ulid.fromBytes(minBytes);
    try std.testing.expectEqual(expected.time, 0);
    try std.testing.expectEqual(expected.random, 0);

    // Max
    expected.time = TIME_MAX;
    expected.random = RANDOM_MAX;
    const maxBytes = &[16]u8{
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
    };
    expected = Ulid.fromBytes(maxBytes);
    try std.testing.expectEqual(expected.time, TIME_MAX);
    try std.testing.expectEqual(expected.random, RANDOM_MAX);

    // Max time, zero random
    expected.time = TIME_MAX;
    expected.random = 0;
    const maxTimeZeroRandomBytes = &[16]u8{
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    };
    expected = Ulid.fromBytes(maxTimeZeroRandomBytes);
    try std.testing.expectEqual(expected.time, TIME_MAX);
    try std.testing.expectEqual(expected.random, 0);

    // Zero time, max random
    expected.time = 0;
    expected.random = RANDOM_MAX;
    const zeroTimeMaxRandomBytes = &[16]u8{
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF,
    };
    expected = Ulid.fromBytes(zeroTimeMaxRandomBytes);
    try std.testing.expectEqual(expected.time, 0);
    try std.testing.expectEqual(expected.random, RANDOM_MAX);

    // random sample
    expected.time = 0xDF8D52319C55;
    expected.random = 0x41C3A6B1CBB27CFBE140;
    const randomSampleBytes = &[16]u8{
        // DF:8D:52:31:9C:55:01:C3:26:B1:CB:B2:7C:FB:E1:40
        0xDF, 0x8D, 0x52, 0x31,
        0x9C, 0x55, 0x41, 0xC3,
        0xA6, 0xB1, 0xCB, 0xB2,
        0x7C, 0xFB, 0xE1, 0x40,
    };
    expected = Ulid.fromBytes(randomSampleBytes);
    try std.testing.expectEqual(expected.time, 0xDF8D52319C55);
    try std.testing.expectEqual(expected.random, 0x41C3A6B1CBB27CFBE140);

    // vice versa
    const ulidFromRandomSampleBytes = Ulid.fromBytes(randomSampleBytes);
    try std.testing.expectEqual(ulidFromRandomSampleBytes.time, expected.time);
    try std.testing.expectEqual(ulidFromRandomSampleBytes.random, expected.random);
}

/// Converts the ULID to its canonical string representation using Crockford's Base32 alphabet
/// Returns error.BufferTooSmall if the provided buffer is smaller than ULID_STRING_LENGTH (26)
/// Format: ttttttttttrrrrrrrrrrrrrrrr where:
///   - t is Timestamp (10 characters)
///   - r is Randomness (16 characters)
pub fn toStringAlloc(self: Ulid, allocator: std.mem.Allocator) (Error || std.mem.Allocator.Error)![]u8 {
    var buffer = try allocator.alloc(u8, ULID_STRING_LENGTH);

    const value = self.toInt();
    var remaining = value;

    // Encode from right to left
    var i: usize = ULID_STRING_LENGTH;
    while (i > 0) : (i -= 1) {
        buffer[i - 1] = ALPHABET[@intCast(remaining & 0x1F)];
        remaining >>= 5;
    }

    return buffer;
}

test toStringAlloc {
    var ulid = Ulid.zero();

    // Min
    ulid.time = 0;
    ulid.random = 0;
    const strMin = try ulid.toStringAlloc(std.testing.allocator);
    defer std.testing.allocator.free(strMin);
    try std.testing.expectEqualSlices(u8, "00000000000000000000000000", strMin);

    // Max
    ulid.time = TIME_MAX;
    ulid.random = RANDOM_MAX;
    const strMax = try ulid.toStringAlloc(std.testing.allocator);
    defer std.testing.allocator.free(strMax);
    try std.testing.expectEqualSlices(u8, "7ZZZZZZZZZZZZZZZZZZZZZZZZZ", strMax);

    // Max time, zero random
    ulid.time = TIME_MAX;
    ulid.random = 0;
    const strMaxTimeZeroRandom = try ulid.toStringAlloc(std.testing.allocator);
    defer std.testing.allocator.free(strMaxTimeZeroRandom);
    try std.testing.expectEqualSlices(u8, "7ZZZZZZZZZ0000000000000000", strMaxTimeZeroRandom);

    // Zero time, max random
    ulid.time = 0;
    ulid.random = RANDOM_MAX;
    const strZeroTimeMaxRandom = try ulid.toStringAlloc(std.testing.allocator);
    defer std.testing.allocator.free(strZeroTimeMaxRandom);
    try std.testing.expectEqualSlices(u8, "0000000000ZZZZZZZZZZZZZZZZ", strZeroTimeMaxRandom);

    // random sample
    ulid.time = 0xDF8D52319C55;
    ulid.random = 0x41C3A6B1CBB27CFBE140;
    const randomSample = try ulid.toStringAlloc(std.testing.allocator);
    defer std.testing.allocator.free(randomSample);
    try std.testing.expectEqualSlices(u8, "6ZHN93372N871TDCEBP9YFQRA0", randomSample);

    // vice versa
    const ulidFromRandomSample = try Ulid.fromString(randomSample);
    try std.testing.expectEqual(ulidFromRandomSample.time, ulid.time);
    try std.testing.expectEqual(ulidFromRandomSample.random, ulid.random);
}

pub fn toString(self: Ulid, buffer: []u8) !void {
    std.debug.assert(buffer.len == ULID_STRING_LENGTH);

    const value = self.toInt();
    var remaining = value;

    // Encode from right to left
    var i: usize = ULID_STRING_LENGTH;
    while (i > 0) : (i -= 1) {
        buffer[i - 1] = ALPHABET[@intCast(remaining & 0x1F)];
        remaining >>= 5;
    }
}

/// Initializes the ULID from its canonical string representation
/// Returns error if:
///   - Input length is not ULID_STRING_LENGTH (26)
///   - First character is > '7' (overflow protection)
///   - Any character is not in the Crockford Base32 alphabet
/// Format: ttttttttttrrrrrrrrrrrrrrrr where:
///   - t is Timestamp (10 characters)
///   - r is Randomness (16 characters)
pub fn fromString(encoded: []const u8) !Ulid {
    if (encoded.len != ULID_STRING_LENGTH) {
        return error.InvalidLength;
    }

    // Check first character for overflow (since we encode 130 bits into 128 bits)
    if (encoded[0] > '7') {
        return error.Overflow;
    }

    var value: u128 = 0;

    // Decode each character
    for (encoded) |c| {
        const decoded = ASCII_LOOKUP[c];
        if (decoded == 0xFF) {
            return error.InvalidChar;
        }
        value = (value << 5) | decoded;
    }

    return fromInt(value);
}

test fromString {
    var ulid = Ulid.zero();

    // Min
    const strMin = "00000000000000000000000000";
    ulid = try Ulid.fromString(strMin);
    try std.testing.expectEqual(ulid.time, 0);
    try std.testing.expectEqual(ulid.random, 0);

    // Max
    const strMax = "7ZZZZZZZZZZZZZZZZZZZZZZZZZ";
    ulid = try Ulid.fromString(strMax);
    try std.testing.expectEqual(ulid.time, TIME_MAX);
    try std.testing.expectEqual(ulid.random, RANDOM_MAX);

    // Max time, zero random
    const strMaxTimeZeroRandom = "7ZZZZZZZZZ0000000000000000";
    ulid = try Ulid.fromString(strMaxTimeZeroRandom);
    try std.testing.expectEqual(ulid.time, TIME_MAX);
    try std.testing.expectEqual(ulid.random, 0);

    // Zero time, max random
    const strZeroTimeMaxRandom = "0000000000ZZZZZZZZZZZZZZZZ";
    ulid = try Ulid.fromString(strZeroTimeMaxRandom);
    try std.testing.expectEqual(ulid.time, 0);
    try std.testing.expectEqual(ulid.random, RANDOM_MAX);

    // random sample
    const strSample = "6ZHN93372N871TDCEBP9YFQRA0";
    ulid = try Ulid.fromString(strSample);
    try std.testing.expectEqual(ulid.time, 0xDF8D52319C55);
    try std.testing.expectEqual(ulid.random, 0x41C3A6B1CBB27CFBE140);

    // overflow
    const strOverflow = "8ZZZZZZZZZZZZZZZZZZZZZZZZZ";
    try std.testing.expectError(Error.Overflow, Ulid.fromString(strOverflow));

    // invalid character
    const strInvalidChar = "01ARYZ6S41YYYYYYYYYYYYYYYI";
    try std.testing.expectError(Error.InvalidChar, Ulid.fromString(strInvalidChar));

    // invalid length
    const strInvalidLength = "01ARYZ6S41YYYYYYYYYYYYYYY";
    try std.testing.expectError(Error.InvalidLength, Ulid.fromString(strInvalidLength));
}

// impl std.fmt.Formatter for Ulid
pub fn format(self: Ulid, comptime fmt: []const u8, _: std.fmt.FormatOptions, writer: anytype) @TypeOf(writer).Error!void {
    if (fmt.len == 0 or fmt[0] == 's' or fmt[0] == 'c' or fmt[0] == 'u') {
        var buf: [ULID_STRING_LENGTH]u8 = undefined;
        try self.toString(buf[0..]);
        try writer.writeAll(buf[0..]);
    } else if (fmt[0] == 'd' or fmt[0] == 'x' or fmt[0] == 'X' or fmt[0] == 'b') {
        try writer.print("{" ++ fmt ++ "}", .{self.toInt()});
    } else @compileError("Invalid format specifier `" ++ fmt ++ "` for ULID");
}
