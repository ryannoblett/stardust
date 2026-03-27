const std = @import("std");

/// Formats a byte slice as printable ASCII, replacing bytes outside the
/// printable ASCII range (0x20–0x7e) with \xNN escape sequences.
/// Use with the `{f}` format specifier, not `{s}`.
///
/// Example:
///   std.log.info("host={f}", .{escapedStr(hostname)});
pub const EscapedStr = struct {
    bytes: []const u8,

    pub fn format(self: EscapedStr, writer: anytype) !void {
        for (self.bytes) |b| {
            if (b >= 0x20 and b <= 0x7e) {
                try writer.writeByte(b);
            } else {
                try writer.print("\\x{x:0>2}", .{b});
            }
        }
    }
};

pub fn escapedStr(bytes: []const u8) EscapedStr {
    return .{ .bytes = bytes };
}
