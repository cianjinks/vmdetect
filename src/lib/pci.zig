const std = @import("std");
const root = @import("root.zig");
const log = std.log.scoped(.vmdetect);

pub const Subsys = struct {
    id: [2]u8,
    vendorId: [2]u8,
};

pub const Class = struct {
    base: u8,
    sub: u8,
    pi: ?u8, // programming interface
};

pub const PciId = struct {
    vendor: [2]u8,
    device: [2]u8,
    subsys: ?Subsys = null,
    revision: ?u8 = null,
    class: ?Class = null,
};

// parseHardwareId takes a windows PCI device hardware ID and parses out the various IDs in hex.
// See: https://learn.microsoft.com/en-us/windows-hardware/drivers/install/identifiers-for-pci-devices
pub fn parseHardwareId(id: []const u8) !PciId {
    var p = Parser{ .input = id };

    try p.consumePrefix("PCI\\VEN_");
    const vendor = try p.consumeHex(2);
    try p.consumePrefix("&DEV_");
    const device = try p.consumeHex(2);

    var result = PciId{ .vendor = vendor, .device = device };

    if (p.tryConsumePrefix("&SUBSYS_")) {
        result.subsys = .{
            .id = try p.consumeHex(2),
            .vendorId = try p.consumeHex(2),
        };
    }

    if (p.tryConsumePrefix("&REV_")) {
        result.revision = (try p.consumeHex(1))[0];
    }

    if (p.tryConsumePrefix("&CC_")) {
        var class = Class{ .base = (try p.consumeHex(1))[0], .sub = (try p.consumeHex(1))[0], .pi = null };
        if (try p.tryConsumeHex(1)) |pi| class.pi = pi[0];
        result.class = class;
    }

    if (!p.done()) {
        log.err("invalid PCI hardware ID: failed to parse all bytes: {s}\n", .{id});
        return error.Internal;
    }

    return result;
}

const Parser = struct {
    input: []const u8,
    pos: usize = 0,

    fn consumePrefix(self: *Parser, prefix: []const u8) !void {
        if (!std.mem.startsWith(u8, self.input[self.pos..], prefix)) {
            log.err("PCI hardware ID is missing expected prefix {s}: {s}\n", .{ prefix, self.input[self.pos..] });
            return error.Internal;
        }
        self.pos += prefix.len;
    }

    fn tryConsumePrefix(self: *Parser, prefix: []const u8) bool {
        if (!std.mem.startsWith(u8, self.input[self.pos..], prefix)) return false;
        self.pos += prefix.len;
        return true;
    }

    fn consumeHex(self: *Parser, comptime n: usize) ![n]u8 {
        if (self.pos + n * 2 > self.input.len) {
            log.err("invalid PCI hardware ID: failed to find hex: {s}\n", .{self.input});
            return error.Internal;
        }
        var out: [n]u8 = undefined;
        for (0..n) |i| {
            out[i] = try std.fmt.parseInt(u8, self.input[self.pos + i * 2 .. self.pos + i * 2 + 2], 16);
        }
        self.pos += n * 2;
        return out;
    }

    fn tryConsumeHex(self: *Parser, comptime n: usize) !?[n]u8 {
        if (self.pos + n * 2 > self.input.len) return null;
        return try self.consumeHex(n);
    }

    fn done(self: *Parser) bool {
        return self.pos == self.input.len;
    }
};
