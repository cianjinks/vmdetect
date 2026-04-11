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

// ParseHardwareId takes a windows PCI device hardware ID and parses out the various IDs in hex.
// See: https://learn.microsoft.com/en-us/windows-hardware/drivers/install/identifiers-for-pci-devices
pub fn ParseHardwareId(id: []const u8) !PciId {
    var pos: usize = 0;

    // initial prefix
    const prefix = "PCI\\VEN_";
    try checkPrefix(id[pos..], prefix);
    pos += prefix.len;

    // parse vendor ID
    try checkIdLen(id, pos + 4);
    const vendor = try parseHex4(id[pos .. pos + 4]);
    pos += 4;

    // dev prefix
    const devPrefix = "&DEV_";
    try checkPrefix(id[pos..], devPrefix);
    pos += devPrefix.len;

    // parse device ID
    try checkIdLen(id, pos + 4);
    const device = try parseHex4(id[pos .. pos + 4]);
    pos += 4;

    var result = PciId{ .vendor = vendor, .device = device };

    // try subsys prefix
    if (std.mem.startsWith(u8, id[pos..], "&SUBSYS_")) {
        pos += "&SUBSYS_".len;

        // parse subsys ID
        try checkIdLen(id, pos + 4);
        const subsysId = try parseHex4(id[pos .. pos + 4]);
        pos += 4;

        // parse subsys vendor ID
        try checkIdLen(id, pos + 4);
        const subsysVendorId = try parseHex4(id[pos .. pos + 4]);
        pos += 4;

        result.subsys = .{
            .id = subsysId,
            .vendorId = subsysVendorId,
        };
    }

    // try revision prefix
    if (std.mem.startsWith(u8, id[pos..], "&REV_")) {
        pos += "&REV_".len;

        // parse revision
        try checkIdLen(id, pos + 2);
        result.revision = try parseHex2(id[pos .. pos + 2]);
        pos += 2;
    }

    // try class prefix
    if (std.mem.startsWith(u8, id[pos..], "&CC_")) {
        pos += "&CC_".len;

        // parse class base
        try checkIdLen(id, pos + 2);
        const base = try parseHex2(id[pos .. pos + 2]);
        pos += 2;

        // parse sub class
        try checkIdLen(id, pos + 2);
        const sub = try parseHex2(id[pos .. pos + 2]);
        pos += 2;

        var class = Class{ .base = base, .sub = sub, .pi = null };

        // try pi (optional, no prefix separator)
        if (id.len >= pos + 2) {
            class.pi = try parseHex2(id[pos .. pos + 2]);
            pos += 2;
        }

        result.class = class;
    }

    if (pos != id.len) {
        log.err("invalid PCI hardware ID: {s}\n", .{id});
        return error.Internal;
    }

    return result;
}

fn parseHex4(input: []const u8) ![2]u8 {
    return std.mem.toBytes(std.mem.nativeToBig(u16, try std.fmt.parseInt(u16, input, 16)));
}

fn parseHex2(input: []const u8) !u8 {
    return try std.fmt.parseInt(u8, input, 16);
}

fn checkPrefix(input: []const u8, prefix: []const u8) !void {
    if (!std.mem.startsWith(u8, input, prefix)) {
        log.err("PCI hardware ID is missing expected prefix {s}: {s}\n", .{ prefix, input });
        return error.Internal;
    }
}

fn checkIdLen(id: []const u8, requiredLen: usize) !void {
    if (id.len < requiredLen) {
        log.err("PCI hardware ID is too short: {s}\n", .{id});
        return error.Internal;
    }
}
