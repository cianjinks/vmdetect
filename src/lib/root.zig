const std = @import("std");
const device = @import("device.zig");

pub const Error = error{
    // vmdetect
    Internal,
    // allocator
    OutOfMemory,
    // utf
    DanglingSurrogateHalf,
    ExpectedSecondSurrogateHalf,
    UnexpectedSecondSurrogateHalf,
};

pub const Failure = struct {
    reason: []const u8,

    pub fn init(allocator: std.mem.Allocator, comptime fmt: []const u8, args: anytype) !Failure {
        return .{ .reason = try std.fmt.allocPrint(allocator, fmt, args) };
    }

    pub fn deinit(self: Failure, allocator: std.mem.Allocator) void {
        allocator.free(self.reason);
    }
};

pub const Report = struct {
    failures: []Failure,

    pub fn passed(self: Report) bool {
        return self.failures.len == 0;
    }

    pub fn deinit(self: Report, allocator: std.mem.Allocator) void {
        for (self.failures) |failure| failure.deinit(allocator);
        allocator.free(self.failures);
    }
};

// This library contains various CheckFunction's which return a Report detailing
// which checks failed, if any.
pub const CheckFunction = *const fn (std.mem.Allocator) Error!Report;

// checkDevices checks all devices known to the Windows PnP manager to look for common VM related-devices.
pub const checkDevices = device.checkDevices;

fn checkDrivers() void {
    // TODO
}

fn checkProcesses() void {
    // TODO
}

fn checkCPU() void {
    // TODO
}
