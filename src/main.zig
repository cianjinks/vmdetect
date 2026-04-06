const std = @import("std");
const vmdetect = @import("vmdetect");

pub const std_options: std.Options = .{
    .log_level = .debug,
    .logFn = logFn,
};

fn logFn(
    comptime level: std.log.Level,
    comptime scope: @TypeOf(.enum_literal),
    comptime format: []const u8,
    args: anytype,
) void {
    _ = scope;
    _ = level;
    var buf: [1024]u8 = undefined;
    var w = std.fs.File.stdout().writer(&buf);
    w.interface.print(format, args) catch {};
    w.interface.flush() catch {};
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}).init;
    defer _ = gpa.deinit();

    runCheck(gpa.allocator(), "checkDevices", vmdetect.checkDevices);
}

fn runCheck(allocator: std.mem.Allocator, comptime checkName: []const u8, comptime check: vmdetect.CheckFunction) void {
    const report = check(allocator) catch {
        std.log.info("{s}: Error\n", .{checkName});
        return;
    };

    if (report.passed()) {
        std.log.info("{s}: Passed\n", .{checkName});
    } else {
        std.log.info("{s}: Failed\n", .{checkName});
        for (report.failures) |failure| {
            std.log.info("  - {s}\n", .{failure.reason});
        }
    }
}
