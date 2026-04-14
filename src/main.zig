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
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2 or args.len > 3) {
        printHelp();
        std.process.exit(1);
    }

    const checks = .{
        .{ "checkDevices", vmdetect.checkDevices },
        .{ "checkCPU", vmdetect.checkCPU },
    };

    if (std.mem.eql(u8, args[1], "check")) {
        const filter: ?[]const u8 = if (args.len == 3) args[2] else null;
        inline for (checks) |entry| {
            if (matchesFilter(entry[0], filter)) runCheck(allocator, entry[0], entry[1]);
        }
    } else if (std.mem.eql(u8, args[1], "debug-print-devices")) {
        vmdetect.debugPrintDevices(allocator) catch {
            std.log.err("Unexpected error encountered...\n", .{});
        };
    } else if (std.mem.eql(u8, args[1], "debug-print-cpuid")) {
        vmdetect.debugPrintCpuid();
    } else {
        printHelp();
    }
}

fn printHelp() void {
    std.log.err(
        \\Usage: vmdetect-cli <command>
        \\
        \\Commands:
        \\  check [checks]         Run checks to determine if this is a virtual machine.
        \\                         Optionally provide a comma-separated list of check names to restrict which run.
        \\  debug-print-devices    Debug output showing a list of PnP devices and their properties
        \\
        \\
    , .{});
}

fn matchesFilter(name: []const u8, filter: ?[]const u8) bool {
    const f = filter orelse return true;
    var it = std.mem.splitScalar(u8, f, ',');
    while (it.next()) |token| {
        if (std.mem.eql(u8, token, name)) return true;
    }
    return false;
}

fn runCheck(allocator: std.mem.Allocator, comptime checkName: []const u8, comptime check: vmdetect.CheckFunction) void {
    const report = check(allocator) catch {
        std.log.err("{s}: Unexpected error encountered...\n", .{checkName});
        return;
    };
    defer report.deinit(allocator);

    if (report.passed()) {
        std.log.info("{s}: Passed\n", .{checkName});
    } else {
        std.log.info("{s}: Failed\n", .{checkName});
        for (report.failures) |failure| {
            std.log.info("  - {s}\n", .{failure.reason});
        }
    }
}
