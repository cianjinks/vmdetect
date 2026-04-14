const std = @import("std");
const root = @import("root.zig");
const log = std.log.scoped(.vmdetect);

pub fn checkCPU(allocator: std.mem.Allocator) root.Error!root.Report {
    var failures = std.ArrayList(root.Failure).empty;
    // TODO
    return root.Report{ .failures = try failures.toOwnedSlice(allocator) };
}

pub fn debugPrintCpuid() void {
    const result = cpuid(0x0, 0x0);
    log.info("eax: 0x{x}\n", .{result.eax});
    log.info("ebx: 0x{x}\n", .{result.ebx});
    log.info("ecx: 0x{x}\n", .{result.ecx});
    log.info("edx: 0x{x}\n", .{result.edx});

    var vendor: [12]u8 = undefined;
    std.mem.writeInt(u32, vendor[0..4], result.ebx, .little);
    std.mem.writeInt(u32, vendor[4..8], result.edx, .little);
    std.mem.writeInt(u32, vendor[8..12], result.ecx, .little);
    log.info("vendor: {s}\n", .{vendor});
}

const CpuidResult = struct {
    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
};

fn cpuid(leaf: u32, subleaf: u32) CpuidResult {
    var eax: u32 = undefined;
    var ebx: u32 = undefined;
    var ecx: u32 = undefined;
    var edx: u32 = undefined;

    asm volatile ("cpuid"
        : [eax] "={eax}" (eax),
          [ebx] "={ebx}" (ebx),
          [ecx] "={ecx}" (ecx),
          [edx] "={edx}" (edx),
        : [leaf] "{eax}" (leaf),
          [subleaf] "{ecx}" (subleaf),
    );

    return .{ .eax = eax, .ebx = ebx, .ecx = ecx, .edx = edx };
}
