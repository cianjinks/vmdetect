const std = @import("std");
const root = @import("root.zig");
const log = std.log.scoped(.vmdetect);

pub fn checkCPU(allocator: std.mem.Allocator) root.Error!root.Report {
    var failures = std.ArrayList(root.Failure).empty;
    errdefer {
        for (failures.items) |f| f.deinit(allocator);
        failures.deinit(allocator);
    }

    // cpuid check for hypervisor
    const l0 = cpuid(0x0);
    if (l0.maxLeaf > 0) {
        const l1 = cpuid(0x1);
        if (l1.hypervisor == 1) {
            // extract hypervisor ID for display
            const hl0 = cpuid(0x40000000);
            try failures.append(allocator, try root.Failure.init(allocator, "Hypervisor bit is present in CPUID: id = {s}", .{hl0.hypervisorId}));
        }
    } else {
        log.warn("cpuid does not support 0x1 leaf?: {d}", .{l0.maxLeaf});
    }

    return root.Report{ .failures = try failures.toOwnedSlice(allocator) };
}

// https://en.wikipedia.org/wiki/CPUID#EAX=0:_Highest_Function_Parameter_and_Manufacturer_ID
const Leaf0 = struct {
    maxLeaf: u32,
    vendor: [12]u8,

    pub fn parse(raw: RawResult) Leaf0 {
        var vendor: [12]u8 = undefined;
        std.mem.writeInt(u32, vendor[0..4], raw.ebx, .little);
        std.mem.writeInt(u32, vendor[4..8], raw.edx, .little);
        std.mem.writeInt(u32, vendor[8..12], raw.ecx, .little);
        return .{ .maxLeaf = raw.eax, .vendor = vendor };
    }
};

const Leaf1 = packed struct {
    // eax
    steppingId: u4,
    model: u4,
    familyId: u4,
    processorType: u2,
    _res0: u2,
    extModelId: u4,
    extFamilyId: u8,
    _res1: u4,
    // ebx
    brandIndex: u8,
    clflushSize: u8,
    logicalProc: u8,
    localApicId: u8,
    // ecx
    _todo0: u31,
    hypervisor: u1,
    // edx
    _todo1: u32,

    pub fn parse(raw: RawResult) Leaf1 {
        return @bitCast(raw);
    }
};

const LeafHypervisor0 = struct {
    maxLeaf: u32,
    hypervisorId: [12]u8,

    pub fn parse(raw: RawResult) LeafHypervisor0 {
        var id: [12]u8 = undefined;
        std.mem.writeInt(u32, id[0..4], raw.ebx, .little);
        std.mem.writeInt(u32, id[4..8], raw.edx, .little);
        std.mem.writeInt(u32, id[8..12], raw.ecx, .little);
        return .{ .maxLeaf = raw.eax, .hypervisorId = id };
    }
};

fn LeafType(comptime leaf: u32) type {
    return switch (leaf) {
        0x0 => Leaf0,
        0x1 => Leaf1,
        0x40000000 => LeafHypervisor0,
        else => @compileError("unsupported cpuid leaf"),
    };
}

fn cpuid(comptime leaf: u32) LeafType(leaf) {
    const raw = cpuidRaw(leaf, 0);
    return LeafType(leaf).parse(raw);
}

const RawResult = extern struct {
    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
};

fn cpuidRaw(leaf: u32, subleaf: u32) RawResult {
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
