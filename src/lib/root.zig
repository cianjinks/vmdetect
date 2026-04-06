const std = @import("std");
const setup_api = @import("setup_api.zig");
const windows = std.os.windows;
const log = std.log.scoped(.vmdetect);

pub const Error = error{
    // vmdetect
    Internal,
    // allocator
    OutOfMemory,
    // utf
    DanglingSurrogateHalf, ExpectedSecondSurrogateHalf, UnexpectedSecondSurrogateHalf
    //
    };

// This library contains various CheckFunction's which return a Report detailing
// which checks failed, if any.
pub const CheckFunction = *const fn (std.mem.Allocator) Error!Report;

pub const Failure = struct {
    reason: []const u8,
};

pub const Report = struct {
    failures: []Failure,

    pub fn passed(self: Report) bool {
        return self.failures.len == 0;
    }

    pub fn deinit(self: Report, allocator: std.mem.Allocator) void {
        allocator.free(self.failures);
    }
};

// checkDevices checks all devices known to the Windows PnP manager to look for common VM related-devices.
pub fn checkDevices(allocator: std.mem.Allocator) Error!Report {
    var failures = std.ArrayList(Failure).empty;

    // grab device info pointer for all class types
    const devInfo = setup_api.SetupDiGetClassDevsW(null, null, null, .ALLCLASSES);
    if (devInfo == windows.INVALID_HANDLE_VALUE) {
        log.err("got invalid value from SetupDiGetClassDevsW", .{});
        return error.Internal;
    }

    // get data for each
    var data: setup_api.SP_DEVINFO_DATA = .{
        .cbSize = @sizeOf(setup_api.SP_DEVINFO_DATA),
        .InterfaceClassGuid = std.mem.zeroes(setup_api.GUID),
        .Flags = 0,
        .Reserved = 0,
    };
    var i: setup_api.DWORD = 0;
    while (setup_api.SetupDiEnumDeviceInfo(devInfo, i, &data) != 0) {
        try checkDevice(allocator, &failures, devInfo, &data);
        i += 1;
    }

    // free device info
    if (setup_api.SetupDiDestroyDeviceInfoList(devInfo) == 0) {
        log.err("failed to free device info pointer: {}", .{windows.kernel32.GetLastError()});
        return error.Internal;
    }

    return Report{ .failures = try failures.toOwnedSlice(allocator) };
}

fn checkDevice(allocator: std.mem.Allocator, failures: *std.ArrayList(Failure), devInfo: setup_api.HDEVINFO, data: *setup_api.SP_DEVINFO_DATA) !void {
    // get data type + required size
    var dataType: setup_api.DEVPROPTYPE = 0;
    var requiredSize: setup_api.DWORD = 0;
    _ = setup_api.SetupDiGetDevicePropertyW(devInfo, data.*, &setup_api.DEVPKEY_Device_DeviceDesc, &dataType, null, 0, &requiredSize, 0);
    if (requiredSize == 0) {
        // this property is not available for this device
        return;
    }

    // get data
    const buf = try allocator.alloc(u8, requiredSize);
    defer allocator.free(buf);
    if (setup_api.SetupDiGetDevicePropertyW(devInfo, data.*, &setup_api.DEVPKEY_Device_DeviceDesc, &dataType, @ptrCast(buf.ptr), requiredSize, null, 0) == 0) {
        log.err("failed to get device property: {}\n", .{windows.kernel32.GetLastError()});
        return error.Internal;
    }

    _ = failures;
    try printDeviceProperties(allocator, devInfo, data);
}

const DevProperty = struct {
    name: []const u8,
    key: *const setup_api.DEVPROPKEY,
};

// a list of possible device properties
const properties = [_]DevProperty{
    .{ .name = "DeviceDesc", .key = &setup_api.DEVPKEY_Device_DeviceDesc },
    .{ .name = "HardwareIds", .key = &setup_api.DEVPKEY_Device_HardwareIds },
    .{ .name = "CompatibleIds", .key = &setup_api.DEVPKEY_Device_CompatibleIds },
    .{ .name = "Service", .key = &setup_api.DEVPKEY_Device_Service },
    .{ .name = "Class", .key = &setup_api.DEVPKEY_Device_Class },
    .{ .name = "ClassGuid", .key = &setup_api.DEVPKEY_Device_ClassGuid },
    .{ .name = "Driver", .key = &setup_api.DEVPKEY_Device_Driver },
    .{ .name = "ConfigFlags", .key = &setup_api.DEVPKEY_Device_ConfigFlags },
    .{ .name = "Manufacturer", .key = &setup_api.DEVPKEY_Device_Manufacturer },
    .{ .name = "FriendlyName", .key = &setup_api.DEVPKEY_Device_FriendlyName },
    .{ .name = "LocationInfo", .key = &setup_api.DEVPKEY_Device_LocationInfo },
    .{ .name = "PDOName", .key = &setup_api.DEVPKEY_Device_PDOName },
    .{ .name = "Capabilities", .key = &setup_api.DEVPKEY_Device_Capabilities },
    .{ .name = "UINumber", .key = &setup_api.DEVPKEY_Device_UINumber },
    .{ .name = "UpperFilters", .key = &setup_api.DEVPKEY_Device_UpperFilters },
    .{ .name = "LowerFilters", .key = &setup_api.DEVPKEY_Device_LowerFilters },
    .{ .name = "BusTypeGuid", .key = &setup_api.DEVPKEY_Device_BusTypeGuid },
    .{ .name = "LegacyBusType", .key = &setup_api.DEVPKEY_Device_LegacyBusType },
    .{ .name = "BusNumber", .key = &setup_api.DEVPKEY_Device_BusNumber },
    .{ .name = "EnumeratorName", .key = &setup_api.DEVPKEY_Device_EnumeratorName },
    .{ .name = "Security", .key = &setup_api.DEVPKEY_Device_Security },
    .{ .name = "SecuritySDS", .key = &setup_api.DEVPKEY_Device_SecuritySDS },
    .{ .name = "DevType", .key = &setup_api.DEVPKEY_Device_DevType },
    .{ .name = "Exclusive", .key = &setup_api.DEVPKEY_Device_Exclusive },
    .{ .name = "Characteristics", .key = &setup_api.DEVPKEY_Device_Characteristics },
    .{ .name = "Address", .key = &setup_api.DEVPKEY_Device_Address },
    .{ .name = "UINumberDescFormat", .key = &setup_api.DEVPKEY_Device_UINumberDescFormat },
    .{ .name = "PowerData", .key = &setup_api.DEVPKEY_Device_PowerData },
    .{ .name = "RemovalPolicy", .key = &setup_api.DEVPKEY_Device_RemovalPolicy },
    .{ .name = "RemovalPolicyDefault", .key = &setup_api.DEVPKEY_Device_RemovalPolicyDefault },
    .{ .name = "RemovalPolicyOverride", .key = &setup_api.DEVPKEY_Device_RemovalPolicyOverride },
    .{ .name = "InstallState", .key = &setup_api.DEVPKEY_Device_InstallState },
    .{ .name = "LocationPaths", .key = &setup_api.DEVPKEY_Device_LocationPaths },
};

fn printDeviceProperties(allocator: std.mem.Allocator, devInfo: setup_api.HDEVINFO, data: *setup_api.SP_DEVINFO_DATA) !void {
    for (properties) |property| {
        // get data type + required size
        var dataType: setup_api.DEVPROPTYPE = 0;
        var requiredSize: setup_api.DWORD = 0;
        _ = setup_api.SetupDiGetDevicePropertyW(devInfo, data.*, property.key, &dataType, null, 0, &requiredSize, 0);
        if (requiredSize == 0) {
            continue;
        }

        // get property
        const buf = try allocator.alloc(u8, requiredSize);
        defer allocator.free(buf);
        if (setup_api.SetupDiGetDevicePropertyW(devInfo, data.*, property.key, &dataType, @ptrCast(buf.ptr), requiredSize, null, 0) == 0) {
            log.err("failed to get device property: {}\n", .{windows.kernel32.GetLastError()});
            return error.Internal;
        }

        try printProperty(allocator, property.name, dataType, buf);
    }
    log.info("----------------------------\n", .{});
}

fn printProperty(allocator: std.mem.Allocator, name: []const u8, dataType: setup_api.DEVPROPTYPE, propBuf: []const u8) !void {
    switch (dataType) {
        setup_api.DEVPROP_TYPE_EMPTY, setup_api.DEVPROP_TYPE_NULL => log.info("{s}: (none)\n", .{name}),
        setup_api.DEVPROP_TYPE_BINARY => log.info("{s}: <binary>\n", .{name}),
        setup_api.DEVPROP_TYPE_BOOLEAN => {
            if (propBuf.len >= 1) {
                log.info("{s}: {}\n", .{ name, propBuf[0] != 0 });
            } else {
                log.info("{s}: <invalid data>\n", .{name});
            }
        },
        setup_api.DEVPROP_TYPE_UINT32 => {
            if (propBuf.len >= 4) {
                log.info("{s}: {d}\n", .{ name, std.mem.readInt(u32, propBuf[0..4], .little) });
            } else {
                log.info("{s}: <invalid data>\n", .{name});
            }
        },
        setup_api.DEVPROP_TYPE_UINT64 => {
            if (propBuf.len >= 8) {
                log.info("{s}: {d}\n", .{ name, std.mem.readInt(u64, propBuf[0..8], .little) });
            } else {
                log.info("{s}: <invalid data>\n", .{name});
            }
        },
        setup_api.DEVPROP_TYPE_STRING => {
            const utf16: []const u16 = @alignCast(std.mem.bytesAsSlice(u16, propBuf));
            const upperBound: usize = (propBuf.len / 2) * 3;
            const utf8 = try allocator.alloc(u8, upperBound);
            defer allocator.free(utf8);
            const realSize = try std.unicode.utf16LeToUtf8(utf8, utf16);
            // strip null terminator
            const end = if (realSize > 0 and utf8[realSize - 1] == 0) realSize - 1 else realSize;
            log.info("{s}: {s}\n", .{ name, utf8[0..end] });
        },
        setup_api.DEVPROP_TYPE_STRING_LIST => {
            log.info("{s}: [", .{name});
            const utf16: []const u16 = @alignCast(std.mem.bytesAsSlice(u16, propBuf));
            var start: usize = 0;
            var first = true;
            while (start < utf16.len and utf16[start] != 0) {
                var end = start;
                while (end < utf16.len and utf16[end] != 0) {
                    end += 1;
                }
                const upperBound: usize = (end - start) * 3;
                const utf8 = try allocator.alloc(u8, upperBound);
                defer allocator.free(utf8);
                const realSize = try std.unicode.utf16LeToUtf8(utf8, utf16[start..end]);
                if (!first) log.info(", ", .{});
                log.info("\"{s}\"", .{utf8[0..realSize]});
                first = false;
                start = end + 1;
            }
            log.info("]\n", .{});
        },
        else => log.info("{s}: <type 0x{x}>\n", .{ name, dataType }),
    }
}
