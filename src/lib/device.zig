const std = @import("std");
const setup_api = @import("setup_api.zig");
const root = @import("root.zig");
const windows = std.os.windows;
const log = std.log.scoped(.vmdetect);

// checkDevices checks all devices known to the Windows PnP manager to look for common VM related-devices.
pub fn checkDevices(allocator: std.mem.Allocator) root.Error!root.Report {
    var failures = std.ArrayList(root.Failure).empty;

    // grab device info pointer for all class types
    const devInfo = setup_api.SetupDiGetClassDevsW(null, null, null, .ALLCLASSES);
    if (devInfo == windows.INVALID_HANDLE_VALUE) {
        log.err("got invalid value from SetupDiGetClassDevsW", .{});
        return error.Internal;
    }

    // get data for each
    var devData: setup_api.SP_DEVINFO_DATA = .{
        .cbSize = @sizeOf(setup_api.SP_DEVINFO_DATA),
        .InterfaceClassGuid = std.mem.zeroes(setup_api.GUID),
        .Flags = 0,
        .Reserved = 0,
    };
    var i: setup_api.DWORD = 0;
    while (setup_api.SetupDiEnumDeviceInfo(devInfo, i, &devData) != 0) {
        try checkDevice(allocator, &failures, devInfo, &devData);
        i += 1;
    }

    // free device info
    if (setup_api.SetupDiDestroyDeviceInfoList(devInfo) == 0) {
        log.err("failed to free device info pointer: {}", .{windows.kernel32.GetLastError()});
        return error.Internal;
    }

    return root.Report{ .failures = try failures.toOwnedSlice(allocator) };
}

fn checkDevice(allocator: std.mem.Allocator, failures: *std.ArrayList(root.Failure), devInfo: setup_api.HDEVINFO, devData: *setup_api.SP_DEVINFO_DATA) !void {
    try checkDeviceStrings(allocator, failures, devInfo, devData);
    // TODO: check PCI
    // TODO: cmos?
    // try printDeviceProperties(allocator, devInfo, devData);
}

const PropWithName = struct {
    name: []const u8,
    key: *const setup_api.DEVPROPKEY,
};

// checkDeviceStrings looks for VM related strings in string device properties
fn checkDeviceStrings(allocator: std.mem.Allocator, failures: *std.ArrayList(root.Failure), devInfo: setup_api.HDEVINFO, devData: *setup_api.SP_DEVINFO_DATA) !void {
    const stringPropertiesToCheck = [_]PropWithName{
        .{ .name = "DeviceDesc", .key = &setup_api.DEVPKEY_Device_DeviceDesc },
        .{ .name = "Manufacturer", .key = &setup_api.DEVPKEY_Device_Manufacturer },
        .{ .name = "FriendlyName", .key = &setup_api.DEVPKEY_Device_FriendlyName },
        .{ .name = "Service", .key = &setup_api.DEVPKEY_Device_Service },
    };

    const substrings = [_][]const u8{
        "qemu",
        // To support virtual IO the hypervisor provides PCI devices: https://pve.proxmox.com/wiki/Windows_VirtIO_Drivers
        "virtio",
        // Manufacturer of many virtualized devices
        "red hat",
        "redhat",
        // When windows is virtualized it loads the `Microsoft Hyper-V Virtualization Infrastructure` driver
        "hyper-v",
        // Qxl is the driver for SPICE: https://pve.proxmox.com/wiki/SPICE
        "qxl",
        // Inter-VM Shared Memory PCI device provided by QEMU
        "ivshmem",
    };

    for (stringPropertiesToCheck) |property| {
        if (getDeviceProperty(allocator, devInfo, devData, property.key) catch null) |deviceDesc| {
            defer allocator.free(deviceDesc.data);

            // get string for property
            if (deviceDesc.type != setup_api.DEVPROP_TYPE_STRING) {
                log.warn("found property which is not a string? {s}\n", .{property.name});
                continue;
            }
            const value = try parseStringProperty(allocator, deviceDesc.data);
            defer allocator.free(value);

            // check for substrings in string (case insensitive)
            for (substrings) |substring| {
                if (std.ascii.indexOfIgnoreCase(value, substring) != null) {
                    // TODO: add a function to get an identifier for a device to provide in the failure reason
                    try failures.append(allocator, try root.Failure.init(allocator, "Found suspicious device property: {s} = {s}", .{ property.name, value }));
                }
            }
        }
    }
}

const DeviceProperty = struct {
    type: setup_api.DEVPROPTYPE,
    typeMod: setup_api.DEVPROPTYPE,
    data: []u8,
};

fn getDeviceProperty(allocator: std.mem.Allocator, devInfo: setup_api.HDEVINFO, devData: *setup_api.SP_DEVINFO_DATA, propertyKey: *const setup_api.DEVPROPKEY) !?DeviceProperty {
    // get data type + required size
    var dataType: setup_api.DEVPROPTYPE = 0;
    var requiredSize: setup_api.DWORD = 0;
    _ = setup_api.SetupDiGetDevicePropertyW(devInfo, devData.*, propertyKey, &dataType, null, 0, &requiredSize, 0);
    if (requiredSize == 0) {
        // this property is not available for this device
        return null;
    }

    // get data
    const buf = try allocator.alloc(u8, requiredSize);
    errdefer allocator.free(buf);
    if (setup_api.SetupDiGetDevicePropertyW(devInfo, devData.*, propertyKey, &dataType, @ptrCast(buf.ptr), requiredSize, null, 0) == 0) {
        log.err("failed to get device property: {}\n", .{windows.kernel32.GetLastError()});
        return error.Internal;
    }

    return DeviceProperty{
        .type = dataType & setup_api.DEVPROP_MASK_TYPE,
        .typeMod = dataType & setup_api.DEVPROP_MASK_TYPEMOD,
        .data = buf,
    };
}

fn parseStringProperty(allocator: std.mem.Allocator, propBuf: []const u8) ![]u8 {
    // windows strings are utf-16 :(
    const utf16: []const u16 = @alignCast(std.mem.bytesAsSlice(u16, propBuf));
    const upperBound = (propBuf.len / 2) * 3;
    const utf8 = try allocator.alloc(u8, upperBound);
    errdefer allocator.free(utf8);
    const realSize = try std.unicode.utf16LeToUtf8(utf8, utf16);
    // strip null terminator
    const end = if (realSize > 0 and utf8[realSize - 1] == 0) realSize - 1 else realSize;
    return allocator.realloc(utf8, end);
}

fn printDeviceProperties(allocator: std.mem.Allocator, devInfo: setup_api.HDEVINFO, data: *setup_api.SP_DEVINFO_DATA) !void {
    const propertiesToPrint = [_]PropWithName{
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

    for (propertiesToPrint) |property| {
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
            const string = try parseStringProperty(allocator, propBuf);
            defer allocator.free(string);
            log.info("{s}: {s}\n", .{ name, string });
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
