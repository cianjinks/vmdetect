const std = @import("std");
const setup_api = @import("setup_api.zig");
const windows = std.os.windows;
const log = std.log.scoped(.vmdetect);

pub const Error = error{
    Internal,
    OutOfMemory,
};

pub fn checkPCI(allocator: std.mem.Allocator) Error!bool {
    // grab device info pointer for all class types
    const devInfo = setup_api.SetupDiGetClassDevsW(null, null, null, setup_api.DIGCF_ALLCLASSES);
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
        try printDeviceProperties(allocator, devInfo, &data);
        i += 1;
    }

    // free device info
    if (setup_api.SetupDiDestroyDeviceInfoList(devInfo) == 0) {
        log.err("failed to free device info pointer: {}", .{windows.kernel32.GetLastError()});
        return error.Internal;
    }

    return true;
}

// a list of properties to print for each device
const properties = [_]setup_api.SPDRP{
    .DEVICEDESC,
    .HARDWAREID,
    .COMPATIBLEIDS,
    .UNUSED0,
    .SERVICE,
    .UNUSED1,
    .UNUSED2,
    .CLASS,
    .CLASSGUID,
    .DRIVER,
    .CONFIGFLAGS,
    .MFG,
    .FRIENDLYNAME,
    .LOCATION_INFORMATION,
    .PHYSICAL_DEVICE_OBJECT_NAME,
    .CAPABILITIES,
    .UI_NUMBER,
    .UPPERFILTERS,
    .LOWERFILTERS,
    .BUSTYPEGUID,
    .LEGACYBUSTYPE,
    .BUSNUMBER,
    .ENUMERATOR_NAME,
    .SECURITY,
    .SECURITY_SDS,
    .DEVTYPE,
    .EXCLUSIVE,
    .CHARACTERISTICS,
    .ADDRESS,
    .UI_NUMBER_DESC_FORMAT,
    .DEVICE_POWER_DATA,
    .REMOVAL_POLICY,
    .REMOVAL_POLICY_HW_DEFAULT,
    .REMOVAL_POLICY_OVERRIDE,
    .INSTALL_STATE,
    .LOCATION_PATHS,
    .MAXIMUM_PROPERTY,
};

fn printDeviceProperties(allocator: std.mem.Allocator, devInfo: setup_api.HDEVINFO, data: *setup_api.SP_DEVINFO_DATA) !void {
    for (properties) |property| {
        // get data type + required size
        var dataType: setup_api.REG = .NONE;
        var requiredSize: setup_api.DWORD = 0;
        _ = setup_api.SetupDiGetDeviceRegistryPropertyW(devInfo, data.*, property, &dataType, null, 0, &requiredSize);
        if (requiredSize == 0) {
            continue;
        }

        // get property
        const buf = try allocator.alloc(u8, requiredSize);
        defer allocator.free(buf);
        if (setup_api.SetupDiGetDeviceRegistryPropertyW(devInfo, data.*, property, &dataType, @ptrCast(buf.ptr), requiredSize, null) == 0) {
            log.err("failed to get device registry property: {}", .{windows.kernel32.GetLastError()});
            return error.Internal;
        }

        // print property
        try printProperty(allocator, property, dataType, buf);
    }
    log.info("----------------------------", .{});
}

fn printProperty(allocator: std.mem.Allocator, property: setup_api.SPDRP, dataType: setup_api.REG, propBuf: []const u8) !void {
    switch (dataType) {
        .NONE => log.info("{s}: (none)", .{@tagName(property)}),
        .BINARY => log.info("{s}: <binary>", .{@tagName(property)}),
        .DWORD => {
            if (propBuf.len >= 4) {
                log.info("{s}: {d}", .{ @tagName(property), std.mem.readInt(u32, propBuf[0..4], .little) });
            } else {
                log.info("{s}: <invalid data>", .{@tagName(property)});
            }
        },
        .SZ, .EXPAND_SZ => {
            // const utf16: []const u16 = @alignCast(std.mem.bytesAsSlice(u16, propBuf));
            // const buf8 = try allocator.alloc(u8, )
            _ = allocator;
            log.info("{s}: {s}", .{ @tagName(property), propBuf });
        },
        .MULTI_SZ => {},
        else => log.info("{s}: <unusual type {}>", .{ @tagName(property), dataType }),
    }
}
