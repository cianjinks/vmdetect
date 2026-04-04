const std = @import("std");
const windows = std.os.windows;

pub const HDEVINFO = windows.PVOID;
pub const GUID = windows.GUID;
pub const PCWSTR = windows.PCWSTR;
pub const HWND = windows.HWND;
pub const DWORD = windows.DWORD;
pub const BOOL = windows.BOOL;
pub const ULONG_PTR = windows.ULONG_PTR;
pub const BYTE = windows.BYTE;

pub const DIGCF_ALLCLASSES: DWORD = 0x00000004;

pub const SPDRP = enum(DWORD) {
    DEVICEDESC = 0x00000000,
    HARDWAREID = 0x00000001,
    COMPATIBLEIDS = 0x00000002,
    UNUSED0 = 0x00000003,
    SERVICE = 0x00000004,
    UNUSED1 = 0x00000005,
    UNUSED2 = 0x00000006,
    CLASS = 0x00000007,
    CLASSGUID = 0x00000008,
    DRIVER = 0x00000009,
    CONFIGFLAGS = 0x0000000A,
    MFG = 0x0000000B,
    FRIENDLYNAME = 0x0000000C,
    LOCATION_INFORMATION = 0x0000000D,
    PHYSICAL_DEVICE_OBJECT_NAME = 0x0000000E,
    CAPABILITIES = 0x0000000F,
    UI_NUMBER = 0x00000010,
    UPPERFILTERS = 0x00000011,
    LOWERFILTERS = 0x00000012,
    BUSTYPEGUID = 0x00000013,
    LEGACYBUSTYPE = 0x00000014,
    BUSNUMBER = 0x00000015,
    ENUMERATOR_NAME = 0x00000016,
    SECURITY = 0x00000017,
    SECURITY_SDS = 0x00000018,
    DEVTYPE = 0x00000019,
    EXCLUSIVE = 0x0000001A,
    CHARACTERISTICS = 0x0000001B,
    ADDRESS = 0x0000001C,
    UI_NUMBER_DESC_FORMAT = 0x0000001D,
    DEVICE_POWER_DATA = 0x0000001E,
    REMOVAL_POLICY = 0x0000001F,
    REMOVAL_POLICY_HW_DEFAULT = 0x00000020,
    REMOVAL_POLICY_OVERRIDE = 0x00000021,
    INSTALL_STATE = 0x00000022,
    LOCATION_PATHS = 0x00000023,
    MAXIMUM_PROPERTY = 0x00000024,
};

pub const REG = enum(DWORD) {
    NONE = 0,
    SZ = 1,
    EXPAND_SZ = 2,
    BINARY = 3,
    DWORD = 4,
    DWORD_BIG_ENDIAN = 5,
    LINK = 6,
    MULTI_SZ = 7,
    RESOURCE_LIST = 8,
    FULL_RESOURCE_DESCRIPTOR = 9,
    RESOURCE_REQUIREMENTS_LIST = 10,
    QWORD = 11,
};

pub extern "setupapi" fn SetupDiGetClassDevsW(
    ClassGuide: ?*const GUID,
    Enumerator: ?PCWSTR,
    hwndParent: ?HWND,
    Flags: DWORD,
) callconv(.winapi) HDEVINFO;

pub const SP_DEVINFO_DATA = extern struct {
    cbSize: DWORD,
    InterfaceClassGuid: GUID,
    Flags: DWORD,
    Reserved: ULONG_PTR,
};

pub extern "setupapi" fn SetupDiEnumDeviceInfo(
    DeviceInfoSet: HDEVINFO,
    MemberIndex: DWORD,
    DeviceInfoData: *SP_DEVINFO_DATA,
) callconv(.winapi) BOOL;

pub extern "setupapi" fn SetupDiDestroyDeviceInfoList(DeviceInfoSet: HDEVINFO) callconv(.winapi) BOOL;

pub extern "setupapi" fn SetupDiGetDeviceRegistryPropertyW(
    DeviceInfoSet: HDEVINFO,
    DeviceInfoData: SP_DEVINFO_DATA,
    Property: SPDRP,
    PropertyRegDataType: ?*REG,
    PropertyBuffer: ?*BYTE,
    PropertyBufferSize: DWORD,
    RequiredSize: ?*DWORD,
) callconv(.winapi) BOOL;
