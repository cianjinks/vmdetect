// A file containing all magic numbers, strings, etc that are used to detect a VM

// deviceSubstrings is a list of magic substrings to look for in device properties
pub const deviceSubstrings = [_][]const u8{
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

// pciIds is a list of known VM related PCI devices
// See: https://pci-ids.ucw.cz/
pub const PciMagic = struct {
    name: []const u8,
    vendor: [2]u8,
    device: ?[2]u8, // device is optional to allow black listing and entire vendor
};
pub const pciIds = [_]PciMagic{
    // Red Hat, Inc. - these vendor IDs are only used for virtio and QEMU
    .{ .name = "Red Hat, Inc.", .vendor = .{ 0x1A, 0xF4 }, .device = null }, // https://admin.pci-ids.ucw.cz/read/PC/1af4
    .{ .name = "Red Hat, Inc.", .vendor = .{ 0x1B, 0x36 }, .device = null }, // https://admin.pci-ids.ucw.cz/read/PC/1b36
    .{ .name = "Red Hat, Inc.", .vendor = .{ 0x69, 0x00 }, .device = null }, // no devices but marked as Red Hat
};
