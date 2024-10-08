#!/usr/bin/env python3

import argparse
import ctypes
import math
import os
import pathlib


class RomHeader(ctypes.Structure):
    SIGNATURE = 0xAA55
    EFI_SIGNATURE = 0xEF1

    class Subsystem:
        EFI_BOOT_SERVICE_DRIVER = 0x0B

    class MachineType:
        X86_64 = 0x8664

    _fields_ = [
        ("signature", ctypes.c_uint16),
        ("initialization_size", ctypes.c_uint16),
        ("efi_signature", ctypes.c_uint32),
        ("efi_subsystem", ctypes.c_uint16),
        ("efi_machine_type", ctypes.c_uint16),
        ("efi_compression_type", ctypes.c_uint16),
        ("_reserved", (ctypes.c_uint8 * 8)),
        ("efi_image_header_offset", ctypes.c_uint16),
        ("pcir_offset", ctypes.c_uint16),
    ]

    def __init__(self):
        self.signature = self.SIGNATURE
        self.efi_signature = self.EFI_SIGNATURE
        self.efi_subsystem = self.Subsystem.EFI_BOOT_SERVICE_DRIVER
        self.efi_machine_type = self.MachineType.X86_64
        self.pcir_offset = ctypes.sizeof(RomHeader)


class PCIR(ctypes.Structure):
    class Indicator:
        LAST_IMAGE = 0x80

    class CodeType:
        EFI_IMAGE = 0x03

    class Revision:
        PCI_2_2 = 0x00
        PCI_3_0 = 0x03

    _fields_ = [
        ("signature", ctypes.c_uint32),
        ("vendor_id", ctypes.c_uint16),
        ("device_id", ctypes.c_uint16),
        ("device_list_offset", ctypes.c_uint16),
        ("length", ctypes.c_uint16),
        ("revision", ctypes.c_uint8),
        ("class_code", ctypes.c_uint8 * 3),
        ("image_length", ctypes.c_uint16),
        ("code_revision", ctypes.c_uint16),
        ("code_type", ctypes.c_uint8),
        ("indicator", ctypes.c_uint8),
        ("max_runtime_image_length", ctypes.c_uint16),
        ("config_utility_code_header_offset", ctypes.c_uint16),
        ("dmtfclp_entry_point_offset", ctypes.c_uint16),
    ]

    def __init__(self, vendor, device):
        self.signature = int.from_bytes(b"PCIR", byteorder="little")
        self.indicator = self.Indicator.LAST_IMAGE
        self.code_type = self.CodeType.EFI_IMAGE
        self.length = ctypes.sizeof(PCIR)
        self.revision = self.Revision.PCI_3_0

        self.vendor_id = int(vendor)
        self.device_id = int(device)


def write_serialized(struct, output):
    serialized = ctypes.cast(
        ctypes.byref(struct), ctypes.POINTER(ctypes.c_char * ctypes.sizeof(struct))
    )
    output.write(serialized.contents.raw)


parser = argparse.ArgumentParser()
parser.add_argument(
    "-v", dest="vendor", type=lambda x: int(x, 16), required=True, help="PCI vendor ID"
)
parser.add_argument(
    "-d", dest="device", type=lambda x: int(x, 16), required=True, help="PCI device ID"
)
parser.add_argument(
    "-i",
    dest="input",
    type=argparse.FileType("rb"),
    required=True,
    help="input DXE file",
)
parser.add_argument(
    "-o", dest="output", type=pathlib.Path, required=True, help="output ROM file"
)

args = parser.parse_args()

print(
    f"Building ROM for {args.vendor:04X}:{args.device:04X} using {args.input.name} to {args.output}"
)

output = open(args.output, "wb")

efi_image_offset = (
    math.ceil((ctypes.sizeof(RomHeader) + ctypes.sizeof(PCIR)) / 512) * 512
)
output_file_size = efi_image_offset + os.stat(args.input.name).st_size
output_file_sectors = math.ceil(output_file_size / 512)

rom_header = RomHeader()
rom_header.efi_image_header_offset = efi_image_offset
rom_header.initialization_size = output_file_sectors

write_serialized(rom_header, output)

pcir = PCIR(args.vendor, args.device)
pcir.image_length = output_file_sectors

write_serialized(pcir, output)
output.write(b"\xff" * (efi_image_offset - output.tell()))

output.write(args.input.read())
output.write(b"\x00" * (output_file_size - output.tell()))

output.close()
