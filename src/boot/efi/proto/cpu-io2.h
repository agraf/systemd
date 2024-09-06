/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "efi.h"

#define EFI_CPU_IO2_PROTOCOL_GUID \
        GUID_DEF(0xad61f191, 0xae5f, 0x4c0e, 0xb9, 0xfa, 0xe8, 0x69, 0xd2, 0x88, 0xc6, 0x4f)

typedef struct _EFI_CPU_IO2_PROTOCOL EFI_CPU_IO2_PROTOCOL;

typedef enum {
        EfiCpuIoWidthUint8,
        EfiCpuIoWidthUint16,
        EfiCpuIoWidthUint32,
        EfiCpuIoWidthUint64,
        EfiCpuIoWidthFifoUint8,
        EfiCpuIoWidthFifoUint16,
        EfiCpuIoWidthFifoUint32,
        EfiCpuIoWidthFifoUint64,
        EfiCpuIoWidthFillUint8,
        EfiCpuIoWidthFillUint16,
        EfiCpuIoWidthFillUint32,
        EfiCpuIoWidthFillUint64,
        EfiCpuIoWidthMaximum
} EFI_CPU_IO_PROTOCOL_WIDTH;

typedef EFI_STATUS(EFIAPI *EFI_CPU_IO_PROTOCOL_IO_MEM)(
                EFI_CPU_IO2_PROTOCOL *This,
                EFI_CPU_IO_PROTOCOL_WIDTH Width,
                uint64_t Address,
                size_t Count,
                void *Buffer);

typedef struct {
        EFI_CPU_IO_PROTOCOL_IO_MEM Read;
        EFI_CPU_IO_PROTOCOL_IO_MEM Write;
} EFI_CPU_IO_PROTOCOL_ACCESS;

struct _EFI_CPU_IO2_PROTOCOL {
        EFI_CPU_IO_PROTOCOL_ACCESS Mem;
        EFI_CPU_IO_PROTOCOL_ACCESS Io;
};
