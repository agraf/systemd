/* SPDX-License-Identifier: BSD-2-Clause-Patent */
/*
  Port to systemd-boot
  Copyright (C) 2024 Matter Labs, Harald Hoyer <hh@matterlabs.dev>

  Original source from the EDK2 project
  Copyright (C) 2013, Red Hat, Inc.
  Copyright (c) 2011 - 2013, Intel Corporation. All rights reserved.
  Copyright (c) 2017, Advanced Micro Devices. All rights reserved.
*/
#pragma once

#include "efi.h"
#include "proto/cpu-io2.h"

//
// The size, in bytes, of names of firmware configuration files, including at
// least one terminating NUL byte.
//
#define QEMU_FW_CFG_FNAME_SIZE  56

typedef struct {
        EFI_PHYSICAL_ADDRESS    FwCfgSelectorAddress;
        EFI_PHYSICAL_ADDRESS    FwCfgDataAddress;
        EFI_PHYSICAL_ADDRESS    FwCfgDmaAddress;
} QEMU_FW_CFG_RESOURCE;


//
// Numerically defined keys.
//
typedef enum {
        QemuFwCfgItemSignature          = 0x0000,
        QemuFwCfgItemInterfaceVersion   = 0x0001,
        QemuFwCfgItemSystemUuid         = 0x0002,
        QemuFwCfgItemRamSize            = 0x0003,
        QemuFwCfgItemGraphicsEnabled    = 0x0004,
        QemuFwCfgItemSmpCpuCount        = 0x0005,
        QemuFwCfgItemMachineId          = 0x0006,
        QemuFwCfgItemKernelAddress      = 0x0007,
        QemuFwCfgItemKernelSize         = 0x0008,
        QemuFwCfgItemKernelCommandLine  = 0x0009,
        QemuFwCfgItemInitrdAddress      = 0x000a,
        QemuFwCfgItemInitrdSize         = 0x000b,
        QemuFwCfgItemBootDevice         = 0x000c,
        QemuFwCfgItemNumaData           = 0x000d,
        QemuFwCfgItemBootMenu           = 0x000e,
        QemuFwCfgItemMaximumCpuCount    = 0x000f,
        QemuFwCfgItemKernelEntry        = 0x0010,
        QemuFwCfgItemKernelData         = 0x0011,
        QemuFwCfgItemInitrdData         = 0x0012,
        QemuFwCfgItemCommandLineAddress = 0x0013,
        QemuFwCfgItemCommandLineSize    = 0x0014,
        QemuFwCfgItemCommandLineData    = 0x0015,
        QemuFwCfgItemKernelSetupAddress = 0x0016,
        QemuFwCfgItemKernelSetupSize    = 0x0017,
        QemuFwCfgItemKernelSetupData    = 0x0018,
        QemuFwCfgItemFileDir            = 0x0019,

        QemuFwCfgItemX86AcpiTables   = 0x8000,
        QemuFwCfgItemX86SmbiosTables = 0x8001,
        QemuFwCfgItemX86Irq0Override = 0x8002,
        QemuFwCfgItemX86E820Table    = 0x8003,
        QemuFwCfgItemX86HpetData     = 0x8004,
} FIRMWARE_CONFIG_ITEM;

bool EFIAPI QemuFwCfgIsAvailable(void);
void EFIAPI QemuFwCfgSelectItem(FIRMWARE_CONFIG_ITEM QemuFwCfgItem);
void EFIAPI QemuFwCfgReadBytes(size_t Size, void *Buffer);
void EFIAPI QemuFwCfgWriteBytes(size_t Size, void *Buffer);
void EFIAPI QemuFwCfgSkipBytes(size_t Size);
uint8_t EFIAPI QemuFwCfgRead8(void);
uint16_t EFIAPI QemuFwCfgRead16(void);
uint32_t EFIAPI QemuFwCfgRead32(void);
uint64_t EFIAPI QemuFwCfgRead64(void);
EFI_STATUS EFIAPI QemuFwCfgFindFile(const char *Name, FIRMWARE_CONFIG_ITEM *Item, size_t *Size);
void EFIAPI MapFwCfgDmaDataBuffer(
                bool IsWrite,
                void *HostAddress,
                uint32_t Size,
                EFI_PHYSICAL_ADDRESS *DeviceAddress,
                void **MapInfo);
void EFIAPI UnmapFwCfgDmaDataBuffer(void *Mapping);
