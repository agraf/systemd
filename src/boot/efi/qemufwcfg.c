/* SPDX-License-Identifier: BSD-2-Clause-Patent */
/*
  Port to systemd-boot
  Copyright (C) 2024 Matter Labs, Harald Hoyer <hh@matterlabs.dev>

  Original source from the EDK2 project
  Copyright (C) 2013, Red Hat, Inc.
  Copyright (c) 2011 - 2013, Intel Corporation. All rights reserved.
  Copyright (c) 2017, Advanced Micro Devices. All rights reserved.
*/
#include "qemufwcfg.h"
#include "log.h"
#include "proto/iommu.h"
#include "vmm.h"

#if defined(__i386__) || defined(__x86_64__)
//
// Define macros to build data structure signatures from characters.
//
#        define SIGNATURE_16(A, B) ((A) | (B << 8))
#        define SIGNATURE_32(A, B, C, D) (SIGNATURE_16(A, B) | (SIGNATURE_16(C, D) << 16))
#        define SIGNATURE_64(A, B, C, D, E, F, G, H) \
                (SIGNATURE_32(A, B, C, D) | ((uint64_t) (SIGNATURE_32(E, F, G, H)) << 32))

#        define FW_CFG_F_DMA 0x00000002

#        define FW_CFG_DMA_CTL_ERROR 0x01
#        define FW_CFG_DMA_CTL_READ 0x02
#        define FW_CFG_DMA_CTL_SKIP 0x04
#        define FW_CFG_DMA_CTL_SELECT 0x08
#        define FW_CFG_DMA_CTL_WRITE 0x10

//
// The fw_cfg registers can be found at these IO Ports, on the IO-mapped
// platforms (Ia32 and X64).
//
#        define FW_CFG_IO_SELECTOR 0x510
#        define FW_CFG_IO_DATA 0x511
#        define FW_CFG_IO_DMA_ADDRESS 0x514

//
// Communication structure for the DMA access method. All fields are encoded in
// big endian.
//
#        pragma pack(1)
typedef struct {
        uint32_t Control;
        uint32_t Length;
        uint64_t Address;
} FW_CFG_DMA_ACCESS;
#        pragma pack()

static EFI_CPU_IO2_PROTOCOL *mCpuIo = NULL;
static EDKII_IOMMU_PROTOCOL *mIoMmuProtocol = NULL;
static bool mQemuFwCfgProbed = false;
static bool mQemuFwCfgSupported = false;
static bool mQemuFwCfgDmaSupported = false;
static bool mQemuFwCfgInCCChecked = false;
static bool mQemuFwCfgInCC = false;

static EFI_STATUS EFIAPI IoLibConstructor(void) {
        EFI_STATUS Status;

        Status = BS->LocateProtocol(MAKE_GUID_PTR(EFI_CPU_IO2_PROTOCOL), NULL, (void **) &mCpuIo);
        return Status;
}

static EFI_STATUS EFIAPI IoMmuLibConstructor(void) {
        EFI_STATUS Status;

        Status = BS->LocateProtocol(MAKE_GUID_PTR(EDKII_IOMMU_PROTOCOL), NULL, (void **) &mIoMmuProtocol);
        return Status;
}

static bool InternalQemuFwCfgInCC(void) {
        if (!mQemuFwCfgInCCChecked) {
                mQemuFwCfgInCC = is_confidential_vm();
        }
        return mQemuFwCfgInCC;
}

static void EFIAPI IoReadFifoWorker(size_t Port, EFI_CPU_IO_PROTOCOL_WIDTH Width, size_t Count, void *Buffer) {
        EFI_STATUS Status;

        ASSERT_PTR(mCpuIo);
        Status = mCpuIo->Io.Read(mCpuIo, Width, Port, Count, Buffer);
        assert(Status == EFI_SUCCESS);
}

static void EFIAPI IoReadFifo8(size_t Port, size_t Count, void *Buffer) {
        IoReadFifoWorker(Port, EfiCpuIoWidthFifoUint8, Count, Buffer);
}

static uint16_t EFIAPI IoWriteWorker(size_t Port, EFI_CPU_IO_PROTOCOL_WIDTH Width, uint64_t Data) {
        EFI_STATUS Status;

        ASSERT_PTR(mCpuIo);
        Status = mCpuIo->Io.Write(mCpuIo, Width, Port, 1, &Data);
        assert(Status == EFI_SUCCESS);
        return Data;
}

static void EFIAPI IoWriteFifo8(size_t Port, size_t Count, void *Buffer) {
        uint8_t *Buffer8;

        Buffer8 = (uint8_t *) Buffer;
        while (Count-- > 0) {
                IoWriteWorker(Port, EfiCpuIoWidthUint8, *Buffer8++);
        }
}

static uint16_t EFIAPI IoWrite16(size_t Port, uint16_t Value) {
        return (uint16_t) IoWriteWorker(Port, EfiCpuIoWidthUint16, Value);
}

static uint32_t EFIAPI IoWrite32(size_t Port, uint32_t Value) {
        return (uint32_t) IoWriteWorker(Port, EfiCpuIoWidthUint32, Value);
}

static EFI_STATUS EFIAPI QemuFwCfgProbe(void) {
        uint32_t Signature;
        uint32_t Revision;

        if (!in_hypervisor())
                return EFI_UNSUPPORTED;

        if (IoLibConstructor() != EFI_SUCCESS)
                return EFI_UNSUPPORTED;

        // Use direct Io* calls for probing to avoid recursion.
        IoWrite16(FW_CFG_IO_SELECTOR, (uint16_t) QemuFwCfgItemSignature);
        IoReadFifo8(FW_CFG_IO_DATA, sizeof Signature, &Signature);
        IoWrite16(FW_CFG_IO_SELECTOR, (uint16_t) QemuFwCfgItemInterfaceVersion);
        IoReadFifo8(FW_CFG_IO_DATA, sizeof Revision, &Revision);

        if ((Signature == SIGNATURE_32('Q', 'E', 'M', 'U')) && (Revision >= 1)) {
                if ((Revision & FW_CFG_F_DMA) == 0) {
                        log_error("QemuFwCfg interface (IO Port) is supported.");
                } else {
                        mQemuFwCfgDmaSupported = true;
                        log_error("QemuFwCfg interface (DMA) is supported.");
                }
                log_wait();
                mQemuFwCfgSupported = true;
        } else {
                log_error("no QEMU");
                log_wait();
                return EFI_UNSUPPORTED;
        }

        if (mQemuFwCfgDmaSupported && InternalQemuFwCfgInCC()) {
                //
                // IoMmuDxe driver must have installed the IOMMU protocol. If we are not
                // able to locate the protocol then something must have gone wrong.
                //
                if (IoMmuLibConstructor() != EFI_SUCCESS) {
                        log_error("IoMmuLibConstructor failed");
                        EFI_STATUS Status;

                        Status = BS->LocateProtocol(
                                        MAKE_GUID_PTR(IOMMU_ABSENT_PROTOCOL), NULL, (void **) &mIoMmuProtocol);
                        if (Status != EFI_SUCCESS) {
                                log_error("IOMMU_ABSENT_PROTOCOL failed");
                        } else {
                                log_error("IOMMU_ABSENT_PROTOCOL present");
                        }
                        return EFI_UNSUPPORTED;
                }
        }

        return EFI_SUCCESS;
}

bool EFIAPI QemuFwCfgIsAvailable(void) {
        if (mQemuFwCfgProbed)
                return mQemuFwCfgSupported;

        mQemuFwCfgProbed = true;
        return EFI_SUCCESS == QemuFwCfgProbe();
}

#else
bool EFIAPI QemuFwCfgIsAvailable(void) {
        return false
}
#endif

static uint16_t EFIAPI SwapBytes16(uint16_t Value) {
        return (uint16_t) ((Value << 8) | (Value >> 8));
}

static uint32_t EFIAPI SwapBytes32(uint32_t Value) {
        uint32_t LowerBytes;
        uint32_t HigherBytes;

        LowerBytes = (uint32_t) SwapBytes16((uint16_t) Value);
        HigherBytes = (uint32_t) SwapBytes16((uint16_t) (Value >> 16));

        return (LowerBytes << 16 | HigherBytes);
}

static uint64_t EFIAPI SwapBytes64(uint64_t Operand) {
        uint64_t LowerBytes;
        uint64_t HigherBytes;

        LowerBytes = (uint64_t) SwapBytes32((uint32_t) Operand);
        HigherBytes = (uint64_t) SwapBytes32((uint32_t) (Operand >> 32));

        return (LowerBytes << 32 | HigherBytes);
}


static uint64_t EFIAPI RShiftU64(uint64_t Operand, size_t Count) {
        return Operand >> Count;
}

void EFIAPI QemuFwCfgSelectItem(FIRMWARE_CONFIG_ITEM QemuFwCfgItem) {
        if (!QemuFwCfgIsAvailable()) {
                return;
        }

        IoWrite16(FW_CFG_IO_SELECTOR, (uint16_t) (size_t) QemuFwCfgItem);
}

static void ZeroMem(void *Buffer, size_t Length) {
        uint8_t *Pointer8;
        Pointer8 = (uint8_t *) Buffer;

        if (Length == 0)
                return;
        if (Buffer == NULL)
                return;
        while (Length-- > 0) {
                *(Pointer8++) = 0;
        }
}

static void EFIAPI MemoryFence(void) {
        __asm__ __volatile__("" ::: "memory");
}


/**
  Function is used for allocating a bi-directional FW_CFG_DMA_ACCESS used
  between Host and device to exchange the information. The buffer must be free'd
  using FreeFwCfgDmaAccessBuffer ().

**/
static void AllocFwCfgDmaAccessBuffer(void **Access, void **MapInfo) {
        size_t Size;
        size_t NumPages;
        EFI_STATUS Status;
        void *HostAddress;
        EFI_PHYSICAL_ADDRESS DmaAddress;
        void *Mapping;

        Size = sizeof(FW_CFG_DMA_ACCESS);
        NumPages = EFI_SIZE_TO_PAGES(Size);

        if (mIoMmuProtocol == NULL) {
                assert(IoMmuLibConstructor() == EFI_SUCCESS);
        }

        //
        // As per UEFI spec, in order to map a host address with
        // BusMasterCommonBuffer64, the buffer must be allocated using the IOMMU
        // AllocateBuffer()
        //
        Status = mIoMmuProtocol->AllocateBuffer(
                        mIoMmuProtocol,
                        AllocateAnyPages,
                        EfiBootServicesData,
                        NumPages,
                        &HostAddress,
                        EDKII_IOMMU_ATTRIBUTE_DUAL_ADDRESS_CYCLE);
        if (EFIERR(Status)) {
                log_error("Failed to allocate FW_CFG_DMA_ACCESS");
                assert(false);
                freeze();
        }

        //
        // Avoid exposing stale data even temporarily: zero the area before mapping
        // it.
        //
        ZeroMem(HostAddress, Size);

        //
        // Map the host buffer with BusMasterCommonBuffer64
        //
        Status = mIoMmuProtocol->Map(
                        mIoMmuProtocol,
                        EdkiiIoMmuOperationBusMasterCommonBuffer64,
                        HostAddress,
                        &Size,
                        &DmaAddress,
                        &Mapping);
        if (EFIERR(Status)) {
                mIoMmuProtocol->FreeBuffer(mIoMmuProtocol, NumPages, HostAddress);
                log_error("Failed to Map() FW_CFG_DMA_ACCESS");
                assert(false);
                freeze();
        }

        if (Size < sizeof(FW_CFG_DMA_ACCESS)) {
                mIoMmuProtocol->Unmap(mIoMmuProtocol, Mapping);
                mIoMmuProtocol->FreeBuffer(mIoMmuProtocol, NumPages, HostAddress);
                log_error("Failed to Map() - requested 0x%lx got 0x%lx",
                          (uint64_t) sizeof(FW_CFG_DMA_ACCESS),
                          (uint64_t) Size);
                assert(false);
                freeze();
        }

        *Access = HostAddress;
        *MapInfo = Mapping;
}

/**
  Function is to used for freeing the Access buffer allocated using
  AllocFwCfgDmaAccessBuffer()

**/
static void FreeFwCfgDmaAccessBuffer(void *Access, void *Mapping) {
        size_t NumPages;
        EFI_STATUS Status;

        if (mIoMmuProtocol == NULL) {
                assert(IoMmuLibConstructor() == EFI_SUCCESS);
        }

        NumPages = EFI_SIZE_TO_PAGES(sizeof(FW_CFG_DMA_ACCESS));

        Status = mIoMmuProtocol->Unmap(mIoMmuProtocol, Mapping);
        if (EFIERR(Status)) {
                log_error("Failed to UnMap() Mapping 0x%lx", (uint64_t) (size_t) Mapping);
                assert(false);
                freeze();
        }

        Status = mIoMmuProtocol->FreeBuffer(mIoMmuProtocol, NumPages, Access);
        if (EFIERR(Status)) {
                log_error("Failed to Free() 0x%lx\n", (uint64_t) (size_t) Access);
                assert(false);
                freeze();
        }
}

/**
  Function is used for mapping host address to device address. The buffer must
  be unmapped with UnmapDmaDataBuffer ().

**/
void EFIAPI MapFwCfgDmaDataBuffer(
                bool IsWrite,
                void *HostAddress,
                uint32_t Size,
                EFI_PHYSICAL_ADDRESS *DeviceAddress,
                void **MapInfo) {
        EFI_STATUS Status;
        size_t NumberOfBytes;
        void *Mapping;
        EFI_PHYSICAL_ADDRESS PhysicalAddress;

        if (mIoMmuProtocol == NULL) {
                assert(IoMmuLibConstructor() == EFI_SUCCESS);
        }

        NumberOfBytes = Size;
        Status = mIoMmuProtocol->Map(
                        mIoMmuProtocol,
                        (IsWrite ? EdkiiIoMmuOperationBusMasterRead64 : EdkiiIoMmuOperationBusMasterWrite64),
                        HostAddress,
                        &NumberOfBytes,
                        &PhysicalAddress,
                        &Mapping);
        if (EFIERR(Status)) {
                log_error("Failed to Map() Address 0x%lx Size 0x%lx\n",
                          (uint64_t) (size_t) HostAddress,
                          (uint64_t) Size);
                assert(false);
                freeze();
        }

        if (NumberOfBytes < Size) {
                mIoMmuProtocol->Unmap(mIoMmuProtocol, Mapping);
                log_error("Failed to Map() - requested 0x%x got 0x%lx\n", Size, (uint64_t) NumberOfBytes);
                assert(false);
                freeze();
        }

        *DeviceAddress = PhysicalAddress;
        *MapInfo = Mapping;
}

void EFIAPI UnmapFwCfgDmaDataBuffer(void *Mapping) {
        EFI_STATUS Status;

        if (mIoMmuProtocol == NULL) {
                assert(IoMmuLibConstructor() == EFI_SUCCESS);
        }

        Status = mIoMmuProtocol->Unmap(mIoMmuProtocol, Mapping);
        if (EFIERR(Status)) {
                log_error("Failed to UnMap() Mapping 0x%lx\n", (uint64_t) (size_t) Mapping);
                assert(false);
                freeze();
        }
}

static void InternalQemuFwCfgDmaBytes(uint32_t Size, void *Buffer, uint32_t Control) {
        volatile FW_CFG_DMA_ACCESS LocalAccess;
        volatile FW_CFG_DMA_ACCESS *Access;
        uint32_t AccessHigh, AccessLow;
        uint32_t Status;
        void *DataBuffer;

        assert(Control == FW_CFG_DMA_CTL_WRITE || Control == FW_CFG_DMA_CTL_READ ||
               Control == FW_CFG_DMA_CTL_SKIP);

        if (Size == 0) {
                return;
        }

        Access = &LocalAccess;
        DataBuffer = Buffer;

        void *AccessMapping = NULL, *DataMapping = NULL;

        //
        // When SEV or TDX is enabled, map Buffer to DMA address before issuing the DMA
        // request
        //
        if (InternalQemuFwCfgInCC()) {
                void *AccessBuffer;
                EFI_PHYSICAL_ADDRESS DataBufferAddress;

                //
                // Allocate DMA Access buffer
                //
                AllocFwCfgDmaAccessBuffer(&AccessBuffer, &AccessMapping);

                Access = AccessBuffer;

                //
                // Map actual data buffer
                //
                if (Control != FW_CFG_DMA_CTL_SKIP) {
                        MapFwCfgDmaDataBuffer(
                                        Control == FW_CFG_DMA_CTL_WRITE,
                                        Buffer,
                                        Size,
                                        &DataBufferAddress,
                                        &DataMapping);

                        DataBuffer = (void *) (size_t) DataBufferAddress;
                }
        }
        Access->Control = SwapBytes32(Control);
        Access->Length = SwapBytes32(Size);
        Access->Address = SwapBytes64((size_t) DataBuffer);

        //
        // Delimit the transfer from (a) modifications to Access, (b) in case of a
        // write, from writes to Buffer by the caller.
        //
        MemoryFence();

        //
        // Start the transfer.
        //
        AccessHigh = (uint32_t) RShiftU64((size_t) Access, 32);
        AccessLow = (uint32_t) (size_t) Access;
        IoWrite32(FW_CFG_IO_DMA_ADDRESS, SwapBytes32(AccessHigh));
        IoWrite32(FW_CFG_IO_DMA_ADDRESS + 4, SwapBytes32(AccessLow));

        //
        // Don't look at Access.Control before starting the transfer.
        //
        MemoryFence();

        //
        // Wait for the transfer to complete.
        //
        do {
                Status = SwapBytes32(Access->Control);
                assert((Status & FW_CFG_DMA_CTL_ERROR) == 0);
        } while (Status != 0);

        //
        // After a read, the caller will want to use Buffer.
        //
        MemoryFence();

        //
        // If Access buffer was dynamically allocated then free it.
        //
        if (AccessMapping != NULL) {
                FreeFwCfgDmaAccessBuffer((void *) Access, AccessMapping);
        }

        //
        // If DataBuffer was mapped then unmap it.
        //
        if (DataMapping != NULL) {
                UnmapFwCfgDmaDataBuffer(DataMapping);
        }
}

static bool InternalQemuFwCfgDmaIsAvailable(void) {
        return mQemuFwCfgDmaSupported;
}

static void EFIAPI InternalQemuFwCfgReadBytes(size_t Size, void *Buffer) {
        if (InternalQemuFwCfgDmaIsAvailable() && (Size <= UINT32_MAX)) {
                InternalQemuFwCfgDmaBytes((uint32_t) Size, Buffer, FW_CFG_DMA_CTL_READ);
                return;
        }

        IoReadFifo8(FW_CFG_IO_DATA, Size, Buffer);
}


void EFIAPI QemuFwCfgReadBytes(size_t Size, void *Buffer) {
        if (QemuFwCfgIsAvailable()) {
                InternalQemuFwCfgReadBytes(Size, Buffer);
        } else {
                ZeroMem(Buffer, Size);
        }
}

void EFIAPI QemuFwCfgWriteBytes(size_t Size, void *Buffer) {
        if (!QemuFwCfgIsAvailable()) {
                return;
        }

        if (InternalQemuFwCfgDmaIsAvailable() && (Size <= UINT32_MAX)) {
                InternalQemuFwCfgDmaBytes((uint32_t) Size, Buffer, FW_CFG_DMA_CTL_WRITE);
                return;
        }

        IoWriteFifo8(FW_CFG_IO_DATA, Size, Buffer);
}

void EFIAPI QemuFwCfgSkipBytes(size_t Size) {
        size_t ChunkSize;
        uint8_t SkipBuffer[256];

        if (!QemuFwCfgIsAvailable()) {
                return;
        }

        if (InternalQemuFwCfgDmaIsAvailable() && (Size <= UINT32_MAX)) {
                InternalQemuFwCfgDmaBytes((uint32_t) Size, NULL, FW_CFG_DMA_CTL_SKIP);
                return;
        }

        while (Size > 0) {
                ChunkSize = MIN(Size, sizeof SkipBuffer);
                IoReadFifo8(FW_CFG_IO_DATA, ChunkSize, SkipBuffer);
                Size -= ChunkSize;
        }
}

uint8_t EFIAPI QemuFwCfgRead8(void) {
        uint8_t Result;

        QemuFwCfgReadBytes(sizeof(Result), &Result);

        return Result;
}

uint16_t EFIAPI QemuFwCfgRead16(void) {
        uint16_t Result;

        QemuFwCfgReadBytes(sizeof(Result), &Result);

        return Result;
}

uint32_t EFIAPI QemuFwCfgRead32(void) {
        uint32_t Result;

        QemuFwCfgReadBytes(sizeof(Result), &Result);

        return Result;
}

uint64_t EFIAPI QemuFwCfgRead64(void) {
        uint64_t Result;
        QemuFwCfgReadBytes(sizeof(Result), &Result);
        return Result;
}


EFI_STATUS EFIAPI QemuFwCfgFindFile(const char *Name, FIRMWARE_CONFIG_ITEM *Item, size_t *Size) {
        uint32_t Count;
        uint32_t Idx;

        if (!QemuFwCfgIsAvailable()) {
                return EFI_UNSUPPORTED;
        }

        QemuFwCfgSelectItem(QemuFwCfgItemFileDir);
        Count = SwapBytes32(QemuFwCfgRead32());

        for (Idx = 0; Idx < Count; ++Idx) {
                uint32_t FileSize;
                uint16_t FileSelect;
                uint16_t FileReserved;
                char FName[QEMU_FW_CFG_FNAME_SIZE];

                FileSize = QemuFwCfgRead32();
                FileSelect = QemuFwCfgRead16();
                FileReserved = QemuFwCfgRead16();
                (void) FileReserved; // Force a do-nothing reference.
                QemuFwCfgReadBytes(sizeof(FName), FName);

                if (strcmp8(Name, FName) == 0) {
                        *Item = SwapBytes16(FileSelect);
                        *Size = SwapBytes32(FileSize);
                        return EFI_SUCCESS;
                }
        }

        return EFI_NOT_FOUND;
}
