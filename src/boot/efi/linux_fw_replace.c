/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * x86 specific code to for EFI handover boot protocol
 * Linux kernels version 5.8 and newer support providing the initrd by
 * LINUX_INITRD_MEDIA_GUID DevicePath. In order to support older kernels too,
 * this x86 specific linux_exec function passes the initrd by setting the
 * corresponding fields in the setup_header struct.
 *
 * see https://docs.kernel.org/arch/x86/boot.html
 */

#include "initrd.h"
#include "linux.h"
#include "macro-fundamental.h"
#include "memory-util-fundamental.h"
#include "qemufwcfg.h"
#include "util.h"
#include "vmm.h"

#define KERNEL_SECTOR_SIZE 512u
#define BOOT_FLAG_MAGIC 0xAA55u
#define SETUP_MAGIC 0x53726448u /* "HdrS" */
#define SETUP_VERSION_2_11 0x20bu
#define SETUP_VERSION_2_12 0x20cu
#define SETUP_VERSION_2_15 0x20fu
#define CMDLINE_PTR_MAX 0xA0000u

enum {
        XLF_KERNEL_64 = 1 << 0,
        XLF_CAN_BE_LOADED_ABOVE_4G = 1 << 1,
        XLF_EFI_HANDOVER_32 = 1 << 2,
        XLF_EFI_HANDOVER_64 = 1 << 3,
#ifdef __x86_64__
        XLF_EFI_HANDOVER = XLF_EFI_HANDOVER_64,
#else
        XLF_EFI_HANDOVER = XLF_EFI_HANDOVER_32,
#endif
};

typedef enum {
        VMFW_TYPE_BLOB_KERNEL = 0x01, /* kernel */
        VMFW_TYPE_BLOB_SETUP,         /* need to check if this is required */
        VMFW_TYPE_BLOB_INITRD,        /* initrd */
        VMFW_TYPE_BLOB_CMDLINE,       /* command line */
        VMFW_TYPE_BLOB_FW,            /* firmware */
        VMFW_TYPE_BLOB_MAX
} blob_type_t;

typedef struct FwCfgVmFwUpdateBlob {
        /*
         * blob_type indicates the type of blob/launch digest the guest has passed
         * to the host. blob_type 0x00 is invalid. It is of type blob_type_t.
         */
        uint8_t blob_type;
        /*
         * map_type: type of guest memory mapping requested. Mappings can be either
         * private or shared. Private guest pages are flipped from shared to private
         * when a new SEV guest context is created. The private memory contains CPU
         * state information and firmware blob. The shared memory remains shared
         * with the hypervisor and is excluded from encryption and measurements.
         * The shared data is the next stage artifacts (kernel image/UKI, initrd,
         * command line) that are validated by the second stage firmware present in
         * the private memory. Thus they need not be explicitly measured by ASP.
         */
        uint8_t map_type;
        uint32_t size;         /* size of the blob */
        uint64_t paddr;        /* starting gpa where the blob is in guest memory. We may
                                * copy the contents of the guest private memory to a
                                * different addresss from paddr
                                */
        uint64_t target_paddr; /* guest physical address where private blobs are
                                * copied to.
                                * XXX: Is this really required to be passed from
                                * the guest?
                                */
} FwCfgVmFwUpdateBlob;

/* type of mapping requested */
#define VMFW_TYPE_MAP_PRIVATE 0x00
#define VMFW_TYPE_MAP_SHARED 0x01

typedef struct {
        uint8_t setup_sects;
        uint16_t root_flags;
        uint32_t syssize;
        uint16_t ram_size;
        uint16_t vid_mode;
        uint16_t root_dev;
        uint16_t boot_flag;
        uint8_t jump; /* We split the 2-byte jump field from the spec in two for convenience. */
        uint8_t setup_size;
        uint32_t header;
        uint16_t version;
        uint32_t realmode_swtch;
        uint16_t start_sys_seg;
        uint16_t kernel_version;
        uint8_t type_of_loader;
        uint8_t loadflags;
        uint16_t setup_move_size;
        uint32_t code32_start;
        uint32_t ramdisk_image;
        uint32_t ramdisk_size;
        uint32_t bootsect_kludge;
        uint16_t heap_end_ptr;
        uint8_t ext_loader_ver;
        uint8_t ext_loader_type;
        uint32_t cmd_line_ptr;
        uint32_t initrd_addr_max;
        uint32_t kernel_alignment;
        uint8_t relocatable_kernel;
        uint8_t min_alignment;
        uint16_t xloadflags;
        uint32_t cmdline_size;
        uint32_t hardware_subarch;
        uint64_t hardware_subarch_data;
        uint32_t payload_offset;
        uint32_t payload_length;
        uint64_t setup_data;
        uint64_t pref_address;
        uint32_t init_size;
        uint32_t handover_offset;
} _packed_ SetupHeader;

/* We really only care about a few fields, but we still have to provide a full page otherwise. */
typedef struct {
        uint8_t pad[192];
        uint32_t ext_ramdisk_image;
        uint32_t ext_ramdisk_size;
        uint32_t ext_cmd_line_ptr;
        uint8_t pad2[293];
        SetupHeader hdr;
        uint8_t pad3[3480];
} _packed_ BootParams;
assert_cc(offsetof(BootParams, ext_ramdisk_image) == 0x0C0);
assert_cc(sizeof(BootParams) == 4096);

#ifdef __i386__
#        define __regparm0__ __attribute__((regparm(0)))
#else
#        define __regparm0__
#endif

static void fill_blob(
                FwCfgVmFwUpdateBlob *blob, bool inCC, uint8_t blob_type, uint8_t map_type, void *ptr, size_t len) {
        EFI_PHYSICAL_ADDRESS DataBufferAddress = POINTER_TO_PHYSICAL_ADDRESS(ptr);

        void *DataMapping = NULL; // will not be released anyway

        if (inCC) {
                MapFwCfgDmaDataBuffer(true, ptr, len, &DataBufferAddress, &DataMapping);
        }

        blob->blob_type = blob_type;
        blob->map_type = map_type;
        blob->paddr = DataBufferAddress;
        blob->target_paddr = 0; // ???
        blob->size = len;
}

EFI_STATUS linux_exec_efi_fw_replace(
                EFI_HANDLE parent,
                const char16_t *cmdline,
                const struct iovec *kernel,
                const struct iovec *initrd,
                const struct iovec *firmware) {

        size_t kernel_size_in_memory = 0;
        uint32_t compat_address;

        assert(parent);
        assert(iovec_is_set(kernel));
        assert(iovec_is_valid(initrd));
        assert(iovec_is_valid(firmware));

        // just get `kernel_size_in_memory`
        pe_kernel_info(kernel->iov_base, &compat_address, &kernel_size_in_memory);

        if (kernel->iov_len < sizeof(BootParams))
                return EFI_LOAD_ERROR;

        const BootParams *image_params = (const BootParams *) kernel->iov_base;
        if (image_params->hdr.header != SETUP_MAGIC || image_params->hdr.boot_flag != BOOT_FLAG_MAGIC)
                return log_error_status(EFI_UNSUPPORTED, "Unsupported kernel image.");
        if (image_params->hdr.version < SETUP_VERSION_2_11)
                return log_error_status(EFI_UNSUPPORTED, "Kernel too old.");
        if (!image_params->hdr.relocatable_kernel)
                return log_error_status(EFI_UNSUPPORTED, "Kernel is not relocatable.");

        /* The xloadflags were added in version 2.12+ of the boot protocol but the handover support predates
         * that, so we cannot safety-check this for 2.11. */
        if (image_params->hdr.version >= SETUP_VERSION_2_12 &&
            !FLAGS_SET(image_params->hdr.xloadflags, XLF_EFI_HANDOVER))
                return log_error_status(EFI_UNSUPPORTED, "Kernel does not support EFI handover protocol.");

        bool can_4g = image_params->hdr.version >= SETUP_VERSION_2_12 &&
                        FLAGS_SET(image_params->hdr.xloadflags, XLF_CAN_BE_LOADED_ABOVE_4G);

        /* There is no way to pass the high bits of code32_start. Newer kernels seems to handle this
         * just fine, but older kernels will fail even if they otherwise have above 4G boot support.
         * A PE image's memory footprint can be larger than its file size, due to unallocated virtual
         * memory sections. While normally all PE headers should be taken into account, this case only
         * involves x86 Linux bzImage kernel images, for which unallocated areas are only part of the last
         * header, so parsing SizeOfImage and zeroeing the buffer past the image size is enough. */
        _cleanup_pages_ Pages linux_relocated = {};
        void *linux_buffer;
        if (POINTER_TO_PHYSICAL_ADDRESS(kernel->iov_base) + kernel->iov_len > UINT32_MAX ||
            kernel_size_in_memory > kernel->iov_len) {
                linux_relocated = xmalloc_pages(
                                AllocateMaxAddress,
                                EfiLoaderCode,
                                EFI_SIZE_TO_PAGES(MAX(kernel_size_in_memory, kernel->iov_len)),
                                UINT32_MAX);
                linux_buffer = memcpy(
                                PHYSICAL_ADDRESS_TO_POINTER(linux_relocated.addr),
                                kernel->iov_base,
                                kernel->iov_len);
                if (kernel_size_in_memory > kernel->iov_len)
                        memzero((uint8_t *) linux_buffer + kernel->iov_len,
                                kernel_size_in_memory - kernel->iov_len);
        } else
                linux_buffer = kernel->iov_base;

        _cleanup_pages_ Pages initrd_relocated = {};
        void *initrd_buffer;
        if (!can_4g && POINTER_TO_PHYSICAL_ADDRESS(initrd->iov_base) + initrd->iov_len > UINT32_MAX) {
                initrd_relocated = xmalloc_pages(
                                AllocateMaxAddress,
                                EfiLoaderData,
                                EFI_SIZE_TO_PAGES(initrd->iov_len),
                                UINT32_MAX);
                initrd_buffer = memcpy(
                                PHYSICAL_ADDRESS_TO_POINTER(initrd_relocated.addr),
                                initrd->iov_base,
                                initrd->iov_len);
        } else
                initrd_buffer = initrd->iov_base;

        FwCfgVmFwUpdateBlob blobs[VMFW_TYPE_BLOB_MAX];
        uint8_t cur_blob = 0;

        bool inCC = is_confidential_vm();

        fill_blob(&blobs[cur_blob],
                  inCC,
                  VMFW_TYPE_BLOB_FW,
                  VMFW_TYPE_MAP_PRIVATE,
                  firmware->iov_base,
                  firmware->iov_len);
        cur_blob++;

        fill_blob(&blobs[cur_blob],
                  inCC,
                  VMFW_TYPE_BLOB_KERNEL,
                  VMFW_TYPE_MAP_SHARED,
                  linux_buffer,
                  kernel_size_in_memory);
        cur_blob++;

        fill_blob(&blobs[cur_blob],
                  inCC,
                  VMFW_TYPE_BLOB_INITRD,
                  VMFW_TYPE_MAP_SHARED,
                  initrd_buffer,
                  initrd->iov_len);
        cur_blob++;

        _cleanup_pages_ Pages cmdline_pages = {};
        if (cmdline) {
                size_t len = MIN(strlen16(cmdline), image_params->hdr.cmdline_size);

                cmdline_pages = xmalloc_pages(
                                can_4g ? AllocateAnyPages : AllocateMaxAddress,
                                EfiLoaderData,
                                EFI_SIZE_TO_PAGES(len + 1),
                                CMDLINE_PTR_MAX);

                /* Convert cmdline to ASCII. */
                char *cmdline8 = PHYSICAL_ADDRESS_TO_POINTER(cmdline_pages.addr);
                for (size_t i = 0; i < len; i++)
                        cmdline8[i] = cmdline[i] <= 0x7E ? cmdline[i] : ' ';
                cmdline8[len] = '\0';

                fill_blob(&blobs[cur_blob],
                          inCC,
                          VMFW_TYPE_BLOB_CMDLINE,
                          VMFW_TYPE_MAP_SHARED,
                          cmdline8,
                          EFI_SIZE_TO_PAGES(len + 1) * EFI_PAGE_SIZE);
                cur_blob++;
        }

        FIRMWARE_CONFIG_ITEM FwCfgItem;
        size_t FwCfgSize;
        if (QemuFwCfgFindFile("etc/vmfwupdate-blob", &FwCfgItem, &FwCfgSize) != EFI_SUCCESS) {
                return EFI_LOAD_ERROR;
        }
        QemuFwCfgSelectItem(FwCfgItem);
        QemuFwCfgWriteBytes(cur_blob * sizeof(FwCfgVmFwUpdateBlob), blobs);

        if (QemuFwCfgFindFile("etc/fwupdate-control", &FwCfgItem, &FwCfgSize) != EFI_SUCCESS) {
                return EFI_LOAD_ERROR;
        }
        QemuFwCfgSelectItem(FwCfgItem);
        char cmd = 't';
        QemuFwCfgWriteBytes(1, &cmd);

        return EFI_LOAD_ERROR;
}
