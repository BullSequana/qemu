/*
 * QEMU PCIe device that supports basic SVM
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qemu/units.h"
#include "hw/pci/pci.h"
#include "hw/pci/pci_bus.h"
#include "hw/hw.h"
#include "hw/pci/msi.h"
#include "qemu/timer.h"
#include "qom/object.h"
#include "qemu/main-loop.h" /* iothread mutex */
#include "qemu/module.h"
#include "qapi/visitor.h"
#include "util/atc.h"

#define SVM_LOG(fmt, ...) \
    fprintf(stderr, "svm: " fmt , ## __VA_ARGS__)

#define TYPE_PCI_SVM_DEVICE "svm"
typedef struct SVMState SVMState;
DECLARE_INSTANCE_CHECKER(SVMState, SVM, TYPE_PCI_SVM_DEVICE)

#define PASID_WIDTH                 20
#define SVM_MAX_PASID               ((1 << PASID_WIDTH) - 1)

/* bigger than the max value of a valid PASID */
#define SVM_DISABLE_PASID           (1 << 20)

#define OP_STATUS_OK                0
#define OP_STATUS_ERR               1

#define CHECK_ENTRY_PERM(entry, expected) (!!((entry)->perm & (expected)))
#define EXPECTED_PERM(svm) \
    ((((svm)->command->dir == DMA_DIRECTION_FROM_DEVICE) ? \
                                                    IOMMU_WO : IOMMU_RO) | \
    ((svm)->command->priv ? IOMMU_PRIV : 0))

/* use a prime number to lower the probability of false positives */
#define COUNTER_MAX                 251

/* Adapted from linux/lib/crc8.c (kernel 6.8.2) */
#define CRC8_INIT_VALUE             0xFF
#define CRC8_TABLE_SIZE             256
#define CRC_POLY                    0xAB

static uint8_t crc_table[CRC8_TABLE_SIZE];

static void crc8_populate_lsb(uint8_t table[CRC8_TABLE_SIZE],
                              uint8_t polynomial)
{
    uint8_t t = 1;
    table[0] = 0;
    for (int i = (CRC8_TABLE_SIZE >> 1); i; i >>= 1) {
        t = (t >> 1) ^ (t & 1 ? polynomial : 0);
        for (int j = 0; j < CRC8_TABLE_SIZE; j += 2 * i) {
            table[i + j] = table[j] ^ t;
        }
    }
}

static uint8_t crc8(const uint8_t *pdata, size_t nbytes, uint8_t crc)
{
    while (nbytes-- > 0) {
        crc = crc_table[(crc ^ *pdata++) & 0xff];
    }

    return crc;
}

typedef struct SVMCommand {
    uint32_t pasid;
    hwaddr start_addr;
    hwaddr cur_addr;
    size_t length;
    bool ready;
    bool done;
    bool failure;
    DMADirection dir;
    uint16_t prgi;
    uint8_t crc;
    bool priv;
    uint16_t nr_translation_err;
    uint8_t first_value;
    QSIMPLEQ_ENTRY(SVMCommand) next;
} SVMCommand;

struct SVMState {
    PCIDevice pdev;
    MemoryRegion mmio;
    uint32_t status;

    uint32_t irq_status;
    struct dma_state {
        dma_addr_t addr;
        dma_addr_t cnt;
        uint64_t crc;
        uint64_t opt;
    } dma;
    uint32_t pasid;
    IOMMUPRINotifier pri_iommu_notifier;
    IOMMUNotifier iommu_notifier;
    ATC *atc;
    ATC *priv_atc;
    QemuThread svm_thread;
    QemuMutex svm_mutex;
    QemuCond svm_cond;
    bool svm_running;
    uint16_t prgi;
    uint32_t pri_req_alloc;
    uint64_t op_status;
    uint64_t min_page_size;
    uint32_t pending_pri;
    SVMCommand *command;
};

enum svm_opt {
    OPT_NONE = 0,
    OPT_PRIV = 1,
};

static void svm_raise_irq(SVMState *svm, uint32_t val)
{
    svm->op_status = val;
    SVM_LOG("send irq, status %d\n", val);
    msi_notify(&svm->pdev, 0);
}

static inline ATC *svm_get_atc_for_command(SVMState *svm)
{
    return svm->command->priv ? svm->priv_atc : svm->atc;
}

static inline IOMMUTLBEntry *svm_atc_lookup(SVMState *svm)
{
    ATC *atc = svm_get_atc_for_command(svm);
    return atc_lookup(atc, svm->pasid, svm->command->cur_addr);
}

static inline int svm_atc_update(SVMState *svm, IOMMUTLBEntry *entry)
{
    ATC *atc = svm_get_atc_for_command(svm);
    return atc_update(atc, entry);
}

static inline void svm_atc_invalidate(SVMState *svm, IOMMUTLBEntry *entry)
{
    ATC *atc = entry->perm & IOMMU_PRIV ? svm->priv_atc : svm->atc;
    atc_invalidate(atc, entry);
}

static inline bool svm_pri_about_to_overflow(SVMState *svm)
{
    return (svm->pending_pri + 1) >= svm->pri_req_alloc;
}

static inline bool svm_pri_overflow(SVMState *svm)
{
    return svm->pending_pri >= svm->pri_req_alloc;
}

static int svm_issue_pri_request(SVMState *svm, hwaddr addr, bool lpig)
{
    if (svm_pri_about_to_overflow(svm)) {
        SVM_LOG("PRI prevent overflow\n");
        lpig = true; /* force lpig = true */
    }
    int ret = pci_pri_request_page_pasid(&svm->pdev, svm->pasid,
                                         svm->command->priv,  false, addr,
                                         lpig, svm->prgi,
                                svm->command->dir == DMA_DIRECTION_TO_DEVICE,
                                svm->command->dir == DMA_DIRECTION_FROM_DEVICE);
    SVM_LOG("Send PRI request : pasid = %d, addr = 0x%lx, lpig = %d, prgi = %d\n",
            svm->pasid, addr, lpig, svm->prgi);
    if (ret) {
        return ret;
    }
    svm->pending_pri += 1;
    svm->command->ready = false;
    svm->command->prgi = svm->prgi;
    if (lpig) {
        svm->prgi = (svm->prgi + 1) & PCI_PRI_PRGI_MASK;
    }
    return 0;
}

/* returns the number of errors */
static size_t svm_try_update_atc(SVMState *svm, IOMMUTLBEntry *entries,
                                 size_t size, IOMMUAccessFlags expected_perm)
{
    IOMMUTLBEntry *entry;
    size_t result = 0;
    for (size_t i = 0; i < size; ++i) {
        entry = entries + i;
        if (IOMMU_TLB_ENTRY_TRANSLATION_ERROR(entry) ||
                                !CHECK_ENTRY_PERM(entry, expected_perm)) {
            result += 1;
            if (!IOMMU_TLB_ENTRY_TRANSLATION_ERROR(entry)) {
                SVM_LOG("Lack of permissions 0x%lx, expected : %u, actual %u\n",
                        entry->iova, expected_perm, entry->perm);
            }
        } else {
            SVM_LOG("Translation for 0x%lx : 0x%lx\n",
                    entries[i].iova, entries[i].translated_addr);
            assert(svm_atc_update(svm, entries + i) == 0);
        }
    }

    return result;
}

static void svm_prepare_translations(SVMState *svm)
{
    hwaddr addr = svm->command->cur_addr;
    size_t length = svm->command->length -
                        (svm->command->cur_addr - svm->command->start_addr);
    ssize_t ret;
    size_t result_length = atc_get_max_number_of_pages(svm->atc,
                                                         addr, length);
    IOMMUTLBEntry *buffer = g_malloc(sizeof(*buffer) * result_length);
    uint32_t err_count;
    uint32_t pri_req_count = 0;
    IOMMUAccessFlags expected_perm = EXPECTED_PERM(svm);
    size_t pri_gp_len;
    bool no_write = svm->command->dir != DMA_DIRECTION_FROM_DEVICE;

    ret = pci_ats_request_translation_pasid(&svm->pdev, svm->pasid,
                                svm->command->priv, false,
                                addr, length, no_write, buffer,
                                result_length, &err_count);
    if (ret < 0) { /* Not -ENOMEM as the buffer is large enough*/
        SVM_LOG("Error during ATS request : %ld\n", ret);
        svm->command->failure = true;
        return;
    }
    SVM_LOG("Send ATS request : pasid = %d, addr = 0x%lx, length = %ld, "
        "no_write = %d\n", svm->pasid, addr, length, no_write);
    SVM_LOG("Translation errors : %d / %ld\n", err_count, ret);
    pri_gp_len = svm_try_update_atc(svm, buffer, ret, expected_perm);

    for (ssize_t i = 0; i < ret; ++i) {
        if (IOMMU_TLB_ENTRY_TRANSLATION_ERROR(buffer + i) ||
                            !CHECK_ENTRY_PERM(buffer + i, expected_perm)) {
            pri_req_count += 1;
            if (svm_issue_pri_request(svm, addr, pri_req_count == pri_gp_len)) {
                SVM_LOG("PRI error\n");
                svm->command->failure = true;
                return;
            }
            if (svm_pri_overflow(svm)) {
                /* just wait for the response and try again later */
                return;
            }
        }
        /*
         * Spec : the range of the gap is indicated in the Translation
         * Completion even if R = W = 0b
         */
        addr = (addr & (~buffer[i].addr_mask)) + (buffer[i].addr_mask + 1);
    }
}

static void svm_pri_completion_handler(IOMMUPRINotifier *notifier,
                                       IOMMUPRIResponse *response)
{
    SVMState *svm = container_of(notifier, SVMState, pri_iommu_notifier);
    qemu_mutex_lock(&svm->svm_mutex);
    if (!svm->command) {
        goto unlock;
    }
    /* We only have a single prgi at a time, we can reset the counter */
    svm->pending_pri = 0;
    SVM_LOG("response->response_code : %x\n", response->response_code);
    if (response->response_code == IOMMU_PRI_RESP_SUCCESS) {
        SVM_LOG("PRI completion handler : %d - %d\n",
               response->response_code, response->prgi);
    } else {
        SVM_LOG("Segfault\n");
        svm->command->failure = true;
    }
    svm->command->ready = true;
    qemu_cond_signal(&svm->svm_cond);

unlock:
    qemu_mutex_unlock(&svm->svm_mutex);
}

static void svm_iommu_notification_handler(struct IOMMUNotifier *notifier,
                                           IOMMUTLBEntry *data)
{
    SVMState *svm = container_of(notifier, SVMState, iommu_notifier);
    SVM_LOG("Invalidation : addr = 0x%lx - pasid = %x - mask = 0x%lx\n",
           data->iova, data->pasid, data->addr_mask);
    svm_atc_invalidate(svm, data);
}

static void svm_disable_pasid(SVMState *svm)
{
    pci_pri_unregister_notifier(&svm->pdev, svm->pasid);
    pci_unregister_iommu_tlb_event_notifier(&svm->pdev, svm->pasid,
                                            &svm->iommu_notifier);
    atc_delete_address_space_cache(svm->atc, svm->pasid);
    atc_delete_address_space_cache(svm->priv_atc, svm->pasid);
    svm->pasid = SVM_DISABLE_PASID;
    SVM_LOG("PASID disabled\n");
}

static void svm_enable_pasid(SVMState *svm, uint32_t pasid)
{
    int ret = pci_pri_register_notifier(&svm->pdev, pasid,
                                        &svm->pri_iommu_notifier);
    if (ret != 0) {
        SVM_LOG("Cannot enable PASID\n");
        return;
    }

    svm->pri_req_alloc = pcie_pri_get_req_alloc(&svm->pdev);

    svm->pasid = pasid;
    pci_iommu_init_iotlb_notifier(&svm->pdev, svm->pasid, &svm->iommu_notifier,
                                  svm_iommu_notification_handler, NULL);
    pci_register_iommu_tlb_event_notifier(&svm->pdev, svm->pasid,
                                          &svm->iommu_notifier);
    atc_create_address_space_cache(svm->atc, svm->pasid);
    atc_create_address_space_cache(svm->priv_atc, svm->pasid);
    SVM_LOG("PASID enabled\n");
}

static void svm_init_atc(SVMState *svm)
{
    uint8_t address_width = pci_iommu_get_addr_width(&svm->pdev);
    svm->min_page_size = pci_iommu_get_min_page_size(&svm->pdev);
    assert(address_width);
    assert(svm->min_page_size);
    svm->atc = atc_new(svm->min_page_size, address_width);
    svm->priv_atc = atc_new(svm->min_page_size, address_width);
}

static void svm_destroy_atc(SVMState *svm)
{
    atc_destroy(svm->atc);
    atc_destroy(svm->priv_atc);
}

static void svm_set_pasid(SVMState *svm, uint32_t pasid)
{
    if (!svm->atc) {
        svm_init_atc(svm);
    }

    if (pasid == SVM_DISABLE_PASID && svm->pasid != SVM_DISABLE_PASID) {
        svm_disable_pasid(svm);
    } else if (pasid <= SVM_MAX_PASID && svm->pasid == SVM_DISABLE_PASID) {
        svm_enable_pasid(svm, pasid);
    } else if (pasid <= SVM_MAX_PASID && svm->pasid != SVM_DISABLE_PASID) {
        svm_disable_pasid(svm);
        svm_enable_pasid(svm, pasid);
    }
    /* else { nop } */
    SVM_LOG("Set PASID done : %d\n", svm->pasid);
}

static void svm_submit_command(SVMState *svm, DMADirection dir)
{
    SVMCommand *command;

    qemu_mutex_lock(&svm->svm_mutex);
    if (!svm->svm_running) {
        return;
    }

    command = g_malloc(sizeof(*command));
    command->pasid = svm->pasid;
    command->start_addr = svm->dma.addr;
    command->cur_addr = svm->dma.addr;
    command->length = svm->dma.cnt;
    command->ready = true;
    command->done = false;
    command->failure = false;
    command->dir = dir;
    command->priv = svm->dma.opt & OPT_PRIV;
    command->nr_translation_err = 0;
    command->first_value = 0;

    svm->command = command;
    command->crc = CRC8_INIT_VALUE;
    qemu_cond_signal(&svm->svm_cond);
    qemu_mutex_unlock(&svm->svm_mutex);
}

static void svm_trigger_write(SVMState *svm)
{
    svm_submit_command(svm, DMA_DIRECTION_FROM_DEVICE);
}

static void svm_trigger_read(SVMState *svm)
{
    svm_submit_command(svm, DMA_DIRECTION_TO_DEVICE);
}

static uint64_t svm_mmio_read(void *opaque, hwaddr addr, unsigned size)
{
    SVMState *svm = opaque;
    uint64_t val = ~0ULL;

    if (size != 8) {
        return val;
    }

    switch (addr) {
    case 0x00:
        val = 0x0b1c5111;
        break;
    case 0x08:
        val = svm->op_status;
    }

    return val;
}

static void svm_mmio_write(void *opaque, hwaddr addr, uint64_t val,
                           unsigned size)
{
    SVMState *svm = opaque;

    if (addr < 0x50 && size != 8) {
        return;
    }
    if (addr >= 0x50 && size != 4) {
        return;
    }

    switch (addr) {
    /* 8 bytes */
    case 0x00:
        if (val == 1) {
            svm_trigger_write(svm);
        } else if (val == 2) {
            svm_trigger_read(svm);
        }
        break;
    case 0x8:
        svm->dma.addr = val;
        break;
    case 0x10:
        svm->dma.crc = val;
        break;
    case 0x18:
        svm->dma.cnt = val;
        break;
    case 0x20:
        svm->dma.opt = val;
        break;
    /* 4 bytes */
    case 0x50:
        svm_set_pasid(svm, val);
        break;
    }
}

static const MemoryRegionOps svm_mmio_ops = {
    .read = svm_mmio_read,
    .write = svm_mmio_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid = {
        .min_access_size = 4,
        .max_access_size = 8,
    },
    .impl = {
        .min_access_size = 4,
        .max_access_size = 8,
    },

};

static uint8_t svm_prepare_sub_buffer(uint8_t *buf, uint8_t first_value,
                                      size_t size)
{
    uint8_t v = first_value;
    for (size_t i = 0; i < size; ++i) {
        if (v == COUNTER_MAX) {
            v = 0;
        }
        buf[i] = v;
        v += 1;
    }
    return v;
}

static void svm_do_process_command(SVMState *svm)
{
    SVMCommand *command = svm->command;
    hwaddr virt_end = command->start_addr + command->length;
    hwaddr phys_addr;
    hwaddr phys_next_page;
    hwaddr chunk_size, sub_chunk_size;
    IOMMUTLBEntry *iotlb_entry;
    uint8_t buf[4096];
    size_t i = 0;
    IOMMUAccessFlags expected_perm = EXPECTED_PERM(svm);

    while (command->cur_addr < virt_end) {
        iotlb_entry = svm_atc_lookup(svm);
        if (!iotlb_entry || !CHECK_ENTRY_PERM(iotlb_entry, expected_perm)) {
            /* no overflow because we only have 1 prgi at a time */
            if (svm_issue_pri_request(svm, command->cur_addr, true)) {
                SVM_LOG("PRI error\n");
                svm->command->failure = true;
                return;
            }
            return;
        }
        if (iotlb_entry->perm & IOMMU_UNTRANSLATED_ONLY) {
            SVM_LOG("SVM untranslated only : 0x%lx\n",
                    iotlb_entry->translated_addr);
            command->failure = true;
            return;
        }

        phys_addr = iotlb_entry->translated_addr |
                        (command->cur_addr & iotlb_entry->addr_mask);
        phys_next_page = (iotlb_entry->translated_addr |
                            iotlb_entry->addr_mask) + 1;

        chunk_size = MIN(virt_end - command->cur_addr,
                         phys_next_page - phys_addr);
        for (i = 0; i < chunk_size; i += sizeof(buf)) {
            sub_chunk_size = MIN(sizeof(buf), chunk_size - i);
            if (svm->command->dir == DMA_DIRECTION_FROM_DEVICE) {
                command->first_value = svm_prepare_sub_buffer(buf,
                                                        command->first_value,
                                                        sub_chunk_size);
                pci_dma_write_translated(&svm->pdev, phys_addr,
                                         buf, sub_chunk_size);

                /*
                 * pci_dma_rw(&svm->pdev, command->cur_addr, buf,
                 *            sub_chunk_size, DMA_DIRECTION_FROM_DEVICE,
                 *            ((MemTxAttrs) { .pid = svm->pasid }));
                 */

            } else {
                pci_dma_read_translated(&svm->pdev, phys_addr,
                                        buf, sub_chunk_size);

                /*
                 * pci_dma_rw(&svm->pdev, command->cur_addr, buf,
                 *            sub_chunk_size, DMA_DIRECTION_TO_DEVICE,
                 *            ((MemTxAttrs) { .pid = svm->pasid }));
                 */

                svm->command->crc = crc8(buf, sub_chunk_size,
                                         svm->command->crc);
            }
            phys_addr += sub_chunk_size;
        }
        command->cur_addr += chunk_size;
    }
    command->done = true;
}

static void svm_handle_failure(SVMState *svm)
{
    SVM_LOG("SVM error\n");
    g_free(svm->command);
    svm->command = NULL;
    svm_raise_irq(svm, OP_STATUS_ERR);
}

static void svm_handle_done(SVMState *svm)
{
    uint32_t status;
    if (svm->command->dir == DMA_DIRECTION_FROM_DEVICE) {
        status = OP_STATUS_OK;
    } else {
        SVM_LOG("CRC : Expected = %ld - Actual = %d\n",
                 svm->dma.crc, svm->command->crc);
        status = svm->command->crc == svm->dma.crc ?
                    OP_STATUS_OK : OP_STATUS_ERR;
    }
    g_free(svm->command);
    svm->command = NULL;
    svm_raise_irq(svm, status);
}

static inline bool svm_command_ready(SVMState *svm)
{
    return svm->command && svm->command->ready;
}

static void *svm_thread(void* opaque)
{
    SVMState *svm = opaque;

    qemu_mutex_lock(&svm->svm_mutex);
    while (svm->svm_running) {
        while (svm->svm_running && !svm_command_ready(svm)) {
            qemu_cond_wait(&svm->svm_cond, &svm->svm_mutex);
        }

        if (!svm->svm_running) {
            break;
        }

        if (svm->command->failure) {
            svm_handle_failure(svm);
            continue;
        }
        svm_prepare_translations(svm);
        if (svm->command->failure) {
            svm_handle_failure(svm);
        } else if (svm->command->ready) {
            svm_do_process_command(svm);
            if (svm->command->failure) {
                svm_handle_failure(svm);
            } else if (svm->command->done) {
                svm_handle_done(svm);
            }
        }
        /* Else, some PRI request have been made */
    }
    qemu_mutex_unlock(&svm->svm_mutex);

    return NULL;
}

static void svm_pci_realize(PCIDevice *pdev, Error **errp)
{
    SVMState *svm = SVM(pdev);
    uint16_t cap_offset = PCI_CONFIG_SPACE_SIZE;

    if (msi_init(pdev, 0, 1, true, false, errp)) {
        return;
    }

    memory_region_init_io(&svm->mmio, OBJECT(svm), &svm_mmio_ops, svm,
                    "svm-mmio", 1 * MiB);
    pci_register_bar(pdev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY, &svm->mmio);

    if (pcie_endpoint_cap_init(pdev, 0x80) < 0) {
        hw_error("Failed to initialize PCIe capability");
    }

    pcie_pasid_init(pdev, cap_offset, PASID_WIDTH, false, true);
    cap_offset += PCI_EXT_CAP_PASID_SIZEOF;

    pcie_ats_init(pdev, cap_offset, true);
    cap_offset += PCI_EXT_CAP_ATS_SIZEOF;

    pcie_pri_init(pdev, cap_offset, 2048, true);

    /* Disable PASID by default */
    svm->pasid = SVM_DISABLE_PASID;
    svm->pri_iommu_notifier.notify = svm_pri_completion_handler;
    svm->prgi = 0;

    svm->svm_running = true;
    qemu_mutex_init(&svm->svm_mutex);
    qemu_cond_init(&svm->svm_cond);
    qemu_thread_create(&svm->svm_thread, "svm-svm", svm_thread,
                       svm, QEMU_THREAD_JOINABLE);
}

static void svm_pci_uninit(PCIDevice *pdev)
{
    SVMState *svm = SVM(pdev);

    qemu_mutex_lock(&svm->svm_mutex);
    svm->svm_running = false;
    qemu_cond_signal(&svm->svm_cond);
    qemu_mutex_unlock(&svm->svm_mutex);
    qemu_thread_join(&svm->svm_thread);

    qemu_cond_destroy(&svm->svm_cond);
    qemu_mutex_destroy(&svm->svm_mutex);

    svm_destroy_atc(svm);
    msi_uninit(pdev);
}

static void svm_class_init(ObjectClass *class, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(class);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(class);

    k->realize = svm_pci_realize;
    k->exit = svm_pci_uninit;
    k->vendor_id = PCI_VENDOR_ID_QEMU;
    k->device_id = 0x0b11;
    k->revision = 0x10;
    k->class_id = PCI_CLASS_OTHERS;
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);

    crc8_populate_lsb(crc_table, CRC_POLY);
}

static void svm_pci_register_types(void)
{
    static InterfaceInfo interfaces[] = {
        { INTERFACE_PCIE_DEVICE },
        { },
    };
    static const TypeInfo svm_info = {
        .name          = TYPE_PCI_SVM_DEVICE,
        .parent        = TYPE_PCI_DEVICE,
        .instance_size = sizeof(SVMState),
        .class_init    = svm_class_init,
        .interfaces = interfaces,
    };

    type_register_static(&svm_info);
}
type_init(svm_pci_register_types)
