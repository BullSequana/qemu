/*
 * Host IOMMU device abstract declaration
 *
 * Copyright (C) 2024 Intel Corporation.
 *
 * Authors: Zhenzhong Duan <zhenzhong.duan@intel.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */

#ifndef HOST_IOMMU_DEVICE_H
#define HOST_IOMMU_DEVICE_H

#include "qom/object.h"
#include "qapi/error.h"

/**
 * struct HostIOMMUDeviceCaps - Define host IOMMU device capabilities.
 *
 * @type: host platform IOMMU type.
 *
 * @aw_bits: host IOMMU address width. 0xff if no limitation.
 */
typedef struct HostIOMMUDeviceCaps {
    uint32_t type;
    uint8_t aw_bits;
} HostIOMMUDeviceCaps;

#define TYPE_HOST_IOMMU_DEVICE "host-iommu-device"
OBJECT_DECLARE_TYPE(HostIOMMUDevice, HostIOMMUDeviceClass, HOST_IOMMU_DEVICE)

struct HostIOMMUDevice {
    Object parent_obj;

    char *name;
    HostIOMMUDeviceCaps caps;
};

/**
 * struct HostIOMMUDeviceClass - The base class for all host IOMMU devices.
 *
 * Different types of host devices (e.g., VFIO or VDPA device) or devices
 * with different backend (e.g., VFIO legacy container or IOMMUFD backend)
 * will have different implementations of the HostIOMMUDeviceClass.
 */
struct HostIOMMUDeviceClass {
    ObjectClass parent_class;

    /**
     * @realize: initialize host IOMMU device instance further.
     *
     * Mandatory callback.
     *
     * @hiod: pointer to a host IOMMU device instance.
     *
     * @opaque: pointer to agent device of this host IOMMU device,
     *          e.g., VFIO base device or VDPA device.
     *
     * @errp: pass an Error out when realize fails.
     *
     * Returns: true on success, false on failure.
     */
    bool (*realize)(HostIOMMUDevice *hiod, void *opaque, Error **errp);
    /**
     * @get_cap: check if a host IOMMU device capability is supported.
     *
     * Optional callback, if not implemented, hint not supporting query
     * of @cap.
     *
     * @hiod: pointer to a host IOMMU device instance.
     *
     * @cap: capability to check.
     *
     * @errp: pass an Error out when fails to query capability.
     *
     * Returns: <0 on failure, 0 if a @cap is unsupported, or else
     * 1 or some positive value for some special @cap,
     * i.e., HOST_IOMMU_DEVICE_CAP_AW_BITS.
     */
    int (*get_cap)(HostIOMMUDevice *hiod, int cap, Error **errp);
};

/*
 * Host IOMMU device capability list.
 */
#define HOST_IOMMU_DEVICE_CAP_IOMMU_TYPE        0
#define HOST_IOMMU_DEVICE_CAP_AW_BITS           1

#define HOST_IOMMU_DEVICE_CAP_AW_BITS_MAX       64
#endif