// SPDX-License-Identifier: GPL-3.0-or-later
// Discovery-phase ioctl requests reachable from pinned libcamera v0.8.0
// IPU3 discovery, with the class the lab gate applies. The guest worker's
// seccomp filter admits only these request numbers; anything else fails
// with EPERM before reaching a driver.
#ifndef BOOK2_LAB_DISCOVERY_REQUESTS_H
#define BOOK2_LAB_DISCOVERY_REQUESTS_H

#include <linux/media.h>
#include <linux/v4l2-subdev.h>
#include <linux/videodev2.h>

namespace book2lab {

enum class RequestClass {
    ReadOnly,     // queries with no device or file state change
    PerFile,      // state local to the open file (client caps, TRY formats)
    ListedEffect, // must match an unused effect listed in the reservation
};

struct DiscoveryRequest {
    unsigned long request;
    RequestClass cls;
    const char *name;
};

inline constexpr DiscoveryRequest kDiscoveryRequests[] = {
    {MEDIA_IOC_DEVICE_INFO, RequestClass::ReadOnly, "MEDIA_IOC_DEVICE_INFO"},
    {MEDIA_IOC_G_TOPOLOGY, RequestClass::ReadOnly, "MEDIA_IOC_G_TOPOLOGY"},
    {MEDIA_IOC_ENUM_ENTITIES, RequestClass::ReadOnly, "MEDIA_IOC_ENUM_ENTITIES"},
    {MEDIA_IOC_SETUP_LINK, RequestClass::ListedEffect, "MEDIA_IOC_SETUP_LINK"},
    {VIDIOC_QUERYCAP, RequestClass::ReadOnly, "VIDIOC_QUERYCAP"},
    {VIDIOC_ENUM_FMT, RequestClass::ReadOnly, "VIDIOC_ENUM_FMT"},
    {VIDIOC_ENUM_FRAMESIZES, RequestClass::ReadOnly, "VIDIOC_ENUM_FRAMESIZES"},
    {VIDIOC_G_FMT, RequestClass::ReadOnly, "VIDIOC_G_FMT"},
    {VIDIOC_G_SELECTION, RequestClass::ReadOnly, "VIDIOC_G_SELECTION"},
    {VIDIOC_QUERY_EXT_CTRL, RequestClass::ReadOnly, "VIDIOC_QUERY_EXT_CTRL"},
    {VIDIOC_QUERYMENU, RequestClass::ReadOnly, "VIDIOC_QUERYMENU"},
    {VIDIOC_G_EXT_CTRLS, RequestClass::ReadOnly, "VIDIOC_G_EXT_CTRLS"},
    {VIDIOC_S_EXT_CTRLS, RequestClass::ListedEffect, "VIDIOC_S_EXT_CTRLS"},
    {VIDIOC_SUBDEV_QUERYCAP, RequestClass::ReadOnly, "VIDIOC_SUBDEV_QUERYCAP"},
    {VIDIOC_SUBDEV_ENUM_MBUS_CODE, RequestClass::ReadOnly, "VIDIOC_SUBDEV_ENUM_MBUS_CODE"},
    {VIDIOC_SUBDEV_ENUM_FRAME_SIZE, RequestClass::ReadOnly, "VIDIOC_SUBDEV_ENUM_FRAME_SIZE"},
    {VIDIOC_SUBDEV_G_FMT, RequestClass::ReadOnly, "VIDIOC_SUBDEV_G_FMT"},
    {VIDIOC_SUBDEV_G_SELECTION, RequestClass::ReadOnly, "VIDIOC_SUBDEV_G_SELECTION"},
    {VIDIOC_SUBDEV_G_ROUTING, RequestClass::ReadOnly, "VIDIOC_SUBDEV_G_ROUTING"},
    {VIDIOC_SUBDEV_S_CLIENT_CAP, RequestClass::PerFile, "VIDIOC_SUBDEV_S_CLIENT_CAP"},
    // Active formats are listed effects; TRY formats are per file.
    {VIDIOC_SUBDEV_S_FMT, RequestClass::ListedEffect, "VIDIOC_SUBDEV_S_FMT"},
};

} // namespace book2lab

#endif
