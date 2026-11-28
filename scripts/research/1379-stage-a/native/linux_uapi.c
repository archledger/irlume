#include <time.h>

#include <linux/media.h>
#include <linux/videodev2.h>

#define TYPE_IS(value, type) _Generic((value), type: 1, default: 0)

#ifdef CHECK_SINGLE_PLANE
#define REQUIRED_QUEUE V4L2_BUF_TYPE_VIDEO_CAPTURE
#else
#define REQUIRED_QUEUE V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE
#endif

_Static_assert(REQUIRED_QUEUE == 9, "native IR requires the multiplanar queue");
_Static_assert(V4L2_BUF_TYPE_VIDEO_CAPTURE == 1, "legacy capture queue is distinct");
_Static_assert(V4L2_PIX_FMT_IPU3_Y10 == 0x79337069U, "expected ip3y FourCC");
_Static_assert(V4L2_MEMORY_MMAP == 1, "expected MMAP selector");
_Static_assert(V4L2_FIELD_NONE == 1, "expected progressive field");
_Static_assert(V4L2_BUF_FLAG_ERROR == 0x40, "expected buffer error bit");

_Static_assert(TYPE_IS(((struct v4l2_format *)0)->fmt.pix_mp, struct v4l2_pix_format_mplane),
               "G_FMT must use the multiplanar union member");
_Static_assert(TYPE_IS(((struct v4l2_buffer *)0)->m.planes, struct v4l2_plane *),
               "the multiplanar buffer carries a plane array pointer");
_Static_assert(TYPE_IS(((struct v4l2_plane *)0)->bytesused, __u32), "32-bit bytesused");
_Static_assert(TYPE_IS(((struct v4l2_plane *)0)->length, __u32), "32-bit plane length");
_Static_assert(TYPE_IS(((struct v4l2_plane *)0)->data_offset, __u32), "32-bit payload offset");
_Static_assert(TYPE_IS(((struct v4l2_plane *)0)->m.mem_offset, __u32), "32-bit mapping offset");

_Static_assert(_IOC_SIZE(VIDIOC_G_FMT) == sizeof(struct v4l2_format), "format ioctl shape");
_Static_assert(_IOC_SIZE(VIDIOC_REQBUFS) == sizeof(struct v4l2_requestbuffers), "allocation ioctl shape");
_Static_assert(_IOC_SIZE(VIDIOC_QUERYBUF) == sizeof(struct v4l2_buffer), "query ioctl shape");
_Static_assert(_IOC_SIZE(VIDIOC_QBUF) == sizeof(struct v4l2_buffer), "queue ioctl shape");
_Static_assert(_IOC_SIZE(VIDIOC_DQBUF) == sizeof(struct v4l2_buffer), "dequeue ioctl shape");
_Static_assert(_IOC_SIZE(VIDIOC_STREAMOFF) == sizeof(int), "stop ioctl takes the queue type");
_Static_assert(_IOC_SIZE(MEDIA_IOC_G_TOPOLOGY) == sizeof(struct media_v2_topology), "topology ioctl shape");
