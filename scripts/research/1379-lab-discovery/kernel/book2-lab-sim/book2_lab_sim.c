// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Guest-only simulated IPU3 media graph for the irlume Book 2 discovery lab.
 *
 * Built only into the disposable QEMU guest kernel; never for a host. It
 * mirrors what the pinned ipu3-cio2, ipu3-imgu, ov5693, ov8865 and ov7251
 * drivers publish (names, entity functions, pads, link flags, capabilities
 * and control ids) without hardware, buffers or streaming. Sensor names,
 * port order, control ranges and sizes marked synthetic are not Book 2
 * facts. Every state change userspace causes is appended to a root-only
 * debugfs log. Instances are never freed: the guest powers off after one
 * case, and old instances must outlive descriptors that still point at them.
 */

#include <linux/atomic.h>
#include <linux/debugfs.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/platform_device.h>
#include <linux/sched.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/wait.h>
#include <media/media-device.h>
#include <media/media-entity.h>
#include <media/v4l2-ctrls.h>
#include <media/v4l2-dev.h>
#include <media/v4l2-device.h>
#include <media/v4l2-fh.h>
#include <media/v4l2-ioctl.h>
#include <media/v4l2-subdev.h>

#define SIM_PORTS 4
#define SIM_PIPES 2
#define SIM_IMGU_NODES 5
#define SIM_SENSORS 3
#define SIM_LOG_SIZE 8192
#define SIM_TEXT 112

/* From the pinned staging uapi header intel-ipu3.h. */
#define SIM_CID_INTEL_IPU3_MODE (V4L2_CID_USER_BASE + 0x10c0 + 1)
#define SIM_META_FMT_IPU3_PARAMS v4l2_fourcc('i', 'p', '3', 'p')
#define SIM_META_FMT_IPU3_STAT_3A v4l2_fourcc('i', 'p', '3', 's')

static unsigned int front_port;
module_param(front_port, uint, 0444);
MODULE_PARM_DESC(front_port, "CSI-2 port of the simulated front sensor (0 or 3)");

struct sim_record {
	u64 seq;
	u32 instance;
	pid_t tgid;
	char text[SIM_TEXT];
};

static struct {
	spinlock_t lock;
	u64 count;
	u64 dropped;
	struct sim_record rec[SIM_LOG_SIZE];
} sim_log = { .lock = __SPIN_LOCK_UNLOCKED(sim_log.lock) };

struct sim_instance;

struct sim_node {
	struct sim_instance *inst;
	char name[48];
	atomic_t opens;
	struct list_head list;
};

struct sim_handler {
	struct v4l2_ctrl_handler hdl;
	struct sim_node *node;
};

struct sim_sensor_desc {
	const char *pdev_name;
	const char *name;
	u32 code;
	u32 width, height;
	unsigned int frame_sizes;
	struct v4l2_rect native, active;
	s64 pixel_rate, link_freq;
	s32 exp_min, exp_max, exp_def;
	u32 gain_id;
	s32 gain_min, gain_max, gain_step, gain_def;
	bool digital_gain, white_balance, fwnode_props;
	s32 hblank, vblank_min, vblank_max, vblank_def;
	const char *const *patterns;
	unsigned int n_patterns;
	s32 orientation;
};

struct sim_sensor {
	struct sim_node node;
	const struct sim_sensor_desc *desc;
	struct platform_device *pdev;
	struct v4l2_subdev sd;
	struct media_pad pad;
	struct sim_handler ctrls;
	bool front;
};

struct sim_subdev {
	struct sim_node node;
	struct v4l2_subdev sd;
	struct media_pad pads[SIM_IMGU_NODES];
	struct sim_handler ctrls;
};

struct sim_video {
	struct sim_node node;
	struct video_device vdev;
	struct media_pad pad;
	const u32 *formats;
	unsigned int n_formats;
	u32 buf_type;
};

struct sim_instance {
	u32 id;
	struct platform_device *cio2_pdev, *imgu_pdev;
	struct media_device cio2_mdev, imgu_mdev;
	struct v4l2_device cio2_v4l2, imgu_v4l2;
	struct sim_subdev csi2[SIM_PORTS];
	struct sim_video cio2_video[SIM_PORTS];
	struct sim_sensor sensors[SIM_SENSORS];
	struct sim_subdev imgu[SIM_PIPES];
	struct sim_video imgu_video[SIM_PIPES][SIM_IMGU_NODES];
	struct media_entity extra;
	struct media_pad extra_pad;
	bool extra_registered;
};

static struct sim_instance *sim_current;
static DEFINE_MUTEX(sim_control_lock);
static LIST_HEAD(sim_nodes);
static DEFINE_MUTEX(sim_nodes_lock);
static atomic_t sim_bump_armed = ATOMIC_INIT(0);
static atomic_t sim_media_armed = ATOMIC_INIT(0);
/* Serializes the extra media device; taken under the control lock or a subdev state lock. */
static DEFINE_MUTEX(sim_extra_lock);
static struct platform_device *sim_extra_pdev;
static struct media_device sim_extra_mdev;

static int sim_add_media(void);

/* Test-only pause points: after the front link enable or the front format set. */
enum { SIM_PAUSE_NONE, SIM_PAUSE_FRONT_LINK, SIM_PAUSE_FRONT_FMT };
static atomic_t sim_pause_point = ATOMIC_INIT(SIM_PAUSE_NONE);
static DECLARE_WAIT_QUEUE_HEAD(sim_pause_wq);
static bool sim_paused;

static __printf(2, 3) void sim_record(u32 instance, const char *fmt, ...)
{
	char text[SIM_TEXT];
	unsigned long flags;
	va_list ap;
	int len;

	va_start(ap, fmt);
	len = vsnprintf(text, sizeof(text), fmt, ap);
	va_end(ap);

	spin_lock_irqsave(&sim_log.lock, flags);
	if (len < 0 || len >= (int)sizeof(text) || sim_log.count >= SIM_LOG_SIZE) {
		sim_log.dropped++;
	} else {
		struct sim_record *r = &sim_log.rec[sim_log.count];

		r->seq = sim_log.count + 1;
		r->instance = instance;
		r->tgid = task_tgid_nr(current);
		strscpy(r->text, text, sizeof(r->text));
		sim_log.count++;
	}
	spin_unlock_irqrestore(&sim_log.lock, flags);
}

/* Hold the calling worker, once per arming, until the supervisor writes resume or 20 s pass. */
static void sim_pause(u32 instance, int point)
{
	if (atomic_cmpxchg(&sim_pause_point, point, SIM_PAUSE_NONE) != point)
		return;
	WRITE_ONCE(sim_paused, true);
	sim_record(instance, "control paused");
	if (wait_event_timeout(sim_pause_wq, !READ_ONCE(sim_paused), 20 * HZ))
		sim_record(instance, "control resumed");
	else
		sim_record(instance, "control pause-timeout");
	WRITE_ONCE(sim_paused, false);
}

static void sim_label(char *out, size_t size, const char *name)
{
	size_t i;

	strscpy(out, name, size);
	for (i = 0; out[i]; i++)
		if (out[i] == ' ')
			out[i] = '_';
}

static __printf(3, 4) void sim_node_record(struct sim_node *node, const char *kind,
					   const char *fmt, ...)
{
	char label[sizeof(node->name)], rest[SIM_TEXT];
	va_list ap;
	int len;

	sim_label(label, sizeof(label), node->name);
	va_start(ap, fmt);
	len = vsnprintf(rest, sizeof(rest), fmt, ap);
	va_end(ap);
	if (len < 0 || len >= (int)sizeof(rest)) {
		unsigned long flags;

		/* Too long to record exactly: count it as dropped. */
		spin_lock_irqsave(&sim_log.lock, flags);
		sim_log.dropped++;
		spin_unlock_irqrestore(&sim_log.lock, flags);
		return;
	}
	sim_record(node->inst->id, "%s %s%s%s", kind, label, rest[0] ? " " : "", rest);
}

static void sim_node_init(struct sim_node *node, struct sim_instance *inst, const char *name)
{
	node->inst = inst;
	strscpy(node->name, name, sizeof(node->name));
	atomic_set(&node->opens, 0);
	mutex_lock(&sim_nodes_lock);
	list_add_tail(&node->list, &sim_nodes);
	mutex_unlock(&sim_nodes_lock);
}

/* Sensors, mirroring the pinned drivers' control ids and read-only flags. */

static const char *const ov5693_patterns[] = {
	"Disabled", "Random Data", "Colour Bars", "Colour Bars with Rolling Bar",
};
static const char *const ov8865_patterns[] = {
	"Disabled", "Random data", "Color bars", "Color bars with rolling bar",
	"Color squares", "Color squares with rolling bar",
};
static const char *const ov7251_patterns[] = { "Disabled", "Vertical Pattern Bars" };

enum { SENSOR_FRONT, SENSOR_IR, SENSOR_REAR };

static const struct sim_sensor_desc sim_sensor_descs[SIM_SENSORS] = {
	[SENSOR_FRONT] = {
		.pdev_name = "book2-lab-ov5693", .name = "ov5693 2-0036",
		.code = MEDIA_BUS_FMT_SBGGR10_1X10, .width = 2592, .height = 1944,
		.frame_sizes = 2,
		.native = { 0, 0, 2624, 1956 }, .active = { 16, 6, 2592, 1944 },
		.pixel_rate = 167680000, .link_freq = 419200000,
		/* Synthetic default VTS 1984; the driver computes it per mode. */
		.exp_min = 1, .exp_max = 1976, .exp_def = 1976,
		.gain_id = V4L2_CID_ANALOGUE_GAIN,
		.gain_min = 1, .gain_max = 127, .gain_step = 1, .gain_def = 8,
		.digital_gain = true, .fwnode_props = true,
		.hblank = 96, .vblank_min = 4, .vblank_max = 0xffff - 1944, .vblank_def = 40,
		.patterns = ov5693_patterns, .n_patterns = ARRAY_SIZE(ov5693_patterns),
		.orientation = V4L2_CAMERA_ORIENTATION_FRONT,
	},
	[SENSOR_IR] = {
		.pdev_name = "book2-lab-ov7251", .name = "ov7251 4-0060",
		.code = MEDIA_BUS_FMT_Y10_1X10, .width = 640, .height = 480,
		.frame_sizes = 1,
		.native = { 0, 0, 656, 496 }, .active = { 4, 4, 648, 488 },
		.pixel_rate = 48000000, .link_freq = 240000000,
		.exp_min = 1, .exp_max = 32, .exp_def = 32,
		.gain_id = V4L2_CID_GAIN,
		.gain_min = 16, .gain_max = 1023, .gain_step = 1, .gain_def = 16,
		/* Synthetic blanking. */
		.hblank = 128, .vblank_min = 20, .vblank_max = 0xffff - 480, .vblank_def = 1244,
		.patterns = ov7251_patterns, .n_patterns = ARRAY_SIZE(ov7251_patterns),
		.orientation = V4L2_CAMERA_ORIENTATION_FRONT,
	},
	[SENSOR_REAR] = {
		.pdev_name = "book2-lab-ov8865", .name = "ov8865 3-0010",
		.code = MEDIA_BUS_FMT_SBGGR10_1X10, .width = 3264, .height = 2448,
		.frame_sizes = 1,
		.native = { 0, 0, 3296, 2528 }, .active = { 16, 40, 3264, 2448 },
		/* Synthetic rates, exposure, gain and blanking. */
		.pixel_rate = 288000000, .link_freq = 360000000,
		.exp_min = 2, .exp_max = 2496, .exp_def = 2496,
		.gain_id = V4L2_CID_ANALOGUE_GAIN,
		.gain_min = 128, .gain_max = 2048, .gain_step = 128, .gain_def = 128,
		.white_balance = true, .fwnode_props = true,
		.hblank = 576, .vblank_min = 48, .vblank_max = 0xffff - 2448, .vblank_def = 48,
		.patterns = ov8865_patterns, .n_patterns = ARRAY_SIZE(ov8865_patterns),
		.orientation = V4L2_CAMERA_ORIENTATION_BACK,
	},
};

static int sim_try_ctrl(struct v4l2_ctrl *ctrl)
{
	struct sim_handler *h = container_of(ctrl->handler, struct sim_handler, hdl);

	sim_node_record(h->node, "ctrl", "0x%x=%d", ctrl->id, ctrl->val);
	return 0;
}

static int sim_s_ctrl(struct v4l2_ctrl *ctrl)
{
	return 0;
}

static const struct v4l2_ctrl_ops sim_ctrl_ops = {
	.try_ctrl = sim_try_ctrl,
	.s_ctrl = sim_s_ctrl,
};

static int sim_sd_open(struct v4l2_subdev *sd, struct v4l2_subdev_fh *fh)
{
	struct sim_node *node = v4l2_get_subdevdata(sd);

	atomic_inc(&node->opens);
	sim_node_record(node, "open", "%s", "");
	return 0;
}

static int sim_sd_close(struct v4l2_subdev *sd, struct v4l2_subdev_fh *fh)
{
	struct sim_node *node = v4l2_get_subdevdata(sd);

	sim_node_record(node, "release", "%s", "");
	atomic_dec(&node->opens);
	return 0;
}

static void sim_extra_register(struct sim_instance *inst);

static int sim_sensor_init_state(struct v4l2_subdev *sd, struct v4l2_subdev_state *state)
{
	struct sim_sensor *s = container_of(sd, struct sim_sensor, sd);
	struct v4l2_mbus_framefmt *fmt = v4l2_subdev_state_get_format(state, 0);

	fmt->code = s->desc->code;
	fmt->width = s->desc->width;
	fmt->height = s->desc->height;
	fmt->field = V4L2_FIELD_NONE;
	fmt->colorspace = V4L2_COLORSPACE_RAW;
	return 0;
}

static int sim_sensor_enum_mbus_code(struct v4l2_subdev *sd, struct v4l2_subdev_state *state,
				     struct v4l2_subdev_mbus_code_enum *code)
{
	struct sim_sensor *s = container_of(sd, struct sim_sensor, sd);

	if (code->index)
		return -EINVAL;
	code->code = s->desc->code;
	return 0;
}

static int sim_sensor_enum_frame_size(struct v4l2_subdev *sd, struct v4l2_subdev_state *state,
				      struct v4l2_subdev_frame_size_enum *fse)
{
	struct sim_sensor *s = container_of(sd, struct sim_sensor, sd);

	if (fse->code != s->desc->code || fse->index >= s->desc->frame_sizes)
		return -EINVAL;
	fse->min_width = s->desc->width / (fse->index + 1);
	fse->min_height = s->desc->height / (fse->index + 1);
	fse->max_width = fse->min_width;
	fse->max_height = fse->min_height;
	return 0;
}

static int sim_sensor_set_fmt(struct v4l2_subdev *sd, struct v4l2_subdev_state *state,
			      struct v4l2_subdev_format *format)
{
	struct sim_sensor *s = container_of(sd, struct sim_sensor, sd);
	const struct sim_sensor_desc *d = s->desc;
	struct v4l2_mbus_framefmt *fmt = v4l2_subdev_state_get_format(state, format->pad);
	bool half = d->frame_sizes > 1 && format->format.width <= d->width / 2 &&
		    format->format.height <= d->height / 2 && format->format.width;

	fmt->code = d->code;
	fmt->width = half ? d->width / 2 : d->width;
	fmt->height = half ? d->height / 2 : d->height;
	fmt->field = V4L2_FIELD_NONE;
	fmt->colorspace = V4L2_COLORSPACE_RAW;
	format->format = *fmt;
	sim_node_record(&s->node, "fmt", "%u %s 0x%x %ux%u", format->pad,
			format->which == V4L2_SUBDEV_FORMAT_ACTIVE ? "active" : "try",
			fmt->code, fmt->width, fmt->height);
	if (format->which == V4L2_SUBDEV_FORMAT_ACTIVE && s->front &&
	    atomic_xchg(&sim_bump_armed, 0)) {
		sim_record(s->node.inst->id, "control bump-fired");
		sim_extra_register(s->node.inst);
	}
	if (format->which == V4L2_SUBDEV_FORMAT_ACTIVE && s->front &&
	    atomic_xchg(&sim_media_armed, 0))
		sim_record(s->node.inst->id, "control media-%s", sim_add_media() ? "failed" : "fired");
	if (format->which == V4L2_SUBDEV_FORMAT_ACTIVE && s->front)
		sim_pause(s->node.inst->id, SIM_PAUSE_FRONT_FMT);
	return 0;
}

static int sim_sensor_get_selection(struct v4l2_subdev *sd, struct v4l2_subdev_state *state,
				    struct v4l2_subdev_selection *sel)
{
	struct sim_sensor *s = container_of(sd, struct sim_sensor, sd);

	if (sel->pad)
		return -EINVAL;
	switch (sel->target) {
	case V4L2_SEL_TGT_NATIVE_SIZE:
	case V4L2_SEL_TGT_CROP_BOUNDS:
		sel->r = s->desc->native;
		return 0;
	case V4L2_SEL_TGT_CROP_DEFAULT:
	case V4L2_SEL_TGT_CROP:
		sel->r = s->desc->active;
		return 0;
	default:
		return -EINVAL;
	}
}

static const struct v4l2_subdev_pad_ops sim_sensor_pad_ops = {
	.enum_mbus_code = sim_sensor_enum_mbus_code,
	.enum_frame_size = sim_sensor_enum_frame_size,
	.get_fmt = v4l2_subdev_get_fmt,
	.set_fmt = sim_sensor_set_fmt,
	.get_selection = sim_sensor_get_selection,
};

static const struct v4l2_subdev_ops sim_sensor_ops = { .pad = &sim_sensor_pad_ops };

static const struct v4l2_subdev_internal_ops sim_sensor_internal_ops = {
	.init_state = sim_sensor_init_state,
	.open = sim_sd_open,
	.close = sim_sd_close,
};

/* CSI-2 receivers and ImgU pipes: formats and selections are recorded only. */

static int sim_bridge_init_state(struct v4l2_subdev *sd, struct v4l2_subdev_state *state)
{
	unsigned int pad;

	for (pad = 0; pad < sd->entity.num_pads; pad++) {
		struct v4l2_mbus_framefmt *fmt = v4l2_subdev_state_get_format(state, pad);

		fmt->code = MEDIA_BUS_FMT_SGRBG10_1X10;
		fmt->width = 1936;
		fmt->height = 1096;
		fmt->field = V4L2_FIELD_NONE;
	}
	return 0;
}

static int sim_bridge_set_fmt(struct v4l2_subdev *sd, struct v4l2_subdev_state *state,
			      struct v4l2_subdev_format *format)
{
	struct sim_node *node = v4l2_get_subdevdata(sd);
	struct v4l2_mbus_framefmt *fmt = v4l2_subdev_state_get_format(state, format->pad);

	*fmt = format->format;
	sim_node_record(node, "fmt", "%u %s 0x%x %ux%u", format->pad,
			format->which == V4L2_SUBDEV_FORMAT_ACTIVE ? "active" : "try",
			fmt->code, fmt->width, fmt->height);
	return 0;
}

static int sim_bridge_set_selection(struct v4l2_subdev *sd, struct v4l2_subdev_state *state,
				    struct v4l2_subdev_selection *sel)
{
	struct sim_node *node = v4l2_get_subdevdata(sd);

	sim_node_record(node, "sel", "%u 0x%x %d,%d,%ux%u", sel->pad, sel->target,
			sel->r.left, sel->r.top, sel->r.width, sel->r.height);
	return 0;
}

static int sim_bridge_get_selection(struct v4l2_subdev *sd, struct v4l2_subdev_state *state,
				    struct v4l2_subdev_selection *sel)
{
	struct v4l2_mbus_framefmt *fmt = v4l2_subdev_state_get_format(state, sel->pad);

	sel->r = (struct v4l2_rect){ 0, 0, fmt->width, fmt->height };
	return 0;
}

static const struct v4l2_subdev_pad_ops sim_bridge_pad_ops = {
	.get_fmt = v4l2_subdev_get_fmt,
	.set_fmt = sim_bridge_set_fmt,
	.get_selection = sim_bridge_get_selection,
	.set_selection = sim_bridge_set_selection,
};

static const struct v4l2_subdev_ops sim_bridge_ops = { .pad = &sim_bridge_pad_ops };

static const struct v4l2_subdev_internal_ops sim_bridge_internal_ops = {
	.init_state = sim_bridge_init_state,
	.open = sim_sd_open,
	.close = sim_sd_close,
};

/* Video nodes: query and enumeration only, no buffers. */

static const u32 cio2_formats[] = {
	V4L2_PIX_FMT_IPU3_SGRBG10, V4L2_PIX_FMT_IPU3_SGBRG10, V4L2_PIX_FMT_IPU3_SBGGR10,
	V4L2_PIX_FMT_IPU3_SRGGB10, V4L2_PIX_FMT_IPU3_Y10,
};
static const u32 imgu_raw_formats[] = {
	V4L2_PIX_FMT_IPU3_SGRBG10, V4L2_PIX_FMT_IPU3_SGBRG10, V4L2_PIX_FMT_IPU3_SBGGR10,
	V4L2_PIX_FMT_IPU3_SRGGB10,
};
static const u32 imgu_yuv_formats[] = { V4L2_PIX_FMT_NV12 };
static const u32 imgu_params_formats[] = { SIM_META_FMT_IPU3_PARAMS };
static const u32 imgu_stat_formats[] = { SIM_META_FMT_IPU3_STAT_3A };

static int sim_video_open(struct file *file)
{
	struct sim_node *node = video_drvdata(file);
	int ret = v4l2_fh_open(file);

	if (ret)
		return ret;
	atomic_inc(&node->opens);
	sim_node_record(node, "open", "%s", "");
	return 0;
}

static int sim_video_release(struct file *file)
{
	struct sim_node *node = video_drvdata(file);

	sim_node_record(node, "release", "%s", "");
	atomic_dec(&node->opens);
	return v4l2_fh_release(file);
}

static const struct v4l2_file_operations sim_video_fops = {
	.owner = THIS_MODULE,
	.open = sim_video_open,
	.release = sim_video_release,
	.unlocked_ioctl = video_ioctl2,
};

static int sim_querycap(struct file *file, void *fh, struct v4l2_capability *cap)
{
	struct sim_video *v = video_drvdata(file);
	bool cio2 = v->buf_type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE && v->formats == cio2_formats;

	strscpy(cap->driver, cio2 ? "ipu3-cio2" : "ipu3-imgu", sizeof(cap->driver));
	strscpy(cap->card, cio2 ? "Intel IPU3 CIO2" : "ipu3-imgu", sizeof(cap->card));
	snprintf(cap->bus_info, sizeof(cap->bus_info), "platform:book2-lab-sim.%u", v->node.inst->id);
	return 0;
}

static int sim_enum_fmt(struct file *file, void *fh, struct v4l2_fmtdesc *f)
{
	struct sim_video *v = video_drvdata(file);

	if (f->type != v->buf_type || f->index >= v->n_formats)
		return -EINVAL;
	f->pixelformat = v->formats[f->index];
	/* The core has no names for the private IPU3 metadata formats. */
	if (f->pixelformat == SIM_META_FMT_IPU3_PARAMS)
		strscpy(f->description, "IPU3 processing parameters", sizeof(f->description));
	else if (f->pixelformat == SIM_META_FMT_IPU3_STAT_3A)
		strscpy(f->description, "IPU3 3A statistics", sizeof(f->description));
	return 0;
}

static int sim_g_fmt_mplane(struct file *file, void *fh, struct v4l2_format *f)
{
	struct sim_video *v = video_drvdata(file);
	struct v4l2_pix_format_mplane *pix = &f->fmt.pix_mp;
	bool yuv = v->formats == imgu_yuv_formats;

	if (f->type != v->buf_type)
		return -EINVAL;
	memset(pix, 0, sizeof(*pix));
	pix->width = yuv ? 1920 : 1936;
	pix->height = yuv ? 1080 : 1096;
	pix->pixelformat = v->formats[0];
	pix->field = V4L2_FIELD_NONE;
	pix->num_planes = 1;
	pix->plane_fmt[0].bytesperline = yuv ? 1920 : DIV_ROUND_UP(1936, 50) * 64;
	pix->plane_fmt[0].sizeimage = pix->plane_fmt[0].bytesperline * pix->height * (yuv ? 3 : 2) / 2;
	return 0;
}

static int sim_g_fmt_meta(struct file *file, void *fh, struct v4l2_format *f)
{
	struct sim_video *v = video_drvdata(file);

	if (f->type != v->buf_type)
		return -EINVAL;
	memset(&f->fmt.meta, 0, sizeof(f->fmt.meta));
	f->fmt.meta.dataformat = v->formats[0];
	f->fmt.meta.buffersize = 0x10000; /* synthetic */
	return 0;
}

static const struct v4l2_ioctl_ops sim_ioctl_ops = {
	.vidioc_querycap = sim_querycap,
	.vidioc_enum_fmt_vid_cap = sim_enum_fmt,
	.vidioc_enum_fmt_vid_out = sim_enum_fmt,
	.vidioc_enum_fmt_meta_cap = sim_enum_fmt,
	.vidioc_enum_fmt_meta_out = sim_enum_fmt,
	.vidioc_g_fmt_vid_cap_mplane = sim_g_fmt_mplane,
	.vidioc_g_fmt_vid_out_mplane = sim_g_fmt_mplane,
	.vidioc_g_fmt_meta_cap = sim_g_fmt_meta,
	.vidioc_g_fmt_meta_out = sim_g_fmt_meta,
};

/* Links. */

static int sim_link_notify(struct media_link *link, u32 flags, unsigned int notification)
{
	struct media_device *mdev = link->graph_obj.mdev;
	struct sim_instance *inst = dev_get_drvdata(mdev->dev);
	char source[48], sink[48];

	if (notification != MEDIA_DEV_NOTIFY_POST_LINK_CH)
		return 0;
	sim_label(source, sizeof(source), link->source->entity->name);
	sim_label(sink, sizeof(sink), link->sink->entity->name);
	sim_record(inst->id, "%s %s:%u %s:%u 0x%x", link->flags == flags ? "link" : "link-failed",
		   source, link->source->index, sink, link->sink->index, flags);
	/* Only sensor entities are sim_sensor subdevs; the pause follows the front link enable. */
	if (link->flags == flags && (flags & MEDIA_LNK_FL_ENABLED) &&
	    link->source->entity->function == MEDIA_ENT_F_CAM_SENSOR &&
	    container_of(media_entity_to_v4l2_subdev(link->source->entity), struct sim_sensor, sd)->front)
		sim_pause(inst->id, SIM_PAUSE_FRONT_LINK);
	return 0;
}

static const struct media_device_ops sim_media_ops = { .link_notify = sim_link_notify };

/* Registration. */

static int sim_media_init(struct media_device *mdev, struct platform_device *pdev,
			  const char *driver, const char *model)
{
	mdev->dev = &pdev->dev;
	strscpy(mdev->driver_name, driver, sizeof(mdev->driver_name));
	strscpy(mdev->model, model, sizeof(mdev->model));
	snprintf(mdev->bus_info, sizeof(mdev->bus_info), "platform:%s", dev_name(&pdev->dev));
	mdev->hw_revision = 0;
	mdev->ops = &sim_media_ops;
	media_device_init(mdev);
	return 0;
}

static int sim_v4l2_init(struct v4l2_device *v4l2, struct media_device *mdev,
			 struct platform_device *pdev)
{
	snprintf(v4l2->name, sizeof(v4l2->name), "book2-lab %s", dev_name(&pdev->dev));
	v4l2->mdev = mdev;
	return v4l2_device_register(&pdev->dev, v4l2);
}

static int sim_subdev_register(struct sim_subdev *sub, struct sim_instance *inst,
			       struct v4l2_device *v4l2, const char *name, u32 function,
			       const unsigned long *pad_flags, unsigned int n_pads)
{
	unsigned int i;
	int ret;

	sim_node_init(&sub->node, inst, name);
	v4l2_subdev_init(&sub->sd, &sim_bridge_ops);
	sub->sd.internal_ops = &sim_bridge_internal_ops;
	sub->sd.flags |= V4L2_SUBDEV_FL_HAS_DEVNODE;
	sub->sd.owner = THIS_MODULE;
	sub->sd.dev = v4l2->dev;
	strscpy(sub->sd.name, name, sizeof(sub->sd.name));
	sub->sd.entity.function = function;
	v4l2_set_subdevdata(&sub->sd, &sub->node);
	for (i = 0; i < n_pads; i++)
		sub->pads[i].flags = pad_flags[i];
	ret = media_entity_pads_init(&sub->sd.entity, n_pads, sub->pads);
	if (ret)
		return ret;
	ret = v4l2_subdev_init_finalize(&sub->sd);
	if (ret)
		return ret;
	return v4l2_device_register_subdev(v4l2, &sub->sd);
}

static void sim_sensor_controls(struct sim_sensor *s)
{
	const struct sim_sensor_desc *d = s->desc;
	struct v4l2_ctrl_handler *hdl = &s->ctrls.hdl;
	struct v4l2_ctrl *ctrl;
	const s64 *link_freq = &d->link_freq;

	s->ctrls.node = &s->node;
	v4l2_ctrl_handler_init(hdl, 14);
	ctrl = v4l2_ctrl_new_int_menu(hdl, NULL, V4L2_CID_LINK_FREQ, 0, 0, link_freq);
	if (ctrl)
		ctrl->flags |= V4L2_CTRL_FLAG_READ_ONLY;
	v4l2_ctrl_new_std(hdl, NULL, V4L2_CID_PIXEL_RATE, d->pixel_rate, d->pixel_rate, 1,
			  d->pixel_rate);
	v4l2_ctrl_new_std(hdl, &sim_ctrl_ops, V4L2_CID_EXPOSURE, d->exp_min, d->exp_max, 1,
			  d->exp_def);
	v4l2_ctrl_new_std(hdl, &sim_ctrl_ops, d->gain_id, d->gain_min, d->gain_max, d->gain_step,
			  d->gain_def);
	if (d->digital_gain)
		v4l2_ctrl_new_std(hdl, &sim_ctrl_ops, V4L2_CID_DIGITAL_GAIN, 1, 4095, 1, 1024);
	if (d->white_balance) {
		v4l2_ctrl_new_std(hdl, &sim_ctrl_ops, V4L2_CID_RED_BALANCE, 1, 32767, 1, 1024);
		v4l2_ctrl_new_std(hdl, &sim_ctrl_ops, V4L2_CID_BLUE_BALANCE, 1, 32767, 1, 1024);
	}
	v4l2_ctrl_new_std(hdl, &sim_ctrl_ops, V4L2_CID_HFLIP, 0, 1, 1, 0);
	v4l2_ctrl_new_std(hdl, &sim_ctrl_ops, V4L2_CID_VFLIP, 0, 1, 1, 0);
	ctrl = v4l2_ctrl_new_std(hdl, &sim_ctrl_ops, V4L2_CID_HBLANK, d->hblank, d->hblank, 1,
				 d->hblank);
	if (ctrl)
		ctrl->flags |= V4L2_CTRL_FLAG_READ_ONLY;
	v4l2_ctrl_new_std(hdl, &sim_ctrl_ops, V4L2_CID_VBLANK, d->vblank_min, d->vblank_max, 1,
			  d->vblank_def);
	v4l2_ctrl_new_std_menu_items(hdl, &sim_ctrl_ops, V4L2_CID_TEST_PATTERN,
				     d->n_patterns - 1, 0, 0, d->patterns);
	if (d->fwnode_props) {
		v4l2_ctrl_new_std_menu(hdl, &sim_ctrl_ops, V4L2_CID_CAMERA_ORIENTATION,
				       V4L2_CAMERA_ORIENTATION_EXTERNAL, 0, d->orientation);
		v4l2_ctrl_new_std(hdl, &sim_ctrl_ops, V4L2_CID_CAMERA_SENSOR_ROTATION, 0, 0, 1, 0);
	}
	s->sd.ctrl_handler = hdl;
}

static int sim_sensor_register(struct sim_sensor *s, struct sim_instance *inst,
			       const struct sim_sensor_desc *desc, bool front)
{
	int ret;

	s->desc = desc;
	s->front = front;
	s->pdev = platform_device_register_simple(desc->pdev_name, inst->id, NULL, 0);
	if (IS_ERR(s->pdev))
		return PTR_ERR(s->pdev);
	sim_node_init(&s->node, inst, desc->name);
	v4l2_subdev_init(&s->sd, &sim_sensor_ops);
	s->sd.internal_ops = &sim_sensor_internal_ops;
	s->sd.flags |= V4L2_SUBDEV_FL_HAS_DEVNODE;
	s->sd.owner = THIS_MODULE;
	s->sd.dev = &s->pdev->dev;
	strscpy(s->sd.name, desc->name, sizeof(s->sd.name));
	s->sd.entity.function = MEDIA_ENT_F_CAM_SENSOR;
	v4l2_set_subdevdata(&s->sd, &s->node);
	sim_sensor_controls(s);
	if (s->ctrls.hdl.error)
		return s->ctrls.hdl.error;
	s->pad.flags = MEDIA_PAD_FL_SOURCE;
	ret = media_entity_pads_init(&s->sd.entity, 1, &s->pad);
	if (ret)
		return ret;
	ret = v4l2_subdev_init_finalize(&s->sd);
	if (ret)
		return ret;
	return v4l2_device_register_subdev(&inst->cio2_v4l2, &s->sd);
}

static int sim_video_register(struct sim_video *v, struct sim_instance *inst,
			      struct v4l2_device *v4l2, const char *name, u32 buf_type,
			      u32 caps, const u32 *formats, unsigned int n_formats)
{
	bool output = buf_type == V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE ||
		      buf_type == V4L2_BUF_TYPE_META_OUTPUT;
	int ret;

	sim_node_init(&v->node, inst, name);
	v->formats = formats;
	v->n_formats = n_formats;
	v->buf_type = buf_type;
	strscpy(v->vdev.name, name, sizeof(v->vdev.name));
	v->vdev.fops = &sim_video_fops;
	v->vdev.ioctl_ops = &sim_ioctl_ops;
	v->vdev.v4l2_dev = v4l2;
	v->vdev.release = video_device_release_empty;
	v->vdev.vfl_dir = output ? VFL_DIR_TX : VFL_DIR_RX;
	v->vdev.device_caps = caps;
	v->pad.flags = output ? MEDIA_PAD_FL_SOURCE : MEDIA_PAD_FL_SINK;
	ret = media_entity_pads_init(&v->vdev.entity, 1, &v->pad);
	if (ret)
		return ret;
	/* video_drvdata() returns this sim_video, whose first member is the node. */
	video_set_drvdata(&v->vdev, v);
	return video_register_device(&v->vdev, VFL_TYPE_VIDEO, -1);
}

static const struct {
	const char *suffix;
	u32 buf_type;
	u32 caps;
	const u32 *formats;
	unsigned int n_formats;
	bool immutable;
} sim_imgu_nodes[SIM_IMGU_NODES] = {
	{ "input", V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE, V4L2_CAP_VIDEO_OUTPUT_MPLANE,
	  imgu_raw_formats, ARRAY_SIZE(imgu_raw_formats), false },
	{ "parameters", V4L2_BUF_TYPE_META_OUTPUT, V4L2_CAP_META_OUTPUT,
	  imgu_params_formats, ARRAY_SIZE(imgu_params_formats), false },
	{ "output", V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE, V4L2_CAP_VIDEO_CAPTURE_MPLANE,
	  imgu_yuv_formats, ARRAY_SIZE(imgu_yuv_formats), true },
	{ "viewfinder", V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE, V4L2_CAP_VIDEO_CAPTURE_MPLANE,
	  imgu_yuv_formats, ARRAY_SIZE(imgu_yuv_formats), false },
	{ "3a stat", V4L2_BUF_TYPE_META_CAPTURE, V4L2_CAP_META_CAPTURE,
	  imgu_stat_formats, ARRAY_SIZE(imgu_stat_formats), false },
};

static const char *const sim_imgu_modes[] = { "Video mode", "Still mode" };

static int sim_imgu_register(struct sim_instance *inst, unsigned int pipe)
{
	static const unsigned long pads[SIM_IMGU_NODES] = {
		MEDIA_PAD_FL_SINK, MEDIA_PAD_FL_SINK, MEDIA_PAD_FL_SOURCE,
		MEDIA_PAD_FL_SOURCE, MEDIA_PAD_FL_SOURCE,
	};
	const struct v4l2_ctrl_config mode = {
		.ops = &sim_ctrl_ops, .id = SIM_CID_INTEL_IPU3_MODE, .name = "IPU3 Pipe Mode",
		.type = V4L2_CTRL_TYPE_MENU, .max = ARRAY_SIZE(sim_imgu_modes) - 1, .def = 0,
		.qmenu = sim_imgu_modes,
	};
	struct sim_subdev *sub = &inst->imgu[pipe];
	char name[48];
	unsigned int i;
	int ret;

	snprintf(name, sizeof(name), "ipu3-imgu %u", pipe);
	sub->ctrls.node = &sub->node;
	v4l2_ctrl_handler_init(&sub->ctrls.hdl, 1);
	v4l2_ctrl_new_custom(&sub->ctrls.hdl, &mode, NULL);
	if (sub->ctrls.hdl.error)
		return sub->ctrls.hdl.error;
	sub->sd.ctrl_handler = &sub->ctrls.hdl;
	ret = sim_subdev_register(sub, inst, &inst->imgu_v4l2, name,
				  MEDIA_ENT_F_PROC_VIDEO_STATISTICS, pads, SIM_IMGU_NODES);
	if (ret)
		return ret;
	for (i = 0; i < SIM_IMGU_NODES; i++) {
		snprintf(name, sizeof(name), "ipu3-imgu %u %s", pipe, sim_imgu_nodes[i].suffix);
		ret = sim_video_register(&inst->imgu_video[pipe][i], inst, &inst->imgu_v4l2, name,
					 sim_imgu_nodes[i].buf_type,
					 sim_imgu_nodes[i].caps | V4L2_CAP_STREAMING | V4L2_CAP_IO_MC,
					 sim_imgu_nodes[i].formats, sim_imgu_nodes[i].n_formats);
		if (ret)
			return ret;
	}
	return 0;
}

static int sim_imgu_links(struct sim_instance *inst, unsigned int pipe)
{
	struct media_entity *sd = &inst->imgu[pipe].sd.entity;
	unsigned int i;
	int ret;

	for (i = 0; i < SIM_IMGU_NODES; i++) {
		struct media_entity *vdev = &inst->imgu_video[pipe][i].vdev.entity;
		u32 flags = sim_imgu_nodes[i].immutable ?
			    MEDIA_LNK_FL_ENABLED | MEDIA_LNK_FL_IMMUTABLE : 0;

		if (inst->imgu_video[pipe][i].pad.flags & MEDIA_PAD_FL_SOURCE)
			ret = media_create_pad_link(vdev, 0, sd, i, flags);
		else
			ret = media_create_pad_link(sd, i, vdev, 0, flags);
		if (ret)
			return ret;
	}
	return 0;
}

static struct sim_instance *sim_instance_create(u32 id)
{
	static const unsigned long csi2_pads[2] = { MEDIA_PAD_FL_SINK, MEDIA_PAD_FL_SOURCE };
	const unsigned int ports[SIM_SENSORS] = {
		[SENSOR_FRONT] = front_port, [SENSOR_IR] = 1, [SENSOR_REAR] = 2,
	};
	struct sim_instance *inst;
	char name[48];
	unsigned int i;
	int ret;

	inst = kzalloc(sizeof(*inst), GFP_KERNEL);
	if (!inst)
		return ERR_PTR(-ENOMEM);
	inst->id = id;
	inst->cio2_pdev = platform_device_register_simple("book2-lab-cio2", id, NULL, 0);
	inst->imgu_pdev = platform_device_register_simple("book2-lab-imgu", id, NULL, 0);
	if (IS_ERR(inst->cio2_pdev) || IS_ERR(inst->imgu_pdev) ||
	    !inst->cio2_pdev->dev.driver || !inst->imgu_pdev->dev.driver)
		return ERR_PTR(-ENODEV);
	platform_set_drvdata(inst->cio2_pdev, inst);
	platform_set_drvdata(inst->imgu_pdev, inst);
	sim_media_init(&inst->cio2_mdev, inst->cio2_pdev, "ipu3-cio2", "Intel IPU3 CIO2");
	sim_media_init(&inst->imgu_mdev, inst->imgu_pdev, "ipu3-imgu", "ipu3-imgu");
	ret = sim_v4l2_init(&inst->cio2_v4l2, &inst->cio2_mdev, inst->cio2_pdev);
	if (!ret)
		ret = sim_v4l2_init(&inst->imgu_v4l2, &inst->imgu_mdev, inst->imgu_pdev);
	for (i = 0; !ret && i < SIM_PORTS; i++) {
		snprintf(name, sizeof(name), "ipu3-csi2 %u", i);
		ret = sim_subdev_register(&inst->csi2[i], inst, &inst->cio2_v4l2, name,
					  MEDIA_ENT_F_VID_IF_BRIDGE, csi2_pads, 2);
		if (ret)
			break;
		snprintf(name, sizeof(name), "ipu3-cio2 %u", i);
		ret = sim_video_register(&inst->cio2_video[i], inst, &inst->cio2_v4l2, name,
					 V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE,
					 V4L2_CAP_VIDEO_CAPTURE_MPLANE | V4L2_CAP_STREAMING,
					 cio2_formats, ARRAY_SIZE(cio2_formats));
	}
	for (i = 0; !ret && i < SIM_SENSORS; i++)
		ret = sim_sensor_register(&inst->sensors[i], inst, &sim_sensor_descs[i],
					  i == SENSOR_FRONT);
	for (i = 0; !ret && i < SIM_PIPES; i++)
		ret = sim_imgu_register(inst, i);
	if (!ret)
		ret = v4l2_device_register_subdev_nodes(&inst->cio2_v4l2);
	if (!ret)
		ret = v4l2_device_register_subdev_nodes(&inst->imgu_v4l2);
	for (i = 0; !ret && i < SIM_PORTS; i++)
		ret = media_create_pad_link(&inst->csi2[i].sd.entity, 1,
					    &inst->cio2_video[i].vdev.entity, 0,
					    MEDIA_LNK_FL_ENABLED | MEDIA_LNK_FL_IMMUTABLE);
	for (i = 0; !ret && i < SIM_SENSORS; i++)
		ret = media_create_pad_link(&inst->sensors[i].sd.entity, 0,
					    &inst->csi2[ports[i]].sd.entity, 0, 0);
	for (i = 0; !ret && i < SIM_PIPES; i++)
		ret = sim_imgu_links(inst, i);
	if (!ret)
		ret = media_device_register(&inst->cio2_mdev);
	if (!ret)
		ret = media_device_register(&inst->imgu_mdev);
	return ret ? ERR_PTR(ret) : inst;
}

static void sim_instance_unregister(struct sim_instance *inst)
{
	unsigned int i, j;

	media_device_unregister(&inst->cio2_mdev);
	media_device_unregister(&inst->imgu_mdev);
	for (i = 0; i < SIM_PORTS; i++)
		video_unregister_device(&inst->cio2_video[i].vdev);
	for (i = 0; i < SIM_PIPES; i++)
		for (j = 0; j < SIM_IMGU_NODES; j++)
			video_unregister_device(&inst->imgu_video[i][j].vdev);
	v4l2_device_unregister(&inst->cio2_v4l2);
	v4l2_device_unregister(&inst->imgu_v4l2);
}

static void sim_extra_register(struct sim_instance *inst)
{
	if (inst->extra_registered)
		return;
	/* A lens appearing late, as a VCM would; a defined function avoids a core warning. */
	inst->extra.name = "book2-lab-extra";
	inst->extra.function = MEDIA_ENT_F_LENS;
	inst->extra_pad.flags = MEDIA_PAD_FL_SINK;
	if (media_entity_pads_init(&inst->extra, 1, &inst->extra_pad) ||
	    media_device_register_entity(&inst->cio2_mdev, &inst->extra))
		return;
	inst->extra_registered = true;
}

static int sim_add_media(void)
{
	guard(mutex)(&sim_extra_lock);
	if (sim_extra_pdev)
		return -EBUSY;
	sim_extra_pdev = platform_device_register_simple("book2-lab-extra", 0, NULL, 0);
	if (IS_ERR(sim_extra_pdev))
		return PTR_ERR(sim_extra_pdev);
	if (!sim_extra_pdev->dev.driver)
		return -ENODEV;
	sim_media_init(&sim_extra_mdev, sim_extra_pdev, "book2-lab-extra", "book2-lab-extra");
	sim_extra_mdev.ops = NULL;
	return media_device_register(&sim_extra_mdev);
}

/* debugfs: effects and open counts (read), control (write). Root only. */

static int sim_effects_show(struct seq_file *m, void *unused)
{
	unsigned long flags;
	u64 i;

	spin_lock_irqsave(&sim_log.lock, flags);
	seq_printf(m, "dropped %llu\n", sim_log.dropped);
	for (i = 0; i < sim_log.count; i++)
		seq_printf(m, "%llu %u %d %s\n", sim_log.rec[i].seq, sim_log.rec[i].instance,
			   sim_log.rec[i].tgid, sim_log.rec[i].text);
	spin_unlock_irqrestore(&sim_log.lock, flags);
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(sim_effects);

static int sim_open_counts_show(struct seq_file *m, void *unused)
{
	struct sim_node *node;
	char label[48];

	mutex_lock(&sim_nodes_lock);
	list_for_each_entry(node, &sim_nodes, list) {
		sim_label(label, sizeof(label), node->name);
		seq_printf(m, "%u %s %d\n", node->inst->id, label, atomic_read(&node->opens));
	}
	mutex_unlock(&sim_nodes_lock);
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(sim_open_counts);

static ssize_t sim_control_write(struct file *file, const char __user *ubuf, size_t len,
				 loff_t *ppos)
{
	struct sim_instance *next;
	char buf[32];
	const char *cmd;
	int ret = 0;

	if (len == 0 || len >= sizeof(buf))
		return -EINVAL;
	if (copy_from_user(buf, ubuf, len))
		return -EFAULT;
	buf[len] = '\0';
	cmd = strim(buf);

	mutex_lock(&sim_control_lock);
	if (!sim_current) {
		ret = -ENODEV;
	} else if (!strcmp(cmd, "replace")) {
		sim_record(sim_current->id, "control replace");
		sim_instance_unregister(sim_current);
		next = sim_instance_create(sim_current->id + 1);
		if (IS_ERR(next)) {
			ret = PTR_ERR(next);
			sim_current = NULL;
		} else {
			sim_current = next;
		}
	} else if (!strcmp(cmd, "add-entity")) {
		sim_record(sim_current->id, "control add-entity");
		sim_extra_register(sim_current);
		ret = sim_current->extra_registered ? 0 : -EIO;
	} else if (!strcmp(cmd, "add-media")) {
		sim_record(sim_current->id, "control add-media");
		ret = sim_add_media();
	} else if (!strcmp(cmd, "bump-on-front-fmt")) {
		sim_record(sim_current->id, "control bump-on-front-fmt");
		atomic_set(&sim_bump_armed, 1);
	} else if (!strcmp(cmd, "add-media-on-front-fmt")) {
		sim_record(sim_current->id, "control add-media-on-front-fmt");
		atomic_set(&sim_media_armed, 1);
	} else if (!strcmp(cmd, "canary")) {
		sim_record(sim_current->id, "control canary");
	} else if (!strcmp(cmd, "pause-on-front-link")) {
		sim_record(sim_current->id, "control pause-on-front-link");
		atomic_set(&sim_pause_point, SIM_PAUSE_FRONT_LINK);
	} else if (!strcmp(cmd, "pause-on-front-fmt")) {
		sim_record(sim_current->id, "control pause-on-front-fmt");
		atomic_set(&sim_pause_point, SIM_PAUSE_FRONT_FMT);
	} else if (!strcmp(cmd, "resume")) {
		sim_record(sim_current->id, "control resume");
		WRITE_ONCE(sim_paused, false);
		wake_up(&sim_pause_wq);
	} else {
		ret = -EINVAL;
	}
	mutex_unlock(&sim_control_lock);
	return ret ? ret : (ssize_t)len;
}

static const struct file_operations sim_control_fops = {
	.owner = THIS_MODULE,
	.write = sim_control_write,
	.llseek = noop_llseek,
};

/*
 * Media and V4L2 cores expect the media device's parent to be bound to a
 * driver (subdev_open() takes mdev->dev->driver->owner), as real drivers are.
 * Unbinding through sysfs is suppressed.
 */
static int sim_platform_probe(struct platform_device *pdev)
{
	return 0;
}

static const struct platform_device_id sim_platform_ids[] = {
	{ "book2-lab-cio2" }, { "book2-lab-imgu" }, { "book2-lab-extra" }, { }
};

static struct platform_driver sim_platform_driver = {
	.probe = sim_platform_probe,
	.id_table = sim_platform_ids,
	.driver = { .name = "book2-lab-sim", .suppress_bind_attrs = true },
};

static int __init sim_init(void)
{
	struct dentry *dir;
	struct sim_instance *inst;
	int ret;

	if (front_port != 0 && front_port != 3) {
		pr_err("book2_lab_sim: front_port must be 0 or 3\n");
		return -EINVAL;
	}
	ret = platform_driver_register(&sim_platform_driver);
	if (ret)
		return ret;
	inst = sim_instance_create(1);
	if (IS_ERR(inst)) {
		pr_err("book2_lab_sim: graph registration failed: %ld\n", PTR_ERR(inst));
		return PTR_ERR(inst);
	}
	sim_current = inst;
	dir = debugfs_create_dir("book2_lab_sim", NULL);
	debugfs_create_file("effects", 0400, dir, NULL, &sim_effects_fops);
	debugfs_create_file("open_counts", 0400, dir, NULL, &sim_open_counts_fops);
	debugfs_create_file("control", 0200, dir, NULL, &sim_control_fops);
	return 0;
}
device_initcall(sim_init);
