/* SPDX-License-Identifier: LGPL-2.1-or-later */
#include "lab_guard.h"

#include <cerrno>
#include <cstdio>
#include <string>
#include <utility>
#include <vector>

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include <linux/media.h>
#include <linux/v4l2-subdev.h>
#include <linux/videodev2.h>

#include "libcamera/internal/media_device.h"

#include "discovery_requests.h"

extern char **environ;

namespace libcamera {

namespace book2lab {

namespace {

constexpr const char *kReservationPath = "/run/book2-lab/reservation";
constexpr int kVerdictFd = 3;

/* Files GlobalConfiguration reads for this build's prefix (/usr, sysconfdir /etc). */
const std::vector<std::string> kConfigFiles = {
	"/etc/libcamera/configuration.yaml",
	"/usr/share/libcamera/configuration.yaml",
};

bool readAll(const char *path, std::string *out)
{
	int fd = ::open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return false;
	char buf[4096];
	ssize_t n;
	while ((n = ::read(fd, buf, sizeof(buf))) > 0)
		out->append(buf, static_cast<size_t>(n));
	::close(fd);
	return n == 0;
}

const ::book2lab::DiscoveryRequest *lookup(unsigned long request)
{
	for (const auto &r : ::book2lab::kDiscoveryRequests)
		if (r.request == request)
			return &r;
	return nullptr;
}

std::vector<std::pair<unsigned, unsigned>> sysfsMedia()
{
	std::vector<std::pair<unsigned, unsigned>> devices;
	DIR *dir = opendir("/sys/bus/media/devices");
	if (!dir)
		return devices;
	while (dirent *entry = readdir(dir)) {
		std::string name = entry->d_name, dev;
		unsigned major = 0, minor = 0;
		if (name.rfind("media", 0) == 0 &&
		    readAll(("/sys/bus/media/devices/" + name + "/dev").c_str(), &dev) &&
		    std::sscanf(dev.c_str(), "%u:%u", &major, &minor) == 2)
			devices.emplace_back(major, minor);
	}
	closedir(dir);
	return devices;
}

unsigned int suffix(const std::string &name)
{
	size_t at = name.rfind('_');
	return at == std::string::npos ? 0 : static_cast<unsigned int>(std::stoul(name.substr(at + 1)));
}

const char *entityLabel(const ::book2lab::Snapshot &s, uint32_t id, std::string *out)
{
	for (const auto &e : s.entities)
		if (e.id == id && ::book2lab::label(e.name, out))
			return out->c_str();
	return nullptr;
}

} /* namespace */

Guard::Guard()
{
	std::string text;
	if (readAll(kReservationPath, &text))
		reservation_ = ::book2lab::parse_reservation(text);
	if (!reservation_)
		latched_ = "refuse reservation";
}

/* Latch the first refusal or hold; report it once on the verdict pipe. */
int Guard::refuse(const std::string &reason, bool hold)
{
	if (latched_.empty())
		latched_ = std::string(hold ? "hold " : "refuse ") + reason;
	if (!verdictWritten_) {
		std::string line = "VERDICT " + latched_ + "\n";
		[[maybe_unused]] ssize_t n = ::write(kVerdictFd, line.data(), line.size());
		verdictWritten_ = true;
	}
	return -EPERM;
}

int Guard::admitEffect(const ::book2lab::Effect &effect)
{
	Verdict v = ::book2lab::match_effect(*reservation_, effect, &ledger_);
	if (!v.ok)
		return refuse(v.reason + " " + ::book2lab::format_effect(effect));
	return 0;
}

Verdict Guard::admitDiscovery(MediaDevice &cio2, MediaDevice &imgu)
{
	std::lock_guard<std::mutex> lock(mutex_);
	auto fail = [this](const std::string &reason) {
		refuse(reason);
		return Verdict{ false, latched_ };
	};
	if (!latched_.empty())
		return fail(latched_);
	Verdict v = ::book2lab::check_environment(environ, kConfigFiles);
	if (v.ok)
		v = ::book2lab::check_media_set(*reservation_, sysfsMedia());
	if (v.ok)
		v = ::book2lab::check_front(*reservation_);
	if (!v.ok)
		return fail(v.reason);
	const std::pair<::book2lab::Role, MediaDevice *> media[] = {
		{ ::book2lab::Role::Cio2, &cio2 },
		{ ::book2lab::Role::Imgu, &imgu },
	};
	for (const auto &[role, device] : media) {
		::book2lab::Snapshot s;
		if (::book2lab::read_snapshot(device->labFd(), &s) != 0)
			return fail("snapshot");
		v = ::book2lab::compare_graph(*reservation_, role, s, ledger_);
		if (!v.ok)
			return fail(v.reason);
		if (device->topologyVersion() != s.version)
			return fail("version");
		snapshots_[::book2lab::role_name(role)] = std::move(s);
	}
	return {};
}

int Guard::admitOpen(const std::string &path, int flags, const Node **node)
{
	std::lock_guard<std::mutex> lock(mutex_);
	*node = nullptr;
	if (!latched_.empty())
		return refuse(latched_);
	const Node *match = nullptr;
	for (const Node &n : reservation_->nodes)
		if (n.path == path)
			match = &n;
	if (!match)
		return refuse("unreserved-open");
	int fd = ::open(path.c_str(), flags | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	struct stat st {};
	if (fstat(fd, &st) != 0 || !S_ISCHR(st.st_mode) || st.st_rdev != makedev(match->major, match->minor)) {
		::close(fd);
		return refuse("identity");
	}
	*node = match;
	return fd;
}

int Guard::admitIoctl(const Node *node, unsigned long request, void *arg)
{
	std::lock_guard<std::mutex> lock(mutex_);
	const ::book2lab::DiscoveryRequest *req = lookup(request);
	if (!node || !req)
		return refuse("unlisted-request");
	if (req->cls != ::book2lab::RequestClass::ListedEffect)
		return 0;
	if (request == VIDIOC_SUBDEV_S_FMT &&
	    static_cast<const v4l2_subdev_format *>(arg)->which == V4L2_SUBDEV_FORMAT_TRY)
		return 0;
	if (!latched_.empty())
		return refuse(latched_);
	::book2lab::Effect e;
	e.entity = node->entity;
	if (request == VIDIOC_S_EXT_CTRLS) {
		const auto *c = static_cast<const v4l2_ext_controls *>(arg);
		if (c->which != V4L2_CTRL_WHICH_CUR_VAL || !c->count)
			return refuse("unlisted-effect");
		e.kind = ::book2lab::Effect::Kind::Ctrl;
		for (unsigned int i = 0; i < c->count; i++) {
			/* v4l2_ext_control is packed: copy fields, never bind references. */
			const uint32_t id = c->controls[i].id;
			const int64_t value = c->controls[i].value;
			e.controls.emplace_back(id, value);
		}
	} else if (request == VIDIOC_SUBDEV_S_FMT) {
		const auto *f = static_cast<const v4l2_subdev_format *>(arg);
		e.kind = ::book2lab::Effect::Kind::Fmt;
		e.pad = f->pad;
		e.code = f->format.code;
		e.width = f->format.width;
		e.height = f->format.height;
	} else {
		return refuse("unlisted-request");
	}
	return admitEffect(e);
}

int Guard::admitMediaIoctl(const MediaDevice &media, unsigned long request, void *arg)
{
	std::lock_guard<std::mutex> lock(mutex_);
	const ::book2lab::DiscoveryRequest *req = lookup(request);
	if (!req)
		return refuse("unlisted-request");
	if (req->cls != ::book2lab::RequestClass::ListedEffect)
		return 0;
	if (!latched_.empty())
		return refuse(latched_);
	const std::string role = ::book2lab::role_for_driver(media.driver());
	auto it = snapshots_.find(role);
	const auto *d = static_cast<const media_link_desc *>(arg);
	std::string source, sink;
	if (request != MEDIA_IOC_SETUP_LINK || it == snapshots_.end() ||
	    !entityLabel(it->second, d->source.entity, &source) || !entityLabel(it->second, d->sink.entity, &sink))
		return refuse("unlisted-effect");
	::book2lab::Effect e;
	e.kind = ::book2lab::Effect::Kind::Link;
	e.role = role;
	e.entity = source;
	e.pad = d->source.index;
	e.sink = sink;
	e.sink_pad = d->sink.index;
	e.flags = d->flags;
	return admitEffect(e);
}

Verdict Guard::finalCheck()
{
	std::lock_guard<std::mutex> lock(mutex_);
	if (!latched_.empty()) {
		refuse(latched_);
		return { false, latched_ };
	}
	if (!verdictWritten_) {
		const std::string line = "VERDICT admit\n";
		[[maybe_unused]] ssize_t n = ::write(kVerdictFd, line.data(), line.size());
		verdictWritten_ = true;
	}
	return {};
}

unsigned int Guard::frontPort() const
{
	return reservation_ ? suffix(reservation_->front.csi2) : 0;
}

unsigned int Guard::frontImgu() const
{
	return reservation_ ? suffix(reservation_->front.imgu) : 0;
}

Guard &guard()
{
	static Guard instance;
	return instance;
}

} /* namespace book2lab */

} /* namespace libcamera */
