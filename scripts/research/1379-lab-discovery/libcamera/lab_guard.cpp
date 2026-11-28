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

#include <gnutls/crypto.h>

#include "libcamera/internal/media_device.h"

#include "discovery_requests.h"

extern char **environ;

namespace libcamera {

namespace book2lab {

namespace {

constexpr const char *kReservationPath = "/run/book2-lab/reservation";
constexpr int kVerdictFd = 3;

/* The system files libcamera's global configuration reads, from its own config.h. */
const std::vector<std::string> kConfigFiles = {
	LIBCAMERA_SYSCONF_DIR "/configuration.yaml",
	LIBCAMERA_DATA_DIR "/configuration.yaml",
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

/* Every registered media device; false if any media entry cannot be read. */
bool sysfsMedia(std::vector<std::pair<unsigned, unsigned>> *devices)
{
	auto listed = ::book2lab::list_media_devices("/sys/bus/media/devices");
	if (!listed)
		return false;
	*devices = std::move(*listed);
	return true;
}

unsigned int suffix(const std::string &name)
{
	size_t at = name.rfind('_');
	return at == std::string::npos ? 0 : static_cast<unsigned int>(std::stoul(name.substr(at + 1)));
}

bool kernfsInode(unsigned major, unsigned minor, uint64_t *inode)
{
	struct stat st {};
	const std::string path = "/sys/dev/char/" + std::to_string(major) + ":" + std::to_string(minor);
	if (stat(path.c_str(), &st) != 0)
		return false;
	*inode = st.st_ino;
	return true;
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

/* Reread the media set, both topologies and every bound kernfs inode. */
Verdict Guard::recheckLocked()
{
	std::vector<std::pair<unsigned, unsigned>> present;
	if (!sysfsMedia(&present))
		return { false, "media-set" };
	Verdict v = ::book2lab::check_media_set(*reservation_, present);
	if (!v.ok)
		return v;
	for (const auto &[role, fd] : mediaFds_) {
		::book2lab::Snapshot s;
		if (::book2lab::read_snapshot(fd, &s) != 0)
			return { false, "snapshot" };
		v = ::book2lab::compare_graph(*reservation_, role == "cio2" ? ::book2lab::Role::Cio2 : ::book2lab::Role::Imgu,
					      s, ledger_);
		if (!v.ok)
			return v;
	}
	for (const Node &n : reservation_->nodes) {
		uint64_t inode = 0;
		if (!kernfsInode(n.major, n.minor, &inode) || inode != n.inode)
			return { false, "identity" };
	}
	return {};
}

/* A change before the effect refuses it; settle() turns a change after it into a hold. */
int Guard::admitEffect(const ::book2lab::Effect &effect)
{
	/* No effect before admitDiscovery has checked both graphs and kept their descriptors. */
	if (mediaFds_.size() != 2)
		return refuse("discovery");
	/* One effect at a time: each admitted effect gets its own recheck before the next. */
	if (settle_.pending())
		return refuse("overlapping-effect");
	Verdict v = recheckLocked();
	if (!v.ok)
		return refuse(v.reason);
	v = ::book2lab::match_effect(*reservation_, effect, &ledger_);
	if (!v.ok)
		return refuse(v.reason + " " + ::book2lab::format_effect(effect));
	settle_.admit(std::this_thread::get_id());
	return 0;
}

void Guard::settle()
{
	std::lock_guard<std::mutex> lock(mutex_);
	if (!settle_.settle(std::this_thread::get_id()))
		return;
	Verdict v = recheckLocked();
	if (!v.ok)
		refuse(v.reason, true);
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
	std::vector<std::pair<unsigned, unsigned>> present;
	if (v.ok && !sysfsMedia(&present))
		v = { false, "media-set" };
	if (v.ok)
		v = ::book2lab::check_media_set(*reservation_, present);
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
		mediaFds_[::book2lab::role_name(role)] = device->labFd();
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
	/*
	 * Bracket the open with the registration's kernfs inode, unique within
	 * a boot: equal before and after means the descriptor names the
	 * reserved object, even if a replacement reused the device number.
	 */
	uint64_t before = 0, after = 0;
	if (!kernfsInode(match->major, match->minor, &before) || before != match->inode)
		return refuse("identity");
	int fd = ::open(path.c_str(), flags | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	struct stat st {};
	if (fstat(fd, &st) != 0 || !S_ISCHR(st.st_mode) || st.st_rdev != makedev(match->major, match->minor) ||
	    !kernfsInode(match->major, match->minor, &after) || after != match->inode) {
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
	if (!latched_.empty())
		return refuse(latched_);
	/* TRY formats and stale or empty control sets are refused like any unlisted effect. */
	const ::book2lab::RequestEffect requested = ::book2lab::subdev_request_effect(request, arg, node->entity);
	if (!requested.verdict.ok)
		return refuse(requested.verdict.reason);
	return admitEffect(*requested.effect);
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

/*
 * The threaded route only: signature valid, contract identity, the bound
 * file identity and the SHA-256 of the module bytes. Decided before any proxy.
 */
int Guard::admitIpaRoute(const std::string &path, const char *requested, const char *name,
			 uint32_t pipelineVersion, bool signatureValid)
{
	std::lock_guard<std::mutex> lock(mutex_);
	if (!latched_.empty())
		return refuse(latched_);
	Verdict v = ::book2lab::check_environment(environ, kConfigFiles);
	if (!v.ok)
		return refuse(v.reason);
	if (!signatureValid)
		return refuse("ipa-signature");
	const ::book2lab::Ipa &ipa = reservation_->ipa;
	const ::book2lab::BindIpa &bind = *reservation_->bind_ipa;
	if (path != ipa.path || path != bind.path || ipa.pipeline != requested || ipa.name != name ||
	    ipa.version != pipelineVersion)
		return refuse("ipa-identity");
	struct stat st {};
	std::string bytes;
	unsigned char digest[32];
	if (stat(path.c_str(), &st) != 0 || static_cast<uint64_t>(st.st_dev) != bind.dev ||
	    static_cast<uint64_t>(st.st_ino) != bind.inode || static_cast<uint64_t>(st.st_size) != bind.size ||
	    !readAll(path.c_str(), &bytes) ||
	    gnutls_hash_fast(GNUTLS_DIG_SHA256, bytes.data(), bytes.size(), digest) != 0)
		return refuse("ipa-identity");
	static const char hexdigits[] = "0123456789abcdef";
	std::string hex;
	for (unsigned char b : digest) {
		hex += hexdigits[b >> 4];
		hex += hexdigits[b & 15];
	}
	if (hex != bind.sha256)
		return refuse("ipa-identity");
	return 0;
}

int Guard::refuseFor(const std::string &reason)
{
	std::lock_guard<std::mutex> lock(mutex_);
	return refuse(reason);
}

Verdict Guard::finalCheck()
{
	std::lock_guard<std::mutex> lock(mutex_);
	if (!latched_.empty()) {
		refuse(latched_);
		return { false, latched_ };
	}
	Verdict v = recheckLocked();
	if (!v.ok) {
		refuse(v.reason, true);
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
