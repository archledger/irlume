/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Book 2 lab guard for the private lab build of libcamera v0.8.0 (guest only).
 * Every device open and ioctl passes through it. It loads the supervisor's
 * reservation once, checks the reserved graph before any discovery effect,
 * admits only listed effects and latches refusal or hold. Without a valid
 * reservation it refuses everything.
 */
#pragma once

#include <map>
#include <mutex>
#include <optional>
#include <cstdint>
#include <string>

#include "lab_contract.h"

namespace libcamera {

class MediaDevice;

namespace book2lab {

using ::book2lab::Node;
using ::book2lab::Verdict;

class Guard
{
public:
	Guard();

	Verdict admitDiscovery(MediaDevice &cio2, MediaDevice &imgu);
	int admitOpen(const std::string &path, int flags, const Node **node);
	int admitIoctl(const Node *node, unsigned long request, void *arg);
	int admitMediaIoctl(const MediaDevice &media, unsigned long request, void *arg);
	Verdict finalCheck();
	void settle();
	int admitIpaRoute(const std::string &path, const char *requested, const char *name,
			  uint32_t pipelineVersion, bool signatureValid);
	int refuseFor(const std::string &reason);

	unsigned int frontPort() const;
	unsigned int frontImgu() const;

private:
	int refuse(const std::string &reason, bool hold = false);
	int admitEffect(const ::book2lab::Effect &effect);
	Verdict recheckLocked();

	std::mutex mutex_;
	std::optional<::book2lab::Reservation> reservation_;
	::book2lab::EffectLedger ledger_;
	std::map<std::string, ::book2lab::Snapshot> snapshots_;
	std::map<std::string, int> mediaFds_;
	bool pendingSettle_ = false;
	std::string latched_;
	bool verdictWritten_ = false;
};

Guard &guard();

} /* namespace book2lab */

} /* namespace libcamera */
