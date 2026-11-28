#include <cstdio>
#include <span>
#include <type_traits>
#include <utility>

#include <libcamera/camera.h>
#include <libcamera/camera_manager.h>
#include <libcamera/framebuffer.h>
#include <libcamera/framebuffer_allocator.h>
#include <libcamera/request.h>
#include <libcamera/stream.h>

namespace lc = libcamera;

#ifdef CHECK_MANAGER_STOP_STATUS
using ManagerStop = int (lc::CameraManager::*)();
#else
using ManagerStop = void (lc::CameraManager::*)();
#endif

static_assert(std::is_same_v<decltype(&lc::CameraManager::start), int (lc::CameraManager::*)()>);
static_assert(std::is_same_v<decltype(&lc::CameraManager::stop), ManagerStop>, "manager stop is void");
static_assert(std::is_same_v<decltype(&lc::Camera::acquire), int (lc::Camera::*)()>);
static_assert(std::is_same_v<decltype(&lc::Camera::release), int (lc::Camera::*)()>);
static_assert(std::is_same_v<decltype(&lc::Camera::stop), int (lc::Camera::*)()>);
static_assert(std::is_same_v<decltype(&lc::Camera::configure),
                             int (lc::Camera::*)(lc::CameraConfiguration *)>);
static_assert(std::is_same_v<decltype(&lc::Camera::start), int (lc::Camera::*)(const lc::ControlList *)>);
static_assert(std::is_same_v<decltype(&lc::Camera::queueRequest), int (lc::Camera::*)(lc::Request *)>);
static_assert(std::is_same_v<decltype(&lc::FrameBufferAllocator::free), int (lc::FrameBufferAllocator::*)(lc::Stream *)>);
static_assert(std::is_same_v<decltype(std::declval<const lc::FrameBuffer &>().planes()),
                             std::span<const lc::FrameBuffer::Plane>>);
static_assert(std::is_same_v<decltype(std::declval<const lc::FrameBuffer &>().metadata()),
                             const lc::FrameMetadata &>);
static_assert(std::is_same_v<decltype(lc::FrameBuffer::Plane::fd), lc::SharedFD>);
static_assert(std::is_same_v<decltype(lc::FrameBuffer::Plane::offset), unsigned int>);
static_assert(std::is_same_v<decltype(lc::FrameBuffer::Plane::length), unsigned int>);
static_assert(std::is_same_v<decltype(lc::FrameMetadata::Plane::bytesused), unsigned int>);

namespace {
auto volatile manager_start = &lc::CameraManager::start;
auto volatile manager_stop = &lc::CameraManager::stop;
auto volatile camera_acquire = &lc::Camera::acquire;
auto volatile camera_release = &lc::Camera::release;
auto volatile camera_configure = &lc::Camera::configure;
auto volatile camera_start = &lc::Camera::start;
auto volatile camera_stop = &lc::Camera::stop;
auto volatile camera_queue = &lc::Camera::queueRequest;
auto volatile allocator_free = &lc::FrameBufferAllocator::free;
}

int main()
{
    if (!manager_start || !manager_stop || !camera_acquire || !camera_release ||
        !camera_configure || !camera_start || !camera_stop || !camera_queue || !allocator_free)
        return 1;

    if (lc::CameraManager::version() != "v0.8.0")
        return 1;
    return std::puts("libcamera link witness: 0.8.0") < 0;
}
