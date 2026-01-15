#include "ipc/event.h"
#include <stdexcept>
#include <cerrno>
#include <cstring>
#include <syslog.h>
#include <unistd.h>

using namespace hotkey_manager;

EventManager::EventManager() {
    epollFd = epoll_create1(0);
    if (epollFd == -1) {
        syslog(LOG_ERR, "Failed to create epoll instance: %s", std::strerror(errno));
        throw std::runtime_error("Failed to create epoll instance: " + std::string(std::strerror(errno)));
    }
}

EventManager::~EventManager() {
    close(epollFd);
}

void EventManager::addFd(int fd, uint32_t events) const {
    struct epoll_event ev;
    std::memset(&ev, 0, sizeof(ev));
    ev.events = events;
    ev.data.fd = fd;
    if (epoll_ctl(epollFd, EPOLL_CTL_ADD, fd, &ev) == -1) {
        syslog(LOG_WARNING, "Failed to add fd to epoll: %s", std::strerror(errno));
        throw std::runtime_error("Failed to add fd to epoll: " + std::string(std::strerror(errno)));
    }
}

void EventManager::deleteFd(int fd) const {
    if (epoll_ctl(epollFd, EPOLL_CTL_DEL, fd, nullptr) == -1) {
        syslog(LOG_WARNING, "Failed to delete fd from epoll: %s", std::strerror(errno));
        throw std::runtime_error("Failed to delete fd from epoll: " + std::string(std::strerror(errno)));
    }
}

std::pair<struct epoll_event*, int> EventManager::wait(int timeoutMs) {
    int n = epoll_wait(epollFd, events, maxEvents, timeoutMs);
    if (n == -1) {
        if (errno == EINTR) {
            return {events, 0}; // Interrupted by signal, not an error
        }
        syslog(LOG_WARNING, "Failed to wait on epoll: %s", std::strerror(errno));
        throw std::runtime_error("Failed to wait on epoll: " + std::string(std::strerror(errno)));
    }
    return {events, n}; // Return 0 for timeout
}