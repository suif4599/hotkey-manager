#include "ipc/uds.h"
#include "config.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <chrono>
#include <fcntl.h>
#include <stdexcept>
#include <sys/socket.h>
#include <sys/stat.h>
#include <cstdlib>
#include <unistd.h>
#include <syslog.h>

using namespace hotkey_manager;

namespace hotkey_manager {

static void setNonBlocking(int socket_fd) {
    int flags = fcntl(socket_fd, F_GETFL, 0);
    if (flags == -1)
        throw std::runtime_error("Failed to get socket flags");
    if (fcntl(socket_fd, F_SETFL, flags | O_NONBLOCK) == -1)
        throw std::runtime_error("Failed to set socket to non-blocking");
}


ClientInfo::ClientInfo() {
    throw std::runtime_error("Default constructor not allowed");
}

ClientInfo::ClientInfo(int clientFd, const std::string& proc_info)
: fd(clientFd)
, processInfo(proc_info)
, buffer() {}

void ClientInfo::append(const std::string& data) {
    buffer += data;
}

std::string ClientInfo::getProcessInfo() const {
    return processInfo;
}

std::string* ClientInfo::getCommand() {
    // length of "[COMMAND]" = 9
    syslog(LOG_DEBUG, "Checking for command in buffer of clientFd=%d, buffer=%s", fd, buffer.c_str());
    size_t start = buffer.find("[COMMAND]");
    size_t end = buffer.find("[/COMMAND]");
    if (end < start) {
        // Delete invalid data before the next possible command
        buffer.erase(0, start);
        return nullptr;
    }
    if (start != std::string::npos && end != std::string::npos) {
        start += 9;
        std::string* command = new std::string(buffer.substr(start, end - start));
        buffer.erase(0, end + 10);
        return command;
    }
    return nullptr;
}

int ClientInfo::getFd() const {
    return fd;
}

std::ostream& operator<<(std::ostream& os, const ClientInfo& info) {
    os << "ClientInfo(fd = " << info.fd << ", processInfo = '" << info.processInfo << "')";
    return os;
}

UnixDomainSocket::UnixDomainSocket(const std::string& path) {
    syslog(LOG_INFO, "Creating UnixDomainSocket with path: %s", path.c_str());
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd == -1)
        throw std::runtime_error("Failed to create socket");

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);
}

UnixDomainSocketServer::UnixDomainSocketServer(const std::string& path)
: UnixDomainSocket(path)
, clientMapping()
, newClients()
, deletedClients() {
    syslog(LOG_INFO, "Creating UnixDomainSocketServer with path: %s", path.c_str());
    unlink(path.c_str()); // Remove existing socket file
    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        close(fd);
        throw std::runtime_error("Failed to bind socket");
    }

    if (listen(fd, BACK_LOG) == -1) {
        close(fd);
        throw std::runtime_error("Failed to listen on socket");
    }

    setNonBlocking(fd);
    if (chmod(path.c_str(), 0666) == -1) {
        close(fd);
        throw std::runtime_error("Failed to set socket permissions");
    }

    FD_ZERO(&master_fds);
    FD_SET(fd, &master_fds); // Only the listening socket for now
    max_fd = fd;
}

void UnixDomainSocketServer::next() {
    static char buffer[1024] = {0};
    syslog(LOG_DEBUG, "UnixDomainSocketServer waiting for events...");
    struct timeval timeout {0, 0};
    read_fds = master_fds;
    int ready = select(max_fd + 1, &read_fds, nullptr, nullptr, &timeout);
    if (ready == 0)
        return; // No events
    if (ready == -1) {
        if (errno == EINTR) {
            // Interrupt, the function should retry select, but mainloop will do it
            syslog(LOG_NOTICE, "Select interrupted by signal");
            return;
        }
        syslog(LOG_ERR, "Select error on socket: %s", strerror(errno));
        return;
    }

    for (int i = 0; i <= max_fd; ++i) {
        if (!FD_ISSET(i, &read_fds)) 
            continue;
        if (i == fd) { // New connection
            syslog(LOG_DEBUG, "New connection on listening socket");
            int new_fd = accept(fd, nullptr, nullptr);
            if (new_fd == -1) {
                if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                    continue; // No pending connections
                syslog(LOG_ERR, "Failed to accept new client connection: %s", strerror(errno));
                continue;
            }

            try {
                syslog(LOG_DEBUG, "Setting new client socket to non-blocking");
                setNonBlocking(new_fd);
            } catch (...) {
                close(new_fd);
                continue;
            }

            // Get cred
            struct ucred cred;
            socklen_t len = sizeof(cred);
            if (getsockopt(new_fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) == -1) {
                // Failed to get credentials, unable to authenticate
                syslog(LOG_WARNING, "Failed to get peer credentials for new client");
                close(new_fd);
                continue;
            }
            std::string proc_info = std::to_string(cred.pid) + ":" +
                                    std::to_string(cred.uid) + ":" +
                                    std::to_string(cred.gid);
            clientMapping.emplace(new_fd, ClientInfo(new_fd, proc_info));
            newClients.push_back(&clientMapping.at(new_fd));

            FD_SET(new_fd, &master_fds);
            if (new_fd > max_fd)
                max_fd = new_fd;
        } else { // New message from existing connection
            syslog(LOG_DEBUG, "Receiving data from clientFd=%d", i);
            ssize_t bytes_received = recv(i, buffer, sizeof(buffer) - 1, 0);
            if (bytes_received > 0) {
                buffer[bytes_received] = '\0';
                clientMapping[i].append(std::string(buffer, bytes_received));
            } else if (bytes_received == 0) {
                deleteClient(i);
                deletedClients.push(i);
            } else {
                if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                    continue;
                deleteClient(i);
                deletedClients.push(i);
            }
        }
    }
}
void UnixDomainSocketServer::deleteClient(int clientFd) {
    syslog(LOG_DEBUG, "Deleting clientFd=%d", clientFd);
    ClientInfo& client = clientMapping[clientFd];
    auto it = std::find(newClients.begin(), newClients.end(), &client);
    if (it != newClients.end()) {
        newClients.erase(it);
        syslog(LOG_NOTICE, "The deleted client was still in newClients queue, clientFd=%d", clientFd);
    }
    close(clientFd);
    FD_CLR(clientFd, &master_fds);
    clientMapping.erase(clientFd);
    if (clientFd == max_fd) {
        max_fd = fd;
        for (const auto& [fd_key, _] : clientMapping) {
            if (fd_key > max_fd)
                max_fd = fd_key;
        }
    }
}

void UnixDomainSocketServer::sendResponse(int clientFd, const std::string& response) {
    syslog(LOG_DEBUG, "Sending response to clientFd=%d: %s", clientFd, response.c_str());
    std::string wrapped_response = "[RESPONSE]" + response + "[/RESPONSE]";
    size_t total_sent = 0;
    while (total_sent < wrapped_response.size()) {
        ssize_t bytes_sent = send(clientFd, wrapped_response.c_str() + total_sent, wrapped_response.size() - total_sent, 0);
        if (bytes_sent > 0) {
            total_sent += static_cast<size_t>(bytes_sent);
            continue;
        }
        if (bytes_sent == -1 && errno == EINTR)
            continue;
        if (bytes_sent == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            fd_set write_fds;
            FD_ZERO(&write_fds);
            FD_SET(clientFd, &write_fds);
            if (select(clientFd + 1, nullptr, &write_fds, nullptr, nullptr) == -1) {
                if (errno == EINTR)
                    continue;
                syslog(LOG_WARNING, "Select error while sending response to clientFd=%d", clientFd);
                deleteClient(clientFd);
                deletedClients.push(clientFd);
                return;
            }
            continue;
        }
        syslog(LOG_WARNING, "Failed to send response to clientFd=%d, deleting client", clientFd);
        deleteClient(clientFd);
        deletedClients.push(clientFd);
        return;
    }
}

std::pair<int, std::string*> UnixDomainSocketServer::receiveCommand() {
    syslog(LOG_DEBUG, "Checking for commands from clients");
    for (auto& [clientFd, client_info] : clientMapping) {
        std::string* command = client_info.getCommand();
        if (command != nullptr)
            return {clientFd, command};
    }
    return {-1, nullptr};
}

ClientInfo* UnixDomainSocketServer::getNewClient() {
    if (newClients.empty())
        return nullptr;
    ClientInfo* client = newClients.front();
    newClients.erase(newClients.begin());
    return client;
}

int UnixDomainSocketServer::getDeletedClientFd() {
    if (deletedClients.empty())
        return -1;
    int clientFd = deletedClients.front();
    deletedClients.pop();
    return clientFd;
}

UnixDomainSocketClient::UnixDomainSocketClient(
    const std::string& path,
    int64_t timeoutMs
): UnixDomainSocket(path)
, buffer()
, timeoutMs(timeoutMs) {
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        close(fd);
        throw std::runtime_error("Failed to connect to server socket");
    }

    struct ucred cred;
    socklen_t len = sizeof(cred);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) == -1) {
        close(fd);
        throw std::runtime_error("Failed to get server credentials");
    }
    if (cred.uid != 0) {
        // Server socket must be owned by root
        close(fd);
        throw std::runtime_error("Server socket is tampered (not owned by root)");
    }
    setNonBlocking(fd);
}

std::string* UnixDomainSocketClient::sendCommand(const std::string& command) {
    std::string wrapped_command = "[COMMAND]" + command + "[/COMMAND]";
    size_t total_sent = 0;
    while (total_sent < wrapped_command.size()) {
        ssize_t bytes_sent = send(fd, wrapped_command.c_str() + total_sent, wrapped_command.size() - total_sent, 0);
        if (bytes_sent > 0) {
            total_sent += static_cast<size_t>(bytes_sent);
            continue;
        }
        if (bytes_sent == -1 && errno == EINTR)
            continue;
        if (bytes_sent == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            fd_set write_fds;
            FD_ZERO(&write_fds);
            FD_SET(fd, &write_fds);
            if (select(fd + 1, nullptr, &write_fds, nullptr, nullptr) == -1) {
                if (errno == EINTR)
                    continue;
                throw std::runtime_error("Select error while sending command to server");
            }
            continue;
        }
        throw std::runtime_error("Failed to send command to server");
    }

    int64_t expectedTime = getTimestampMs() + timeoutMs;
    while (getTimestampMs() < expectedTime) {
        std::string* response = receiveResponse();
        if (response != nullptr)
            return response;
        usleep(RECEIVER_CHECK_RESPONSE_INTERVAL_MS * 1000);
    }
    return nullptr;
}

std::string* UnixDomainSocketClient::receiveResponse() {
    static char temp_buffer[1024] = {0};
    while (true) {
        // length of "[RESPONSE]" = 10
        size_t start = buffer.find("[RESPONSE]");
        size_t end = buffer.find("[/RESPONSE]");
        if (end < start) {
            buffer.erase(0, start);
            return nullptr;
        }
        if (start != std::string::npos && end != std::string::npos) {
            start += 10;
            std::string* response = new std::string(buffer.substr(start, end - start));
            buffer.erase(0, end + 11);
            return response;
        }

        ssize_t bytes_received = recv(fd, temp_buffer, sizeof(temp_buffer) - 1, 0);
        if (bytes_received > 0) {
            buffer.append(temp_buffer, bytes_received);
            continue;
        }
        if (bytes_received == 0)
            throw std::runtime_error("Connection closed by server");
        if (bytes_received == -1) {
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return nullptr;
        }
        throw std::runtime_error("Failed to receive response from server");
    }
}

int64_t getTimestampMs() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()
    ).count();
}

} // namespace hotkey_manager
