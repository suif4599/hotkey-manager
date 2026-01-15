#ifndef IPC_UDS_H
#define IPC_UDS_H

#include <string>
#include <sys/un.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <map>
#include <queue>
#include <vector>
#include <iostream>
#include "ipc/event.h"

namespace hotkey_manager {

// Command structure:
// [COMMAND]comtent[/COMMAND]

// Response structure:
// [RESPONSE]content[/RESPONSE]

class ClientInfo {
    int fd;
    std::string processInfo;
    std::string buffer;
public:
    ClientInfo();
    ClientInfo(int clientFd, const std::string& proc_info);
    void append(const std::string& data);
    std::string getProcessInfo() const;
    std::string* getCommand();
    int getFd() const;

    friend std::ostream& operator<<(std::ostream& os, const ClientInfo& info);
};

class UnixDomainSocket {
protected:
    int fd;
    struct sockaddr_un addr;
    socklen_t addrLen;
    std::string socketName;
    std::string displayName;
public:
    explicit UnixDomainSocket(const std::string& name);
    virtual ~UnixDomainSocket();
    UnixDomainSocket(const UnixDomainSocket&) = delete;
    UnixDomainSocket& operator=(const UnixDomainSocket&) = delete;
    UnixDomainSocket(UnixDomainSocket&&) = delete;
    UnixDomainSocket& operator=(UnixDomainSocket&&) = delete;
};

class UnixDomainSocketServer : public UnixDomainSocket {
    std::map<int, ClientInfo> clientMapping;
    std::vector<ClientInfo*> newClients;
    std::queue<int> deletedClients;
    EventManager& eventManager;
public:
    explicit UnixDomainSocketServer(const std::string& name, const EventManager& eventManager);
    ~UnixDomainSocketServer() override;
    void next(struct epoll_event* events, int n);
    void deleteClient(int clientFd);
    void sendResponse(int clientFd, const std::string& response);
    std::pair<int, std::string*> receiveCommand();
    ClientInfo* getNewClient();
    int getDeletedClientFd();
};

class UnixDomainSocketClient : public UnixDomainSocket {
    std::string buffer;
    int64_t timeoutMs;
public:
    UnixDomainSocketClient(const std::string& name, int64_t timeoutMs = 5000);
    std::string* sendCommand(const std::string& command);
    std::string* receiveResponse();
};

int64_t getTimestampMs();

} // namespace hotkey_manager

#endif // IPC_UDS_H
