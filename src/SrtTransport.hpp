#ifndef ZLMEDIAKIT_SRT_TRANSPORT_H
#define ZLMEDIAKIT_SRT_TRANSPORT_H

#include <mutex>

#include "Network/Session.h"
#include "Poller/EventPoller.h"
namespace SRT {
using namespace toolkit;
class SrtTransport {
public:
    using Ptr = std::shared_ptr<SrtTransport>;

    SrtTransport(const EventPoller::Ptr &poller);
    virtual ~SrtTransport() = default;
    const EventPoller::Ptr &getPoller() const;
    void setSession(Session::Ptr session);
    const Session::Ptr &getSession() const;
    /**
     * socket收到udp数据
     * @param buf 数据指针
     * @param len 数据长度
     * @param addr 数据来源地址
     */
    void inputSockData(uint8_t *buf, int len, struct sockaddr_storage *addr);

    std::string getIdentifier();
private:
    void handleHandshake(uint8_t *buf, int len, struct sockaddr_storage *addr);
    void handleKeeplive(uint8_t *buf, int len, struct sockaddr_storage *addr);
    void handleACK(uint8_t *buf, int len, struct sockaddr_storage *addr);
    void handleACKACK(uint8_t *buf, int len, struct sockaddr_storage *addr);
    void handleNAK(uint8_t *buf, int len, struct sockaddr_storage *addr);
    void handleCongestionWarning(uint8_t *buf, int len, struct sockaddr_storage *addr);
    void handleShutDown(uint8_t *buf, int len, struct sockaddr_storage *addr);
    void handleDropReq(uint8_t *buf, int len, struct sockaddr_storage *addr);
    void handleUserDefinedType(uint8_t *buf, int len, struct sockaddr_storage *addr);
    void handlePeerError(uint8_t *buf, int len, struct sockaddr_storage *addr);
private:
    //当前选中的udp链接
    Session::Ptr _selected_session;
    EventPoller::Ptr _poller;

    uint32_t _peer_socket_id;

};

class SrtTransportManager {
public:
    static SrtTransportManager &Instance();
    SrtTransport::Ptr getItem(const std::string &key);
    void addItem(const std::string &key, const SrtTransport::Ptr &ptr);
    void removeItem(const std::string &key);

    void addHandshakeItem(const std::string &key, const SrtTransport::Ptr &ptr);
    void removeHandshakeItem(const std::string &key);
    SrtTransport::Ptr getHandshakeItem(const std::string &key);
private:
    SrtTransportManager() = default;

private:
    std::mutex _mtx;
    std::unordered_map<std::string, std::weak_ptr<SrtTransport>> _map;

    std::mutex _handshake_mtx;
    std::unordered_map<std::string, std::weak_ptr<SrtTransport>> _handshake_map;
};

} // namespace SRT

#endif // ZLMEDIAKIT_SRT_TRANSPORT_H