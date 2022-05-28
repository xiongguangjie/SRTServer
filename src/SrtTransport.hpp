#ifndef ZLMEDIAKIT_SRT_TRANSPORT_H
#define ZLMEDIAKIT_SRT_TRANSPORT_H

#include <mutex>
#include <chrono>

#include "Network/Session.h"
#include "Poller/EventPoller.h"

#include "Common.h"
#include "Packet.hpp"

namespace SRT {
using namespace toolkit;

class SrtTransport {
public:
    using Ptr = std::shared_ptr<SrtTransport>;

    SrtTransport(const EventPoller::Ptr &poller);
    virtual ~SrtTransport();
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
    void handleDataPacket(uint8_t *buf, int len, struct sockaddr_storage *addr);
protected:
    void sendDataPacket(DataPacket::Ptr pkt,char* buf,int len,bool flush = false);
    void sendControlPacket(ControlPacket::Ptr pkt,bool  flush = true);
    void sendPacket(Buffer::Ptr pkt,bool flush =  true);
private:
    //当前选中的udp链接
    Session::Ptr _selected_session;
    EventPoller::Ptr _poller;

    uint32_t _peer_socket_id;
    uint32_t _socket_id;

    TimePoint _start_timestamp;

    uint32_t _mtu = 1500;
    uint32_t _max_window_size = 8192;
    uint32_t  _init_seq_number = 0;

    //保持发送的握手消息，防止丢失重发
    HandshakePacket::Ptr _handleshake_res;

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