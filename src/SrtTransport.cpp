#include "Util/onceToken.h"

#include "SrtTransport.hpp"
#include "Packet.hpp"
namespace SRT {

////////////  SrtTransport //////////////////////////
SrtTransport::SrtTransport(const EventPoller::Ptr &poller)
    : _poller(poller) {}

const EventPoller::Ptr &SrtTransport::getPoller() const {
    return _poller;
}

void SrtTransport::setSession(Session::Ptr session) {
    if (_selected_session) {
        InfoL << "srt network changed: " << _selected_session->get_peer_ip() << ":"
              << _selected_session->get_peer_port() << " -> " << session->get_peer_ip() << ":"
              << session->get_peer_port() << ", id:" << getIdentifier();
    }
    _selected_session = session;
}
const Session::Ptr &SrtTransport::getSession() const {
    return _selected_session;
}

const std::string &SrtTransport::getIdentifier() const {
    return _identifier;
}

void SrtTransport::inputSockData(uint8_t *buf, int len, struct sockaddr_storage *addr) {
     using srt_control_handler = void (SrtTransport::*)(uint8_t* buf,int len,struct sockaddr_storage *addr);
    static std::unordered_map<uint16_t, srt_control_handler> s_control_functions;
    static onceToken token([]() {
        s_control_functions.emplace(ControlPacket::HANDSHAKE, &SrtTransport::handleHandshake);
        s_control_functions.emplace(ControlPacket::KEEPALIVE, &SrtTransport::handleKeeplive);
        s_control_functions.emplace(ControlPacket::ACK, &SrtTransport::handleACK);
        s_control_functions.emplace(ControlPacket::NAK, &SrtTransport::handleNAK);
        s_control_functions.emplace(ControlPacket::CONGESTIONWARNING, &SrtTransport::handleCongestionWarning);
        s_control_functions.emplace(ControlPacket::SHUTDOWN, &SrtTransport::handleShutDown);
        s_control_functions.emplace(ControlPacket::ACKACK, &SrtTransport::handleACKACK);
        s_control_functions.emplace(ControlPacket::DROPREQ, &SrtTransport::handleDropReq);
        s_control_functions.emplace(ControlPacket::PEERERROR, &SrtTransport::handlePeerError);
        s_control_functions.emplace(ControlPacket::USERDEFINEDTYPE, &SrtTransport::handleUserDefinedType);
    });

    // 处理srt数据
    if (DataPacket::isDataPacket(buf, len)) {

    } else {
        if (ControlPacket::isControlPacket(buf, len)) {
            auto it = s_control_functions.find(ControlPacket::getControlType(buf,len));
            if (it == s_control_functions.end()) {
                WarnL<<" not support type ignore" << ControlPacket::getControlType(buf,len);
                return;
            }else{
                (this->*(it->second))(buf,len,addr);
            }
        } else {
            // not reach
            WarnL << "not reach this";
        }
    }
}
void SrtTransport::handleHandshake(uint8_t *buf, int len, struct sockaddr_storage *addr){

}
void SrtTransport::handleKeeplive(uint8_t *buf, int len, struct sockaddr_storage *addr){

}
void SrtTransport::handleACK(uint8_t *buf, int len, struct sockaddr_storage *addr){

}
void SrtTransport::handleNAK(uint8_t *buf, int len, struct sockaddr_storage *addr){

}
void SrtTransport::handleCongestionWarning(uint8_t *buf, int len, struct sockaddr_storage *addr){

}
void SrtTransport::handleShutDown(uint8_t *buf, int len, struct sockaddr_storage *addr){

}
void SrtTransport::handleDropReq(uint8_t *buf, int len, struct sockaddr_storage *addr){

}
void SrtTransport::handleUserDefinedType(uint8_t *buf, int len, struct sockaddr_storage *addr){

}

void SrtTransport::handleACKACK(uint8_t *buf, int len, struct sockaddr_storage *addr){

}

void SrtTransport::handlePeerError(uint8_t *buf, int len, struct sockaddr_storage *addr){

}
////////////  SrtTransportManager //////////////////////////
SrtTransportManager &SrtTransportManager::Instance() {
    static SrtTransportManager s_instance;
    return s_instance;
}

void SrtTransportManager::addItem(const std::string &key, const SrtTransport::Ptr &ptr) {
    std::lock_guard<std::mutex> lck(_mtx);
    _map[key] = ptr;
}

SrtTransport::Ptr SrtTransportManager::getItem(const std::string &key) {
    if (key.empty()) {
        return nullptr;
    }
    std::lock_guard<std::mutex> lck(_mtx);
    auto it = _map.find(key);
    if (it == _map.end()) {
        return nullptr;
    }
    return it->second.lock();
}

void SrtTransportManager::removeItem(const std::string &key) {
    std::lock_guard<std::mutex> lck(_mtx);
    _map.erase(key);
}

void SrtTransportManager::addHandshakeItem(const std::string &key, const SrtTransport::Ptr &ptr) {
    std::lock_guard<std::mutex> lck(_handshake_mtx);
    _handshake_map[key] = ptr;
}
void SrtTransportManager::removeHandshakeItem(const std::string &key) {
     std::lock_guard<std::mutex> lck(_handshake_mtx);
    _handshake_map.erase(key);
}
SrtTransport::Ptr SrtTransportManager::getHandshakeItem(const std::string &key) {
    if (key.empty()) {
        return nullptr;
    }
    std::lock_guard<std::mutex> lck(_handshake_mtx);
    auto it = _handshake_map.find(key);
    if (it == _handshake_map.end()) {
        return nullptr;
    }
    return it->second.lock();
}

} // namespace SRT