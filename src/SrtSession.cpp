#include "SrtSession.hpp"
namespace SRT {

SrtSession::SrtSession(const Socket::Ptr &sock)
    : UdpSession(sock) {
    socklen_t addr_len = sizeof(_peer_addr);
    getpeername(sock->rawFD(), (struct sockaddr *)&_peer_addr, &addr_len);
}

SrtSession::~SrtSession() {
    InfoP(this);
}

EventPoller::Ptr SrtSession::queryPoller(const Buffer::Ptr &buffer) {
   
   return nullptr;
}

void SrtSession::onRecv(const Buffer::Ptr &buffer) {
    if (_find_transport) {
        //只允许寻找一次transport
        _find_transport = false;
       
        InfoP(this);
    }
    _ticker.resetTime();
    // TODO 解析srt的包并且处理

}

void SrtSession::onError(const SockException &err) {
    //udp链接超时，但是srt链接不一定超时，因为可能存在udp链接迁移的情况
    //在udp链接迁移时，新的SrtSession对象将接管SrtSession对象的生命周期
    //本SrtSession对象将在超时后自动销毁
    WarnP(this) << err.what();

}

void SrtSession::onManager() {

    if (_ticker.elapsedTime() > 5 * 1000) {
        shutdown(SockException(Err_timeout, "webrtc connection timeout"));
        return;
    }
}

std::string SrtSession::getIdentifier() const {
    return _identifier;
}

} // namespace SRT