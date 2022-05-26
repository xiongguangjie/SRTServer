﻿#include "SrtSession.hpp"
#include "Packet.hpp"
#include "SrtTransport.hpp"

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
    uint8_t* data = (uint8_t*)buffer->data();
    size_t size = buffer->size();

    if(DataPacket::isDataPacket(data,size)){
        uint32_t socket_id = DataPacket::getSocketID(data,size);
        auto trans = SrtTransportManager::Instance().getItem(std::to_string(socket_id));
        return trans ? trans->getPoller() : nullptr;
    }

    if(HandshakePacket::isHandshakePacket(data,size)){
        auto type = HandshakePacket::getHandshakeType(data,size);
        if(type == HandshakePacket::HANDSHAKE_TYPE_INDUCTION){
            // 握手第一阶段
            return nullptr;
        }else if(type == HandshakePacket::HANDSHAKE_TYPE_CONCLUSION){
            // 握手第二阶段
            uint32_t sync_cookie = HandshakePacket::getSynCookie(data,size);
            auto trans = SrtTransportManager::Instance().getHandshakeItem(std::to_string(sync_cookie));
            return trans ? trans->getPoller() : nullptr;
        }else{
            WarnL<<" not reach there";
        }
    }else{
        uint32_t socket_id = ControlPacket::getSocketID(data,size);
        auto trans = SrtTransportManager::Instance().getItem(std::to_string(socket_id));
        return trans ? trans->getPoller() : nullptr;
    }
    return nullptr;
}

void SrtSession::onRecv(const Buffer::Ptr &buffer) {
    uint8_t* data = (uint8_t*)buffer->data();
    size_t size = buffer->size();

    if (_find_transport) {
        //只允许寻找一次transport
        _find_transport = false;

        if (DataPacket::isDataPacket(data, size)) {
            uint32_t socket_id = DataPacket::getSocketID(data, size);
            auto trans = SrtTransportManager::Instance().getItem(std::to_string(socket_id));
            if(trans){
                _transport = std::move(trans);
            }else{
                WarnL<<" data packet not find transport ";
            }
        }

        if (HandshakePacket::isHandshakePacket(data, size)) {
            auto type = HandshakePacket::getHandshakeType(data, size);
            if (type == HandshakePacket::HANDSHAKE_TYPE_INDUCTION) {
                // 握手第一阶段
                _transport = std::make_shared<SrtTransport>(getPoller());

            } else if (type == HandshakePacket::HANDSHAKE_TYPE_CONCLUSION) {
                // 握手第二阶段
                uint32_t sync_cookie = HandshakePacket::getSynCookie(data, size);
                auto trans = SrtTransportManager::Instance().getHandshakeItem(std::to_string(sync_cookie));
                if (trans) {
                    _transport = std::move(trans);
                } else {
                    WarnL << " hanshake packet not find transport ";
                }
            } else {
                WarnL << " not reach there";
            }
        } else {
            uint32_t socket_id = ControlPacket::getSocketID(data, size);
            auto trans = SrtTransportManager::Instance().getItem(std::to_string(socket_id));
            if(trans){
                _transport = std::move(trans);
            }else{
                WarnL << " not find transport";
            }
        }

        if(_transport){
            _transport->setSession(shared_from_this());
        }
        InfoP(this);
    }
    _ticker.resetTime();

    if(_transport){
        _transport->inputSockData(data,size,&_peer_addr);
    }else{
        WarnL<< "ingore  data";
    }
}

void SrtSession::onError(const SockException &err) {
    // udp链接超时，但是srt链接不一定超时，因为可能存在udp链接迁移的情况
    //在udp链接迁移时，新的SrtSession对象将接管SrtSession对象的生命周期
    //本SrtSession对象将在超时后自动销毁
    WarnP(this) << err.what();

    if (!_transport) {
        return;
    }
    
    // 防止互相引用导致不释放
    auto transport = std::move(_transport);
    getPoller()->async([transport] {
        //延时减引用，防止使用transport对象时，销毁对象
    }, false);
}

void SrtSession::onManager() {

    if (_ticker.elapsedTime() > 5 * 1000) {
        shutdown(SockException(Err_timeout, "srt connection timeout"));
        return;
    }
}

} // namespace SRT