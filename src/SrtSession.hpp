﻿#ifndef ZLMEDIAKIT_SRT_SESSION_H
#define ZLMEDIAKIT_SRT_SESSION_H

#include "Network/Session.h"
namespace SRT{

using namespace toolkit;

class SrtSession : public UdpSession {
public:
    SrtSession(const Socket::Ptr &sock);
    ~SrtSession() override;

    void onRecv(const Buffer::Ptr &) override;
    void onError(const SockException &err) override;
    void onManager() override;
    std::string getIdentifier() const override;

    static EventPoller::Ptr queryPoller(const Buffer::Ptr &buffer);

private:
    std::string _identifier;
    bool _find_transport = true;
    Ticker _ticker;
    struct sockaddr_storage _peer_addr;
};

}
#endif ZLMEDIAKIT_SRT_SESSION_H