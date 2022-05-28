#include "Util/onceToken.h"

#include "SrtTransport.hpp"
#include "Packet.hpp"
namespace SRT {
static std::atomic<uint32_t> s_srt_socket_id_generate{125};
////////////  SrtTransport //////////////////////////
SrtTransport::SrtTransport(const EventPoller::Ptr &poller)
    : _poller(poller) {
        _start_timestamp = SteadyClock::now();
        _socket_id = s_srt_socket_id_generate.fetch_add(1);
    }

SrtTransport::~SrtTransport(){
    TraceL<<" ";
}
const EventPoller::Ptr &SrtTransport::getPoller() const {
    return _poller;
}

void SrtTransport::setSession(Session::Ptr session) {
    if (_selected_session) {
        InfoL << "srt network changed: " << _selected_session->get_peer_ip() << ":"
              << _selected_session->get_peer_port() << " -> " << session->get_peer_ip() << ":"
              << session->get_peer_port() << ", id:" << _selected_session->getIdentifier();
    }
    _selected_session = session;
}
const Session::Ptr &SrtTransport::getSession() const {
    return _selected_session;
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
        handleDataPacket(buf,len,addr);
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
    HandshakePacket pkt;
    assert(pkt.loadFromData(buf,len));

    if(pkt.version == 4 && pkt.handshake_type == HandshakePacket::HS_TYPE_INDUCTION){
        // Induction Phase
        TraceL<<getIdentifier() <<" Induction Phase ";
        if(_handleshake_res){
            TraceL<<getIdentifier()<<" Induction handle repeate ";
            sendControlPacket(_handleshake_res,true);
            return;
        }
        _init_seq_number = pkt.initial_packet_sequence_number;
        _max_window_size = pkt.max_flow_window_size;
        _mtu = pkt.mtu;

        _peer_socket_id = pkt.srt_socket_id;
        HandshakePacket::Ptr res = std::make_shared<HandshakePacket>();
        res->dst_socket_id = _peer_socket_id;
        res->timestamp = DurationCountMicroseconds(_start_timestamp.time_since_epoch());
        res->mtu = _mtu;
        res->max_flow_window_size = _max_window_size;
        res->initial_packet_sequence_number = _init_seq_number;
        res->version = 5;
        res->encryption_field = HandshakePacket::NO_ENCRYPTION;
        res->extension_field = 0x4A17;
        res->handshake_type = HandshakePacket::HS_TYPE_INDUCTION;
        res->srt_socket_id = _peer_socket_id;
        res->syn_cookie = HandshakePacket::generateSynCookie(addr,_start_timestamp);
        //res->assignPeerIP(addr);
        memcpy(res->peer_ip_addr,pkt.peer_ip_addr,sizeof(pkt.peer_ip_addr)*sizeof(pkt.peer_ip_addr[0]));

        _handleshake_res = res;
        res->storeToData();
        sendControlPacket(res,true);

    }else if(pkt.version == 5 && pkt.handshake_type == HandshakePacket::HS_TYPE_CONCLUSION && _handleshake_res){
        // CONCLUSION Phase
        if(_handleshake_res->handshake_type == HandshakePacket::HS_TYPE_INDUCTION){
            // first
            HSExtMessage::Ptr req;
            for (auto ext : pkt.ext_list) {
                TraceL << getIdentifier() << " ext " << ext->dump();
                if (!req) {
                    req = std::dynamic_pointer_cast<HSExtMessage>(ext);
                }
            }

            TraceL<<getIdentifier() <<" CONCLUSION Phase ";
            HandshakePacket::Ptr res = std::make_shared<HandshakePacket>();
            res->dst_socket_id = _peer_socket_id;
            res->timestamp = DurationCountMicroseconds(SteadyClock::now() - _start_timestamp);
            res->mtu = _mtu;
            res->max_flow_window_size = _max_window_size;
            res->initial_packet_sequence_number = _init_seq_number;
            res->version = 5;
            res->encryption_field = HandshakePacket::NO_ENCRYPTION;
            res->extension_field = HandshakePacket::HS_EXT_FILED_HSREQ;
            res->handshake_type = HandshakePacket::HS_TYPE_CONCLUSION;
            res->srt_socket_id = _socket_id;
            res->syn_cookie = 0;
            res->assignPeerIP(addr);
            HSExtMessage::Ptr ext =  std::make_shared<HSExtMessage>();
            ext->extension_type = HSExt::SRT_CMD_HSRSP;
            ext->srt_version = 0x010500;
            ext->srt_flag = req->srt_flag;
            ext->recv_tsbpd_delay = ext->send_tsbpd_delay = req->recv_tsbpd_delay;
            res->ext_list.push_back(std::move(ext));
            res->storeToData();
            _handleshake_res = res;
            sendControlPacket(res, true);
        }else{
            TraceL<<getIdentifier()<<" CONCLUSION handle repeate ";
            sendControlPacket(_handleshake_res,true);
        }
    }
}
void SrtTransport::handleKeeplive(uint8_t *buf, int len, struct sockaddr_storage *addr){
    TraceL;
}
void SrtTransport::handleACK(uint8_t *buf, int len, struct sockaddr_storage *addr){
    TraceL;
}
void SrtTransport::handleNAK(uint8_t *buf, int len, struct sockaddr_storage *addr){
    TraceL;
}
void SrtTransport::handleCongestionWarning(uint8_t *buf, int len, struct sockaddr_storage *addr){
    TraceL;
}
void SrtTransport::handleShutDown(uint8_t *buf, int len, struct sockaddr_storage *addr){
    TraceL;
}
void SrtTransport::handleDropReq(uint8_t *buf, int len, struct sockaddr_storage *addr){
    TraceL;
}
void SrtTransport::handleUserDefinedType(uint8_t *buf, int len, struct sockaddr_storage *addr){
    TraceL;
}

void SrtTransport::handleACKACK(uint8_t *buf, int len, struct sockaddr_storage *addr){
    TraceL;
}

void SrtTransport::handlePeerError(uint8_t *buf, int len, struct sockaddr_storage *addr){
    TraceL;
}

void SrtTransport::handleDataPacket(uint8_t *buf, int len, struct sockaddr_storage *addr){
    DataPacket::Ptr pkt = std::make_shared<DataPacket>();
    pkt->loadFromData(buf,len);
    TraceL<<" seq="<< (uint32_t)pkt->packet_seq_number<<" ts="<<pkt->timestamp<<" size="<<pkt->payloadSize();
}

void SrtTransport::sendDataPacket(DataPacket::Ptr pkt,char* buf,int len, bool flush) { 
    pkt->storeToData((uint8_t*)buf,len);
    sendPacket(pkt,flush);
}
void SrtTransport::sendControlPacket(ControlPacket::Ptr pkt, bool flush) { 
    sendPacket(pkt,flush);
}
void SrtTransport::sendPacket(Buffer::Ptr pkt,bool flush){
    if(_selected_session){
         BufferRaw::Ptr tmp = BufferRaw::create();
         tmp->assign(pkt->data(),pkt->size());
         _selected_session->setSendFlushFlag(flush);
         _selected_session->send(tmp);
    }else{
        WarnL<<"not reach this";
    }
}
std::string SrtTransport::getIdentifier(){
    return _selected_session ? _selected_session->getIdentifier() : "";
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