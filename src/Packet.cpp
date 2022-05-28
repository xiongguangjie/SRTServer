﻿
#include "sys/socket.h"
#include "netdb.h"

#include <atomic>
#include "Util/logger.h"
#include "Util/MD5.h"

#include "Packet.hpp"



namespace SRT {


const size_t DataPacket::HEADER_SIZE;
const size_t ControlPacket::HEADER_SIZE;
const size_t HandshakePacket::HS_CONTENT_MIN_SIZE;

bool DataPacket::isDataPacket(uint8_t *buf, size_t len) {
    if (len < HEADER_SIZE) {
        WarnL << "data size" << len << " less " << HEADER_SIZE;
        return false;
    }
    if (!(buf[0] & 0x80)) {
        return true;
    }
    return false;
}

uint32_t DataPacket::getSocketID(uint8_t *buf, size_t len){
    uint8_t *ptr = buf;
    ptr += 12;
    return loadUint32(ptr);
}

bool DataPacket::loadFromData(uint8_t *buf, size_t len) {
    if (len < HEADER_SIZE) {
        WarnL << "data size" << len << " less " << HEADER_SIZE;
        return false;
    }
    uint8_t *ptr = buf;
    f = ptr[0] >> 7;
    packet_seq_number = (ptr[0] & 0x7f) << 24 | ptr[1] << 12 | ptr[2] << 8 | ptr[3];
    ptr += 4;

    PP = ptr[0] >> 6;
    O = (ptr[0] & 0x20) >> 5;
    KK = (ptr[0] & 0x18) >> 3;
    R = (ptr[0] & 0x04) >> 2;
    msg_number = (ptr[0] & 0x03) << 24 | ptr[1] << 12 | ptr[2] << 8 | ptr[3];
    ptr += 4;

    timestamp = loadUint32(ptr);
    ptr += 4;

    dst_socket_id = loadUint32(ptr);
    ptr += 4;

    _data = BufferRaw::create();
    _data->assign((char *)(buf), len);
    return true;
}

bool DataPacket::storeToData(uint8_t *buf, size_t len) {
    _data = BufferRaw::create();
    _data->setCapacity(len + HEADER_SIZE);
    _data->setSize(len + HEADER_SIZE);

    uint8_t *ptr = (uint8_t *)_data->data();

    ptr[0] = packet_seq_number >> 24;
    ptr[1] = (packet_seq_number >> 16) & 0xff;
    ptr[2] = (packet_seq_number >> 8) & 0xff;
    ptr[3] = packet_seq_number & 0xff;
    ptr += 4;

    ptr[0] = PP << 6;
    ptr[0] |= O << 5;
    ptr[0] |= KK << 3;
    ptr[0] |= R << 2;
    ptr[0] |= (msg_number & 0xff000000) >> 24;
    ptr[1] = (msg_number & 0xff0000) >> 16;
    ptr[2] = (msg_number & 0xff00) >> 8;
    ptr[3] = msg_number & 0xff;
    ptr += 4;

    storeUint32(ptr, timestamp);
    ptr += 4;

    storeUint32(ptr, dst_socket_id);
    ptr += 4;

    memcpy(ptr, buf, len);
    return true;
}

char *DataPacket::data() const {
    if (!_data)
        return nullptr;
    return _data->data();
}
size_t DataPacket::size() const {
    if (!_data) {
        return 0;
    }
    return _data->size();
}

char *DataPacket::payloadData() {
    if (!_data)
        return nullptr;
    return _data->data() + HEADER_SIZE;
}
size_t DataPacket::payloadSize() {
    if (!_data) {
        return 0;
    }
    return _data->size() - HEADER_SIZE;
}



bool ControlPacket::isControlPacket(uint8_t *buf, size_t len) {
    if (len < HEADER_SIZE) {
        WarnL << "data size" << len << " less " << HEADER_SIZE;
        return false;
    }
    if (buf[0] & 0x80) {
        return true;
    }
    return false;
}

uint16_t ControlPacket::getControlType(uint8_t *buf, size_t len) {
    uint8_t *ptr = buf;
    uint16_t control_type = (ptr[0] & 0x7f) << 8 | ptr[1];
    return control_type;
}

bool ControlPacket::loadHeader() {
    uint8_t *ptr = (uint8_t *)_data->data();
    f = ptr[0] >> 7;
    control_type = (ptr[0] & 0x7f) << 8 | ptr[1];
    ptr += 2;

    sub_type = loadUint16(ptr);
    ptr += 2;

    type_specific_info[0] = ptr[0];
    type_specific_info[1] = ptr[1];
    type_specific_info[2] = ptr[2];
    type_specific_info[3] = ptr[3];
    ptr += 4;

    timestamp = loadUint32(ptr);
    ptr += 4;

    dst_socket_id = loadUint32(ptr);
    ptr += 4;
    return true;
}
bool ControlPacket::storeToHeader() {
    uint8_t *ptr = (uint8_t *)_data->data();
    ptr[0] = 0x80;
    ptr[0] |= control_type >> 8;
    ptr[1] = control_type & 0xff;
    ptr += 2;

    storeUint16(ptr, sub_type);
    ptr += 2;

    ptr[0] = type_specific_info[0];
    ptr[1] = type_specific_info[1];
    ptr[2] = type_specific_info[2];
    ptr[3] = type_specific_info[3];
    ptr += 4;

    storeUint32(ptr, timestamp);
    ptr += 4;

    storeUint32(ptr, dst_socket_id);
    ptr += 4;
    return true;
}

char *ControlPacket::data() const {
    if (!_data)
        return nullptr;
    return _data->data();
}
size_t ControlPacket::size() const {
    if (!_data) {
        return 0;
    }
    return _data->size();
}
uint32_t ControlPacket::getSocketID(uint8_t *buf, size_t len){
    return loadUint32(buf+12);
}
bool HandshakePacket::loadFromData(uint8_t *buf, size_t len) {
    if(HEADER_SIZE+HS_CONTENT_MIN_SIZE > len){
        ErrorL << "size too smalle " << encryption_field;
        return false;
    }
    _data = BufferRaw::create();
    _data->assign((char *)(buf), len);
    ControlPacket::loadHeader();

    uint8_t *ptr = (uint8_t *)_data->data() + HEADER_SIZE;
    // parse CIF
    version = loadUint32(ptr);
    ptr += 4;

    encryption_field = loadUint16(ptr);
    ptr += 2;

    extension_field = loadUint16(ptr);
    ptr += 2;

    initial_packet_sequence_number = loadUint32(ptr);
    ptr += 4;

    mtu = loadUint32(ptr);
    ptr += 4;

    max_flow_window_size = loadUint32(ptr);
    ptr += 4;

    handshake_type = loadUint32(ptr);
    ptr += 4;

    srt_socket_id = loadUint32(ptr);
    ptr += 4;

    syn_cookie = loadUint32(ptr);
    ptr += 4;

    memcpy(peer_ip_addr, ptr, sizeof(peer_ip_addr) * sizeof(peer_ip_addr[0]));
    ptr += sizeof(peer_ip_addr) * sizeof(peer_ip_addr[0]);

    if (encryption_field != NO_ENCRYPTION) {
        ErrorL << "not support encryption " << encryption_field;
    }

    if(extension_field == 0){
        return true;
    }

    if(len ==  HEADER_SIZE+HS_CONTENT_MIN_SIZE){
        //ErrorL << "extension filed not exist " << extension_field;
        return true;
    }

    return loadExtMessage(ptr,len-HS_CONTENT_MIN_SIZE-HEADER_SIZE);
}
bool HandshakePacket::loadExtMessage(uint8_t *buf,size_t len){
   uint8_t* ptr = buf;
   ext_list.clear();
   uint16_t type;
   uint16_t length;
   HSExt::Ptr ext;
   while(ptr<buf+len){
       type = loadUint16(ptr);
       length = loadUint16(ptr+2);
       switch (type)
       {
       case HSExt::SRT_CMD_HSREQ:
       case HSExt::SRT_CMD_HSRSP:
            ext = std::make_shared<HSExtMessage>();
            break;
        case HSExt::SRT_CMD_SID:
            ext = std::make_shared<HSExtStreamID>();
            break;
        default:
            WarnL<<"not support ext "<<type;
            break;
       }
       if(ext){
           if(ext->loadFromData(ptr,length*4+4)){
               ext_list.push_back(std::move(ext));
           }else{
               WarnL<<"parse HS EXT failed type="<<type<<" len="<<length;
           }
           ext = nullptr;
       }

       ptr += length*4+4;
   }
   return true;
}

bool HandshakePacket::storeExtMessage()
{
       uint8_t* buf = (uint8_t*)_data->data()+HEADER_SIZE+48;
       size_t len = _data->size()- HEADER_SIZE-48;
       for(auto ex : ext_list){
           memcpy(buf,ex->data(),ex->size());
           buf += ex->size();
       }
       return true;
}

 size_t HandshakePacket::getExtSize(){
     size_t size = 0;
     for(auto it : ext_list){
         size += it->size();
     }
     return size;
 }
bool HandshakePacket::storeToData() {
    _data = BufferRaw::create();
    for(auto ex : ext_list){
        ex->storeToData();
    }
    auto ext_size = getExtSize();
    _data->setCapacity(HEADER_SIZE + 48+ext_size);
    _data->setSize(HEADER_SIZE + 48+ext_size);

    control_type = ControlPacket::HANDSHAKE;
    sub_type = 0;

    ControlPacket::storeToHeader();

    uint8_t *ptr = (uint8_t *)_data->data() + HEADER_SIZE;

    storeUint32(ptr, version);
    ptr += 4;

    storeUint16(ptr, encryption_field);
    ptr += 2;

    storeUint16(ptr, extension_field);
    ptr += 2;

    storeUint32(ptr, initial_packet_sequence_number);
    ptr += 4;

    storeUint32(ptr, mtu);
    ptr += 4;

    storeUint32(ptr, max_flow_window_size);
    ptr += 4;

    storeUint32(ptr, handshake_type);
    ptr += 4;

    storeUint32(ptr, srt_socket_id);
    ptr += 4;

    storeUint32(ptr, syn_cookie);
    ptr += 4;

    memcpy(ptr, peer_ip_addr, sizeof(peer_ip_addr) * sizeof(peer_ip_addr[0]));
    ptr += sizeof(peer_ip_addr) * sizeof(peer_ip_addr[0]);

    if (encryption_field != NO_ENCRYPTION) {
        ErrorL << "not support encryption " << encryption_field;
    }

    assert(encryption_field == NO_ENCRYPTION);

    
    return storeExtMessage();
}

bool HandshakePacket::isHandshakePacket(uint8_t *buf, size_t len){
    if(!ControlPacket::isControlPacket(buf,len)){
        return false;
    }
    if(len < HEADER_SIZE+48){
        return false;
    }
    return ControlPacket::getControlType(buf,len) == HANDSHAKE;
}

uint32_t HandshakePacket::getHandshakeType(uint8_t *buf, size_t len){
    uint8_t *ptr = buf+HEADER_SIZE+5*4;

    return loadUint32(ptr);
}

uint32_t HandshakePacket::getSynCookie(uint8_t *buf, size_t len){
    uint8_t *ptr = buf+HEADER_SIZE+7*4;
    return loadUint32(ptr);
}
void HandshakePacket::assignPeerIP(struct sockaddr_storage* addr){
    memset(peer_ip_addr,0,sizeof(peer_ip_addr)*sizeof(peer_ip_addr[0]));
    if(addr->ss_family == AF_INET){
        struct sockaddr_in * ipv4 = (struct sockaddr_in *)addr;
        //抓包 奇怪好像是小头端？？？
       storeUint32LE(peer_ip_addr,ipv4->sin_addr.s_addr);
    }else{
        const sockaddr_in6* ipv6 = (struct sockaddr_in6 *)addr;
        memcpy(peer_ip_addr,ipv6->sin6_addr.s6_addr,sizeof(peer_ip_addr)*sizeof(peer_ip_addr[0]));
    }
}
uint32_t HandshakePacket::generateSynCookie(struct sockaddr_storage* addr,TimePoint ts,uint32_t current_cookie, int correction ){

    static std::atomic<uint32_t> distractor{0};
    uint32_t    rollover   = distractor.load() + 10;

    for (;;)
    {
        // SYN cookie
        char clienthost[NI_MAXHOST];
        char clientport[NI_MAXSERV];
        getnameinfo((struct sockaddr*)addr,
                    sizeof(struct sockaddr_storage),
                    clienthost,
                    sizeof(clienthost),
                    clientport,
                    sizeof(clientport),
                    NI_NUMERICHOST | NI_NUMERICSERV);
        int64_t timestamp = (DurationCountMicroseconds(SteadyClock::now() - ts) / 60000000) + distractor.load() +
                            correction; // secret changes every one minute
        std::stringstream cookiestr;
        cookiestr << clienthost << ":" << clientport << ":" << timestamp;
        union {
            unsigned char cookie[16];
            uint32_t       cookie_val;
        };
        MD5 md5(cookiestr.str());
        memcpy(cookie,md5.rawdigest().c_str(),16);

        if (cookie_val != current_cookie)
            return cookie_val;

        ++distractor;

        // This is just to make the loop formally breakable,
        // but this is virtually impossible to happen.
        if (distractor == rollover)
            return cookie_val;
    }
}

} // namespace SRT