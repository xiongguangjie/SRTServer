﻿#ifndef ZLMEDIAKIT_SRT_PACKET_H
#define ZLMEDIAKIT_SRT_PACKET_H

#include <stdint.h>
#include <vector>

#include "Network/Buffer.h"

namespace SRT {

using namespace toolkit;

/*
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+- SRT Header +-+-+-+-+-+-+-+-+-+-+-+-+-+
|0|                    Packet Sequence Number                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|P P|O|K K|R|                   Message Number                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Timestamp                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Destination Socket ID                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                              Data                             +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            Figure 3: Data packet structure
            reference https://haivision.github.io/srt-rfc/draft-sharabayko-srt.html#name-packet-structure
*/
class DataPacket : public Buffer {
public:
    using Ptr = std::shared_ptr<DataPacket>;
    DataPacket() = default;
    ~DataPacket() = default;

    static const size_t HEADER_SIZE = 16;
    static bool isDataPacket(uint8_t* buf,size_t len);
    bool loadFromData(uint8_t* buf,size_t len);
    bool storeToData(uint8_t* buf,size_t len);

    ///////Buffer override///////
    char *data() const override;
    size_t size() const override;

    char* payloadData();
    size_t payloadSize();
    
    uint32_t f : 1;
    uint32_t packet_seq_number : 31;
    uint32_t PP : 2;
    uint32_t O : 1;
    uint32_t KK : 2;
    uint32_t R : 1;
    uint32_t msg_number : 26;
    uint32_t timestamp;
    uint32_t dst_socket_id;
private:
    BufferRaw::Ptr _data;
};
/*
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+- SRT Header +-+-+-+-+-+-+-+-+-+-+-+-+-+
|1|         Control Type        |            Subtype            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   Type-specific Information                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Timestamp                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Destination Socket ID                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+- CIF -+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                   Control Information Field                   +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            Figure 4: Control packet structure
             reference https://haivision.github.io/srt-rfc/draft-sharabayko-srt.html#name-control-packets
*/
class ControlPacket : public Buffer {
public:
    static const size_t HEADER_SIZE = 16;
    static bool isControlPacket(uint8_t* buf,size_t len);
    static uint16_t getControlType(uint8_t* buf,size_t len);

    virtual bool loadFromData(uint8_t* buf,size_t len) = 0;
    virtual bool storeToData() = 0;

    bool loadHeader();
    bool storeToHeader();

     ///////Buffer override///////
    char *data() const override;
    size_t size() const override;

    enum
    {
        HANDSHAKE = 0x0000,
        KEEPALIVE = 0x0001,
        ACK = 0x0002,
        NAK = 0x0003,
        CONGESTIONWARNING = 0x0004,
        SHUTDOWN = 0x0005,
        ACKACK = 0x0006,
        DROPREQ = 0x0007,
        PEERERROR = 0x0008,
        USERDEFINEDTYPE = 0x7FFF
    };

    uint32_t sub_type : 16;
    uint32_t control_type : 15;
    uint32_t f : 1;
    uint8_t type_specific_info[4];
    uint32_t timestamp;
    uint32_t dst_socket_id;
protected:
    BufferRaw::Ptr _data;
};

/**
  0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            Version                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Encryption Field       |        Extension Field        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 Initial Packet Sequence Number                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 Maximum Transmission Unit Size                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Maximum Flow Window Size                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Handshake Type                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         SRT Socket ID                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           SYN Cookie                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                                                               |
+                        Peer IP Address                        +
|                                                               |
+                                                               +
|                                                               |
+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
|         Extension Type        |        Extension Length       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                       Extension Contents                      +
|                                                               |
+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
    Figure 5: Handshake packet structure 
    https://haivision.github.io/srt-rfc/draft-sharabayko-srt.html#name-handshake
 */
class HandshakePacket : public ControlPacket{
public:
    enum
    {
        NO_ENCRYPTION = 0,
        AES_128 = 1,
        AES_196 = 2,
        AES_256 = 3
    };

    enum
    {
        HANDSHAKE_TYPE_DONE = 0xFFFFFFFD,
        HANDSHAKE_TYPE_AGREEMENT = 0xFFFFFFFE,
        HANDSHAKE_TYPE_CONCLUSION = 0xFFFFFFFF,
        HANDSHAKE_TYPE_WAVEHAND = 0x00000000,
        HANDSHAKE_TYPE_INDUCTION = 0x00000001
    };

    enum{
        HS_EXT_FILED_HSREQ = 0x00000001,
        HS_EXT_FILED_KMREQ = 0x00000002,
        HS_EXT_FILED_CONFIG = 0x00000004
    };
    ///////ControlPacket override///////
    bool loadFromData(uint8_t *buf, size_t len) override;
    bool storeToData() override;
    
    uint32_t version;
    uint16_t encryption_field;
    uint16_t extension_field;
    uint32_t initial_packet_sequence_number;
    uint32_t mtu;
    uint32_t max_flow_window_size;
    uint32_t handshake_type;
    uint32_t srt_socket_id;
    uint32_t syn_cookie;
    uint8_t peer_ip_addr[16];

    uint16_t extension_type;
    uint16_t extension_length;

};

} // namespace SRT

#endif ZLMEDIAKIT_SRT_PACKET_H