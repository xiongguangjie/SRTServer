#ifndef ZLMEDIAKIT_SRT_PACKET_H
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
class DataPacket {
public:
    static const size_t HEADER_SIZE = 16;
    static bool IsDataPacket(uint8_t* buf,size_t len);
    bool loadFromData(uint8_t* buf,size_t len);
    
    uint32_t f : 1;
    uint32_t packet_seq_number : 31;
    uint32_t PP : 2;
    uint32_t O : 1;
    uint32_t KK : 2;
    uint32_t R : 1;
    uint32_t msg_number : 26;
    uint32_t timestamp;
    uint32_t dst_socket_id;
    Buffer::Ptr data;
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
class ControlPacketHeader {
private:
#if __BYTE_ORDER == __BIG_ENDIAN
    uint32_t f : 1;
    uint32_t control_type : 15;
    uint32_t sub_type : 16;
    uint8_t type_specific_info[4];
    uint32_t timestamp;
    uint32_t dst_socket_id;
#else
    uint32_t sub_type : 16;
    uint32_t control_type : 15;
    uint32_t f : 1;
    uint8_t type_specific_info[4];
    uint32_t timestamp;
    uint32_t dst_socket_id;
#endif
public:
    uint8_t getFlag() {
        return f;
    }
} PACKED;

#if defined(_WIN32)
#pragma pack(pop)
#endif // defined(_WIN32)

} // namespace SRT

#endif ZLMEDIAKIT_SRT_PACKET_H