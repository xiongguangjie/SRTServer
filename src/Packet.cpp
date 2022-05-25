#include "Packet.hpp"

#include "Util/logger.h"

namespace SRT{
    
     bool DataPacket::IsDataPacket(uint8_t* buf,size_t len){
         if(len < HEADER_SIZE){
             WarnL << "data size"<<len<<" less "<<HEADER_SIZE;
             return false;
         }
         if(!(buf[0]&0x80)){
             return true;
         }
         return false;
    }

    bool DataPacket::loadFromData(uint8_t* buf,size_t len){
        f = buf[0]>>7;
        packet_seq_number = (buf[0]&0x7f)<<24 | buf[1]<<12 | buf[2]<<8 | buf[3];
        PP = buf[4]>>6;
        O = (buf[4]&0x20)>>5;
        KK = (buf[4]&0x18)>>3;
        R = (buf[4]&0x04)>>2;
        msg_number = (buf[4]&0x03) << 24 | buf[5]<<12 | buf[6]<<8 | buf[7];
        timestamp = buf[8]<<24 | buf[9]<<12 | buf[10]<<8 | buf[11];
        dst_socket_id = buf[12]<<24 | buf[13]<<12 | buf[14]<<8 | buf[15];
        
        data = BufferRaw::create();
        data->assign((char*)(buf+HEADER_SIZE),len);
    }


}