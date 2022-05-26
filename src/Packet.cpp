#include "Packet.hpp"

#include "Util/logger.h"

namespace SRT{
    
    inline uint32_t loadUint32(uint8_t* ptr){
        return ptr[0] << 24 | ptr[1]<<16 | ptr[2] << 8 | ptr[3];
    }
    inline uint16_t loadUint16(uint8_t* ptr){
        return  ptr[0] << 8 | ptr[1];
    }

    inline void  storeUint32(uint8_t* buf,uint32_t val){
        buf[0] = val >> 24;
        buf[1] = (val >> 16) & 0xff;
        buf[2] = (val >> 8) & 0xff;
        buf[3] = val & 0xff;
    }

    inline void storeUint16(uint8_t* buf,uint16_t val){
        buf[0] = (val >> 8) & 0xff;
        buf[1] = val & 0xff;
    }

     bool DataPacket::isDataPacket(uint8_t* buf,size_t len){
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
        if(len < HEADER_SIZE){
            WarnL << "data size"<<len<<" less "<<HEADER_SIZE;
            return false;
        }
        uint8_t* ptr = buf;
        f = ptr[0]>>7;
        packet_seq_number = (ptr[0]&0x7f)<<24 | ptr[1]<<12 | ptr[2]<<8 | ptr[3];
        ptr += 4;

        PP = ptr[0]>>6;
        O = (ptr[0]&0x20)>>5;
        KK = (ptr[0]&0x18)>>3;
        R = (ptr[0]&0x04)>>2;
        msg_number = (ptr[0]&0x03) << 24 | ptr[1]<<12 | ptr[2]<<8 | ptr[3];
        ptr += 4;

        timestamp = loadUint32(ptr);
        ptr += 4;

        dst_socket_id = loadUint32(ptr);
        ptr += 4;

        _data = BufferRaw::create();
        _data->assign((char*)(buf),len);
        return true;
    }

    bool DataPacket::storeToData(uint8_t* buf,size_t len){
        _data = BufferRaw::create();
        _data->setCapacity(len+HEADER_SIZE);
        _data->setSize(len+HEADER_SIZE);

        uint8_t* ptr = (uint8_t*)_data->data();
    
        ptr[0] =  packet_seq_number >> 24;
        ptr[1] =  (packet_seq_number >> 16) &0xff;
        ptr[2] = (packet_seq_number >> 8) &0xff;
        ptr[3] = packet_seq_number &0xff;
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

        storeUint32(ptr,timestamp);
        ptr += 4;

        storeUint32(ptr,dst_socket_id);
        ptr += 4;

        memcpy(ptr,buf,len);
        return true;
    }

    char *DataPacket::data() const
    {
        if(!_data)
            return nullptr;
        return _data->data();
    }
    size_t DataPacket::size() const
    {
        if(!_data){
            return 0;
        }
        return _data->size();
    }

    char *DataPacket::payloadData()
    {
        if(!_data)
            return nullptr;
        return _data->data() + HEADER_SIZE;
    }
    size_t DataPacket::payloadSize()
    {
        if(!_data){
            return 0;
        }
        return _data->size() - HEADER_SIZE;
    }

    

    bool ControlPacket::isControlPacket(uint8_t* buf,size_t len){
        if(len < HEADER_SIZE){
             WarnL << "data size"<<len<<" less "<<HEADER_SIZE;
             return false;
         }
         if(buf[0]&0x80){
             return true;
         }
         return false;
    }

    uint16_t ControlPacket::getControlType(uint8_t* buf,size_t len){
        uint8_t* ptr = buf;
        uint16_t control_type = (ptr[0]&0x7f)<<8 | ptr[1];
        return control_type;
    }

    bool ControlPacket::loadHeader(){
        uint8_t* ptr = (uint8_t*)_data->data();
         f = ptr[0]>>7;
         control_type = (ptr[0]&0x7f)<<8 | ptr[1];
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
    }
    bool ControlPacket::storeToHeader(){
        uint8_t* ptr = (uint8_t*)_data->data();
        ptr[0] |= control_type >> 8;
        ptr[0] |= 0x80;
        ptr[1]  = control_type &0xff;
        ptr += 2;

        storeUint16(ptr,sub_type);
        ptr += 2;
       
        ptr[0] = type_specific_info[0];
        ptr[1] = type_specific_info[1];
        ptr[2] = type_specific_info[2];
        ptr[3] = type_specific_info[3];
        ptr += 4;

        storeUint32(ptr,timestamp);
        ptr += 4;

        storeUint32(ptr,dst_socket_id);
        ptr += 4;
    }

    char *ControlPacket::data() const
    {
        if(!_data)
            return nullptr;
        return _data->data();
    }
    size_t ControlPacket::size() const
    {
        if(!_data){
            return 0;
        }
        return _data->size();
    }

    bool HandshakePacket::loadFromData(uint8_t* buf,size_t len){
        _data = BufferRaw::create();
        _data->assign((char*)(buf),len);
        ControlPacket::loadHeader();

        uint8_t* ptr = (uint8_t*)_data->data()+HEADER_SIZE;
        // parse CIF
        version = loadUint32(ptr);
        ptr += 4;

        encryption_field = loadUint16(ptr);
        ptr += 2;

        extension_type =loadUint16(ptr);
        ptr += 2;

        initial_packet_sequence_number = loadUint32(ptr);
        ptr += 4;

        mtu = loadUint32(ptr);
        ptr += 4;

        max_flow_window_size = loadUint16(ptr);
        ptr += 4;

        handshake_type = loadUint16(ptr);
        ptr += 4;

        srt_socket_id = loadUint16(ptr);
        ptr += 4;

        syn_cookie = loadUint16(ptr);
        ptr += 4;

        memcpy(peer_ip_addr,ptr,sizeof(peer_ip_addr)*sizeof(peer_ip_addr[0]));
        ptr += sizeof(peer_ip_addr)*sizeof(peer_ip_addr[0]);
        
        if(encryption_field != NO_ENCRYPTION){
            ErrorL<<"not support encryption "<< encryption_field;
        }

        return true;

    }

    bool HandshakePacket::storeToData(){
         _data = BufferRaw::create();
         _data->setSize(HEADER_SIZE+48);
        ControlPacket::storeToHeader();

        uint8_t* ptr = (uint8_t*)_data->data()+HEADER_SIZE;

        storeUint32(ptr,version);
        ptr += 4;

        storeUint16(ptr,encryption_field);
        ptr += 2;

        storeUint16(ptr,extension_field);
        ptr += 2;

        storeUint32(ptr,initial_packet_sequence_number);
        ptr += 4;

        storeUint32(ptr,mtu);
        ptr += 4;

        storeUint32(ptr,max_flow_window_size);
        ptr += 4;

        storeUint32(ptr,handshake_type);
        ptr += 4;

        storeUint32(ptr,srt_socket_id);
        ptr += 4;

        storeUint32(ptr,syn_cookie);
        ptr += 4;

        memcpy(ptr,peer_ip_addr,sizeof(peer_ip_addr)*sizeof(peer_ip_addr[0]));
        ptr += sizeof(peer_ip_addr)*sizeof(peer_ip_addr[0]);

        if(encryption_field != NO_ENCRYPTION){
            ErrorL<<"not support encryption "<< encryption_field;
        }

        assert(encryption_field == NO_ENCRYPTION);
        
        return true;

    }


}