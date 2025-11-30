#ifndef XDR_ANALYSIS_NDR_EVENT_PARSER_HPP
#define XDR_ANALYSIS_NDR_EVENT_PARSER_HPP

#include "../../../../../util/util.hpp" // nlohmann/json 라이브러리 포함 가정
#include <string>
#include <vector>
#include <optional>
#include <memory> // for std::unique_ptr
#include <iostream> // for error logging

#include "parent.hpp"

namespace XDR {
namespace Server {
namespace Analysis {
namespace EventParser {

std::string ProtocolToString(int protocol);



class RAW_NDR_Packet
{
    public:
        struct EthernetLayer
        {
            std::string Src_Mac;
            std::string Dst_Mac;
        };

        struct IpLayer
        {
            std::string Src_Ip;
            std::string Dst_Ip;

            std::string Protocol;
        };

        struct TransportLayer
        {
            unsigned int Src_Port;
            unsigned int Dst_Port;
        };

    public:
        std::optional<struct EthernetLayer> EtherLayerInfo;
        std::optional<struct IpLayer> IpLayerInfo;
        std::optional<struct TransportLayer> TransportLayerInfo;

        json PacketOriginal;

    public:
        RAW_NDR_Packet(const json& Event)
        {

            if(!Event["body"].contains("packet"))
                return;
            
            auto PacketJson = Event["body"]["packet"].get<json>();
            PacketOriginal = PacketJson;

            /*
                PacketJson-> body -> "Packet" 정보를 쉽게 쿼리하여 가져올 수 있도록 하는 클래스 
            */
            for(const auto&[LayerName, V ] : PacketJson.items() )
            {
                if( LayerName == "ethernet" )
                {
                    EtherLayerInfo = EthernetLayer{
                        .Src_Mac = V["src_mac"].get<std::string>(),
                        .Dst_Mac = V["dst_mac"].get<std::string>()
                    };
                }
                else if ( LayerName == "ip" )
                {
                    IpLayerInfo = IpLayer{
                        .Src_Ip = V["src_ip"].get<std::string>(),
                        .Dst_Ip = V["dst_ip"].get<std::string>(),
                        .Protocol = ProtocolToString( V["protocol"].get<int>() )
                    };
                }
                else if ( LayerName == "tcp" || LayerName == "udp"  )
                {
                    TransportLayerInfo = TransportLayer{
                        .Src_Port =    V["src_port"].get<unsigned int>(),
                        .Dst_Port =    V["dst_port"].get<unsigned int>()
                    };
                }
            }
        }

        std::optional<struct EthernetLayer> Get_Ethernet_Info()
        {
            return EtherLayerInfo;
        }
        std::optional<struct IpLayer> Get_Ip_Info()
        {
            return IpLayerInfo;
        }
        std::optional<struct TransportLayer> Get_Transport_Info()
        {
            return TransportLayerInfo;
        }
        json Get_PacketJson()
        {
            return PacketOriginal;
        }
        
};




class RAW_NDR_BODY_EVENT
{
    public:
        virtual ~RAW_NDR_BODY_EVENT() = default;
        RAW_NDR_BODY_EVENT(const json& event)
        : PacketInfoManager(event)
        {

        }


        std::optional<struct RAW_NDR_Packet::EthernetLayer> Get_Ethernet_Info()
        {
            return PacketInfoManager.Get_Ethernet_Info();
        }
        std::optional<struct RAW_NDR_Packet::IpLayer> Get_Ip_Info()
        {
            return PacketInfoManager.Get_Ip_Info();
        }
        std::optional<struct RAW_NDR_Packet::TransportLayer> Get_Transport_Info()
        {
            return PacketInfoManager.Get_Transport_Info();
        }
        json Get_PacketJson()
        {
            return PacketInfoManager.Get_PacketJson();
        }
    private:
        RAW_NDR_Packet PacketInfoManager;
};

class RAW_NDR_EVENT_SESSION_START : public RAW_NDR_BODY_EVENT
{
    public:
        RAW_NDR_EVENT_SESSION_START(const json& event)
        : RAW_NDR_BODY_EVENT(event)
        {
            direction = event["body"]["session_start"]["direction"].get<std::string>();
            interfacename = event["body"]["session_start"]["interfacename"].get<std::string>();
            protocol = event["body"]["session_start"]["protocol"].get<std::string>();
            sourceip = event["body"]["session_start"]["sourceip"].get<std::string>();
            destinationip = event["body"]["session_start"]["destinationip"].get<std::string>();
            sourceport = event["body"]["session_start"]["sourceport"].get<unsigned int>();
            destinationport = event["body"]["session_start"]["destinationport"].get<unsigned int>();
        }

        std::string direction;
        std::string interfacename;
        std::string protocol;
        std::string sourceip;
        std::string destinationip;
        unsigned int sourceport;
        unsigned int destinationport;
};

class RAW_NDR_EVENT_RULE_MATCHED : public RAW_NDR_BODY_EVENT
{
    public:
        RAW_NDR_EVENT_RULE_MATCHED(const json& event)
        : RAW_NDR_BODY_EVENT(event)
        {
            /* x */
        }
    private:
};

class RAW_NDR_EVENT_TIMEOUT : public RAW_NDR_BODY_EVENT
{
    public:
        RAW_NDR_EVENT_TIMEOUT(const json& event)
        : RAW_NDR_BODY_EVENT(event)
        {
            timeout_timestamp = event["body"]["session_timeout"]["session_lastseen_timestamp"].get<unsigned long long>();
            timeout_value = event["body"]["session_timeout"]["timeout_value"].get<unsigned long long>();
        }

        unsigned long long timeout_timestamp;
        unsigned long long timeout_value;
};





class RAW_NDR : public XDR::Server::Analysis::EventParser::EventParserParent {
private:
    std::string flow_session_id;
    std::string sensor_id;

    unsigned long long current_egress_packet_count = 0;
    unsigned long long current_egress_packet_cycle_count = 0;
    unsigned long long current_ingress_packet_count = 0;
    unsigned long long current_ingress_packet_cycle_count = 0;
    unsigned long long current_packet_size = 0;
    unsigned long long current_packet_size_cycle_count = 0;

    std::shared_ptr<RAW_NDR_BODY_EVENT> BodyEvent = nullptr;
    
public:
    RAW_NDR(const json& raw_ndr_json) : XDR::Server::Analysis::EventParser::EventParserParent(raw_ndr_json) 
    { 
        this->_parsing(raw_ndr_json); 
    }

    std::optional<XDR::Server::Analysis::EventParser::Anchor::_NETWORKINFO> Get_XDR_ANCHOR_NETWORK_INFO() const {
        
        if(!BodyEvent)
            return std::nullopt;
        
        std::string SourceMacAddress = "";
        std::string DestMacAddress = "";

        std::string SourceIpAddress = "";
        std::string DestIpAddress = "";
        std::string Protocol = "";

        unsigned int SourcePort = 0;
        unsigned int DestPort = 0;

        auto EthernetInfo = BodyEvent->Get_Ethernet_Info();
        if(EthernetInfo.has_value())
        {
            SourceMacAddress = EthernetInfo->Src_Mac;
            DestMacAddress = EthernetInfo->Dst_Mac;
        }

        auto IpInfo = BodyEvent->Get_Ip_Info();
        if(IpInfo.has_value())
        {
            SourceIpAddress = IpInfo->Src_Ip;
            DestIpAddress = IpInfo->Dst_Ip;
            Protocol = IpInfo->Protocol;
        }

        auto TransportInfo = BodyEvent->Get_Transport_Info();
        if(TransportInfo.has_value())
        {
            SourcePort = TransportInfo->Src_Port;
            DestPort = TransportInfo->Dst_Port;
        }

        return XDR::Server::Analysis::EventParser::Anchor::_NETWORKINFO{
                    .protocol = Protocol,
                    .src_mac  = SourceMacAddress,
                    .dst_mac  = DestMacAddress,
                    .src_ip = SourceIpAddress,
                    .src_port = SourcePort,
                    .dst_ip = DestIpAddress,
                    .dst_port = DestPort
                };
    }

protected:
    bool _parsing(const json& raw_ndr_json) override {
        try {
            // 3가지 상태. 
            /*
                1. 세션시작
                2. 세션 타임아웃
                3. 룰 매치결과
            
                *단, 공통점: -> header 부분

                // * "session_rule"은 이미 threat에 귀속되므로 별도 파싱안해도됨

                NDR의 경우 감지된 패킷, 별도의 Metadata 만 파싱
            */

            // 1. Header파싱
            if(raw_ndr_json.contains("header"))
            {
                this->flow_session_id = raw_ndr_json.at("header").value("flow_session_id", "");

                this->current_egress_packet_count = raw_ndr_json.at("header")["current_egress_packet_count"].get<unsigned long long>();//raw_ndr_json.at("header").value("current_egress_packet_count", 0);
                this->current_egress_packet_cycle_count = raw_ndr_json.at("header")["current_egress_packet_cycle_count"].get<unsigned long long>();//raw_ndr_json.at("header").value("current_egress_packet_cycle_count", 0);
                this->current_ingress_packet_count = raw_ndr_json.at("header")["current_ingress_packet_count"].get<unsigned long long>();//raw_ndr_json.at("header").value("current_ingress_packet_count", 0);
                this->current_ingress_packet_cycle_count = raw_ndr_json.at("header")["current_ingress_packet_cycle_count"].get<unsigned long long>();//raw_ndr_json.at("header").value("current_ingress_packet_cycle_count", 0);
                this->current_packet_size = raw_ndr_json.at("header")["current_packet_size"].get<unsigned long long>();//raw_ndr_json.at("header").value("current_packet_size", 0);
                this->current_packet_size_cycle_count = raw_ndr_json.at("header")["current_packet_size_cycle_count"].get<unsigned long long>();//raw_ndr_json.at("header").value("current_packet_size_cycle_count", 0);

                // parent field update
                this->root_session_id = this->flow_session_id;
                this->nano_timestamp = raw_ndr_json.at("header")["nano_timestamp"].get<unsigned long long>();
                this->timestamp_nano_iso8601 = raw_ndr_json.at("header").value("timestamp_nano_iso8601", "");
            }

            // 2. Body파싱 
            if( raw_ndr_json.contains("body") )
            {
                if( raw_ndr_json["body"].contains("session_start") )
                {
                    BodyEvent = std::make_shared<RAW_NDR_EVENT_SESSION_START>(raw_ndr_json);
                }
                else if( raw_ndr_json["body"].contains("session_rule") )
                {
                    BodyEvent = std::make_shared<RAW_NDR_EVENT_RULE_MATCHED>(raw_ndr_json);
                }
                else if( raw_ndr_json["body"].contains("session_timeout") )
                {
                    BodyEvent = std::make_shared<RAW_NDR_EVENT_TIMEOUT>(raw_ndr_json);
                }
            }

            // 3. threat파싱
            /* 부모에서 ... */
        }
        catch (std::exception& e)
        {
            std::cerr << "RAW_NDR Parsing Error: " << e.what() << std::endl;
            return false;
        }
        return true;
    }
private:
    
};


std::string ProtocolToString(int protocol) {
            switch (protocol) {
            case 0:   return "hopopt";
            case 1:   return "icmp";
            case 2:   return "igmp";
            case 3:   return "ggp";
            case 4:   return "ipv4";
            case 5:   return "st";
            case 6:   return "tcp";
            case 7:   return "cbt";
            case 8:   return "egp";
            case 9:   return "igp";
            case 10:  return "bbn-rcc-mon";
            case 11:  return "nvp-ii";
            case 12:  return "pup";
            case 13:  return "argus";
            case 14:  return "emcon";
            case 15:  return "xnet";
            case 16:  return "chaos";
            case 17:  return "udp";
            case 18:  return "mux";
            case 19:  return "dcn-meas";
            case 20:  return "hmp";
            case 21:  return "prm";
            case 22:  return "xns-idp";
            case 23:  return "trunk-1";
            case 24:  return "trunk-2";
            case 25:  return "leaf-1";
            case 26:  return "leaf-2";
            case 27:  return "rdp";
            case 28:  return "irtp";
            case 29:  return "iso-tp4";
            case 30:  return "netblt";
            case 31:  return "mfe-nsp";
            case 32:  return "merit-inp";
            case 33:  return "dccp";
            case 34:  return "3pc";
            case 35:  return "idpr";
            case 36:  return "xtp";
            case 37:  return "ddp";
            case 38:  return "idpr-cmtp";
            case 39:  return "tp++";
            case 40:  return "il";
            case 41:  return "ipv6";
            case 42:  return "sdrp";
            case 43:  return "ipv6-route";
            case 44:  return "ipv6-frag";
            case 45:  return "idrp";
            case 46:  return "rsvp";
            case 47:  return "gre";
            case 48:  return "dsn";
            case 49:  return "iatp";
            case 50:  return "stp";
            case 51:  return "srp";
            case 52:  return "uti";
            case 53:  return "swipe";
            case 54:  return "narp";
            case 55:  return "mobile";
            case 56:  return "ipv6";
            case 57:  return "cftp";
            case 58:  return "cal";
            case 59:  return "mtp";
            case 60:  return "ax.25";
            case 61:  return "os";
            case 62:  return "micp";
            case 63:  return "scc-sp";
            case 64:  return "etherip";
            case 65:  return "encap";
            case 66:  return "private";
            case 67:  return "gmtp";
            case 68:  return "ifmp";
            case 69:  return "pnni";
            case 70:  return "pim";
            case 71:  return "aris";
            case 72:  return "scps";
            case 73:  return "qnx";
            case 74:  return "a/n";
            case 75:  return "ipcomp";
            case 76:  return "snp";
            case 77:  return "compaq-peer";
            case 78:  return "ipx-in-ip";
            case 79:  return "vrrp";
            case 80:  return "pgm";
            case 81:  return "any";
            case 82:  return "l2tp";
            case 83:  return "ddx";
            case 84:  return "iatp";
            case 85:  return "stp";
            case 86:  return "srp";
            case 87:  return "uti";
            case 88:  return "swipe";
            case 89:  return "narp";
            case 90:  return "mobile";
            case 91:  return "ipv6";
            case 92:  return "cftp";
            case 93:  return "cal";
            case 94:  return "mtp";
            case 95:  return "ax.25";
            case 96:  return "os";
            case 97:  return "micp";
            case 98:  return "scc-sp";
            case 99:  return "etherip";
            case 100: return "encap";
            case 101: return "private";
            case 102: return "gmtp";
            case 103: return "ifmp";
            case 104: return "pnni";
            case 105: return "pim";
            case 106: return "aris";
            case 107: return "scps";
            case 108: return "qnx";
            case 109: return "a/n";
            case 110: return "ipcomp";
            case 111: return "snp";
            case 112: return "compaq-peer";
            case 113: return "ipx-in-ip";
            case 114: return "vrrp";
            case 115: return "pgm";
            case 116: return "any";
            case 117: return "l2tp";
            case 118: return "ddx";
            case 119: return "iatp";
            case 255: return "reserved";
            default:  return "unknown";
            }
        }

}
}
}
}



#endif