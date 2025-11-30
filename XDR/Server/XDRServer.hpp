#ifndef XDRSERVER_HPP
#define XDRSERVER_HPP

#include "../../util/util.hpp"

#include "Analysis/Modules/TimestampBased.hpp"
#include "Analysis/Modules/AnchorBased.hpp"

namespace XDR
{
    namespace Server
    {
        class XDRServer
        {
            public:
                XDRServer(
                    std::string VATEX_SAPIENTIA_SIEM_API_ServerIp,
                    unsigned int VATEX_SAPIENTIA_SIEM_API_ServerPort
                ): 
                Siem(VATEX_SAPIENTIA_SIEM_API_ServerIp, VATEX_SAPIENTIA_SIEM_API_ServerPort), 
                Analysis_TimestampBased(Siem), Analysis_Anchor(Siem)
                {}

                XDR::Server::Analysis::TimestampBased Analysis_TimestampBased;
                XDR::Server::Analysis::AnchorBased Analysis_Anchor;

            private:
                bool is_running = false;
                XDR::Util::ToSiem::SiemClient Siem;

                
        };
    }
}

#endif