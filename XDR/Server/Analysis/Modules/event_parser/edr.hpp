#ifndef XDR_ANALYSIS_EDR_EVENT_PARSER_HPP
#define XDR_ANALYSIS_EDR_EVENT_PARSER_HPP

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

// EDR 이벤트의 구체적인 타입을 식별하기 위한 열거형
enum class EDR_EventType {
    Unknown,
    Process,
    Network,
    FileSystem,
    Registry,
    ImageLoad,
    ProcessAccess,
    Etw
};

// --- EDR 이벤트 클래스 계층 구조 ---
namespace Event {
    
    // 모든 EDR 이벤트의 기반이 될 부모 클래스
    class EDR_Event {
    public:
        // 공통 헤더 정보
        struct Header {
            unsigned long long nano_timestamp;
            std::string agentid;
            std::string root_sessionid;
            std::string parent_sessionid;
            std::string sessionid;
            std::string timestamp_nano_iso8601;
            
            struct OsInfo {
                std::string type;
                std::string version;
            } os;

        } header;
        
        EDR_EventType type = EDR_EventType::Unknown;

        // 생성자: JSON 객체에서 공통 헤더를 파싱
        EDR_Event(const json& event_json) {
            if (!event_json.contains("header")) return;
            const auto& header_json = event_json.at("header");
            
            header.nano_timestamp = header_json.value("nano_timestamp", 0ULL);
            header.agentid = header_json.value("agentid", "");
            header.root_sessionid = header_json.value("root_sessionid", "");
            header.parent_sessionid = header_json.value("parent_sessionid", "");
            header.sessionid = header_json.value("sessionid", "");
            header.timestamp_nano_iso8601 = header_json.value("timestamp_nano_iso8601", "");

            if (header_json.contains("os")) {
                const auto& os_json = header_json.at("os");
                header.os.type = os_json.value("type", "");
                header.os.version = os_json.value("version", "");
            }
        }

        virtual ~EDR_Event() = default; // 다형성을 위한 가상 소멸자
    };

    // 자식 클래스: Process 이벤트
    class EDR_Process_Event : public EDR_Event {
    public:
        std::string action;
        std::string exe_path;
        unsigned long long exe_size;
        std::string exe_sha256;
        std::string parent_exe_path;
        unsigned long long parent_exe_size;
        std::string parent_exe_sha256;
        std::optional<std::string> commandline;
        unsigned long long ppid;
        
        struct UserInfo {
            std::string username;
            std::string sid;
        } user;

        EDR_Process_Event(const json& event_json) : EDR_Event(event_json) {
            this->type = EDR_EventType::Process;
            if (!event_json.at("body").contains("process")) return;
            const auto& proc_json = event_json.at("body").at("process");

            this->action = proc_json.value("action", "");
            this->exe_path = proc_json.value("exe_path", "");
            this->exe_size = proc_json.value("exe_size", 0ULL);
            this->exe_sha256 = proc_json.value("exe_sha256", "");
            this->parent_exe_path = proc_json.value("parent_exe_path", "");
            this->parent_exe_size = proc_json.value("parent_exe_size", 0ULL);
            this->parent_exe_sha256 = proc_json.value("parent_exe_sha256", "");
            this->commandline = proc_json.value("commandline", "");
            this->ppid = proc_json.value("ppid", 0);

            if (proc_json.contains("user")) {
                const auto& user_json = proc_json.at("user");
                this->user.username = user_json.value("username", "");
                this->user.sid = user_json.value("sid", "");
            }
        }
    };

    // 자식 클래스: Network 이벤트
    class EDR_Network_Event : public EDR_Event {
    public:
        std::string sourceip;
        unsigned int sourceport;
        std::string destinationip;
        unsigned int destinationport;
        std::string protocol;
        std::string direction;

        std::string sourcemac;
        std::string destinationmac;

        int packetsize;

        struct SessionInfo {
            std::string sessionid;
            unsigned long long first_seen;
            unsigned long long last_seen;
        } session;

        EDR_Network_Event(const json& event_json) : EDR_Event(event_json) {
            this->type = EDR_EventType::Network;
            if (!event_json.at("body").contains("network")) return;
            const auto& net_json = event_json.at("body").at("network");

            //this->sourcemac = net_json.value("sourcemac", "");
            //this->destinationmac = net_json.value("destinationmac", "");
            // <Before>
            // => 68-1D-EF-4D-F0-85
            // <After>
            // => 68:1d:ef:4d:f0:85
            this->sourcemac = net_json.value("sourcemac", "");
            std::replace(this->sourcemac.begin(), this->sourcemac.end(), '-', ':');
            std::transform(this->sourcemac.begin(), this->sourcemac.end(), this->sourcemac.begin(), ::tolower);

            this->destinationmac = net_json.value("destinationmac", "");
            std::replace(this->destinationmac.begin(), this->destinationmac.end(), '-', ':');
            std::transform(this->destinationmac.begin(), this->destinationmac.end(), this->destinationmac.begin(), ::tolower);

            this->sourceip = net_json.value("sourceip", "");
            this->sourceport = net_json.value("sourceport", 0);
            this->destinationip = net_json.value("destinationip", "");
            this->destinationport = net_json.value("destinationport", 0);
            this->protocol = net_json.value("protocol", "");
            this->direction = net_json.value("direction", "");
            this->packetsize = net_json.value("packetsize", 0);

            if (net_json.contains("session")) {
                const auto& session_json = net_json.at("session");
                this->session.sessionid = session_json.value("sessionid", "");
                this->session.first_seen = session_json.value("first_seen", 0ULL);
                this->session.last_seen = session_json.value("last_seen", 0ULL);
            }
        }
    };

    // 자식 클래스: FileSystem 이벤트
    class EDR_FileSystem_Event : public EDR_Event {
    public:
        std::string action;
        std::string filepath;
        unsigned long long filesize;
        std::string filesha256;

        EDR_FileSystem_Event(const json& event_json) : EDR_Event(event_json) {
            this->type = EDR_EventType::FileSystem;
            if (!event_json.at("body").contains("filesystem")) return;
            const auto& fs_json = event_json.at("body").at("filesystem");
            
            this->action = fs_json.value("action", "");
            this->filepath = fs_json.value("filepath", "");
            this->filesize = fs_json.value("filesize", 0ULL);
            this->filesha256 = fs_json.value("filesha256", "");
        }
    };

    // 자식 클래스: Registry 이벤트
    class EDR_Registry_Event : public EDR_Event {
    public:
        std::string name;
        std::string keyclass;

        EDR_Registry_Event(const json& event_json) : EDR_Event(event_json) {
            this->type = EDR_EventType::Registry;
            if (!event_json.at("body").contains("registry")) return;
            const auto& reg_json = event_json.at("body").at("registry");

            this->name = reg_json.value("name", "");
            this->keyclass = reg_json.value("keyclass", "");
        }
    };

    // 자식 클래스: ImageLoad 이벤트
    class EDR_ImageLoad_Event : public EDR_Event {
    public:
        std::string filepath;
        unsigned long long filesize;
        std::string filesha256;

        EDR_ImageLoad_Event(const json& event_json) : EDR_Event(event_json) {
            this->type = EDR_EventType::ImageLoad;
            if (!event_json.at("body").contains("imageload")) return;
            const auto& img_json = event_json.at("body").at("imageload");

            this->filepath = img_json.value("filepath", "");
            this->filesize = img_json.value("filesize", 0ULL);
            this->filesha256 = img_json.value("filesha256", "");
        }
    };

    // 자식 클래스: ProcessAccess 이벤트
    class EDR_ProcessAccess_Event : public EDR_Event {
    public:
        std::string filepath;
        std::string handletype;
        std::vector<std::string> desiredaccesses;
        unsigned long long target_pid;

        EDR_ProcessAccess_Event(const json& event_json) : EDR_Event(event_json) {
            this->type = EDR_EventType::ProcessAccess;
            if (!event_json.at("body").contains("processaccess")) return;
            const auto& pa_json = event_json.at("body").at("processaccess");

            this->filepath = pa_json.value("filepath", "");
            this->handletype = pa_json.value("handletype", "");
            this->target_pid = pa_json.value("target_pid", 0);
            
            if (pa_json.contains("desiredaccesses") && pa_json.at("desiredaccesses").is_array()) {
                for (const auto& access : pa_json.at("desiredaccesses")) {
                    this->desiredaccesses.push_back(access.get<std::string>());
                }
            }
        }
    };

    // 자식 클래스: ETW 이벤트
    class EDR_Etw_Event : public EDR_Event {
    public:
        int event_id;
        int event_version;
        int event_flags;
        std::string event_name;
        json fields; // ETW fields는 구조가 다양하므로 json 객체로 그대로 저장

        EDR_Etw_Event(const json& event_json) : EDR_Event(event_json) {
            this->type = EDR_EventType::Etw;
            if (!event_json.at("body").contains("etw")) return;
            const auto& etw_json = event_json.at("body").at("etw");
            
            this->event_id = etw_json.value("event_id", 0);
            this->event_version = etw_json.value("event_version", 0);
            this->event_flags = etw_json.value("event_flags", 0);
            this->event_name = etw_json.value("event_name", "");
            
            if (etw_json.contains("fields")) {
                this->fields = etw_json.at("fields");
            }
        }
    };

} // namespace Event



// --- 메인 EDR 로그 파서 클래스 ---
class RAW_EDR : public XDR::Server::Analysis::EventParser::EventParserParent {
public:
    struct SessionInfo {
        std::string Root_SessionID;
        std::string SessionID;
        std::string Parent_SessionID;
    };
    

    struct IamInfo {
        std::string ticket;
        std::string ipv4;
        std::string agent_id;
        std::string username;
    };

    struct SharedTreeTimestampInfo {
        unsigned long long first_seen;
        unsigned long long last_seen;
    };

    std::string agent_id;

    SessionInfo session;
    std::string os_platform;
    std::string os_version;
    std::vector<GlobalStructs::RuleInfo> rules;
    json intelligences;
    std::string root_process_sha256;
    IamInfo iam;

    std::shared_ptr<Event::EDR_Event> Bodyevent;


    // 생성자
    RAW_EDR(const json& Event) : XDR::Server::Analysis::EventParser::EventParserParent(Event) {
        this->_parsing(Event);
    }

    std::optional<XDR::Server::Analysis::EventParser::Anchor::_NETWORKINFO> Get_XDR_ANCHOR_NETWORK_INFO() const {
        if( auto NetworkEvent = Get_Network_Event() )
        {
            std::cout << "Network 추가된" << std::endl; 
            return XDR::Server::Analysis::EventParser::Anchor::_NETWORKINFO{
                    .protocol = NetworkEvent->protocol,
                    .src_mac  = NetworkEvent->sourcemac,
                    .dst_mac  = NetworkEvent->destinationmac,
                    .src_ip = NetworkEvent->sourceip,
                    .src_port = NetworkEvent->sourceport,
                    .dst_ip = NetworkEvent->destinationip,
                    .dst_port = NetworkEvent->destinationport
                };
        }
        return std::nullopt;
    }

    // RAW_EDR 클래스 내부 (public:)
    std::shared_ptr<Event::EDR_Process_Event> Get_Process_Event( unsigned long long* out_nanotimestamp =nullptr) const {
        if(out_nanotimestamp)
            *out_nanotimestamp = nano_timestamp;
        return std::dynamic_pointer_cast<Event::EDR_Process_Event>(Bodyevent);
    }

    std::shared_ptr<Event::EDR_Network_Event> Get_Network_Event(unsigned long long* out_nanotimestamp =nullptr) const {
        if(out_nanotimestamp)
            *out_nanotimestamp = nano_timestamp;
        return std::dynamic_pointer_cast<Event::EDR_Network_Event>(Bodyevent);
    }

    std::shared_ptr<Event::EDR_FileSystem_Event> Get_FileSystem_Event(unsigned long long* out_nanotimestamp =nullptr) const {
        if(out_nanotimestamp)
            *out_nanotimestamp = nano_timestamp;
        return std::dynamic_pointer_cast<Event::EDR_FileSystem_Event>(Bodyevent);
    }

    std::shared_ptr<Event::EDR_Registry_Event> Get_Registry_Event(unsigned long long* out_nanotimestamp =nullptr) const {
        if(out_nanotimestamp)
            *out_nanotimestamp = nano_timestamp;
        return std::dynamic_pointer_cast<Event::EDR_Registry_Event>(Bodyevent);
    }

    std::shared_ptr<Event::EDR_ImageLoad_Event> Get_ImageLoad_Event(unsigned long long* out_nanotimestamp =nullptr) const {
        if(out_nanotimestamp)
            *out_nanotimestamp = nano_timestamp;
        return std::dynamic_pointer_cast<Event::EDR_ImageLoad_Event>(Bodyevent);
    }

    std::shared_ptr<Event::EDR_ProcessAccess_Event> Get_ProcessAccess_Event(unsigned long long* out_nanotimestamp =nullptr) const {
        if(out_nanotimestamp)
            *out_nanotimestamp = nano_timestamp;
        return std::dynamic_pointer_cast<Event::EDR_ProcessAccess_Event>(Bodyevent);
    }

    std::shared_ptr<Event::EDR_Etw_Event> Get_Etw_Event(unsigned long long* out_nanotimestamp =nullptr) const {
        if(out_nanotimestamp)
            *out_nanotimestamp = nano_timestamp;
        return std::dynamic_pointer_cast<Event::EDR_Etw_Event>(Bodyevent);
    }

protected:
    bool _parsing(const json& raw_edr_json) override {
        try {
            // 1. Header 파싱 (단일 로그 구조)
            if (raw_edr_json.contains("header")) {
                this->agent_id = raw_edr_json.at("header").value("agentid", "");

                this->session.SessionID = raw_edr_json.at("header").value("sessionid", "");
                this->session.Parent_SessionID = raw_edr_json.at("header").value("parent_sessionid", "");
                this->session.Root_SessionID = raw_edr_json.at("header").value("root_sessionid", "");



                // parent field update
                this->root_session_id = this->session.Root_SessionID;
                this->nano_timestamp = raw_edr_json.at("header")["nano_timestamp"].get<unsigned long long>();
                this->timestamp_nano_iso8601 = raw_edr_json.at("header").value("timestamp_nano_iso8601", "");
            }

            // 2. Threat (Rules) 파싱
            /* 부모에서 ..  */

            // 3. Event Body 파싱 (Factory Pattern)
            if (raw_edr_json.contains("body")) {
                const auto& body = raw_edr_json.at("body");
                if (body.contains("process")) this->Bodyevent = std::make_shared<Event::EDR_Process_Event>(raw_edr_json);
                else if (body.contains("network")) this->Bodyevent = std::make_shared<Event::EDR_Network_Event>(raw_edr_json);
                else if (body.contains("filesystem")) this->Bodyevent = std::make_shared<Event::EDR_FileSystem_Event>(raw_edr_json);
                else if (body.contains("registry")) this->Bodyevent = std::make_shared<Event::EDR_Registry_Event>(raw_edr_json);
                else if (body.contains("imageload")) this->Bodyevent = std::make_shared<Event::EDR_ImageLoad_Event>(raw_edr_json);
                else if (body.contains("processaccess")) this->Bodyevent = std::make_shared<Event::EDR_ProcessAccess_Event>(raw_edr_json);
                else if (body.contains("etw")) this->Bodyevent = std::make_shared<Event::EDR_Etw_Event>(raw_edr_json);
                else this->Bodyevent = std::make_shared<Event::EDR_Event>(raw_edr_json); // Fallback
            }

        } catch (const json::exception& e) {
            std::cerr << "RAW_EDR Parsing Error: " << e.what() << std::endl;
            return false;
        }
        return true;
    }

    

private:
    
};

// RAW_EDR__Manager ( 여러 RAW_EDR를 리스트형태로 관리 )

} // namespace EventParser
} // namespace Analysis
} // namespace Server
} // namespace XDR

#endif // XDR_ANALYSIS_EVENT_PARSER_HPP