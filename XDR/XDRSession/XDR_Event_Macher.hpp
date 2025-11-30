#ifndef XDRSESSIONMANAGER_HPP
#define XDRSESSIONMANAGER_HPP

#include "../../util/util.hpp"

namespace XDR
{
    namespace Server
    {
        namespace eXtended_Analysis_Session
        {
            namespace Event
            {

                enum SolutionPlatform
                {
                    EDR =1,
                    NDR,
                    SIEM,
                    SOAR,
                    ThirdParty
                };
                
                // 로그 통합시 사용되는 데이터 타입들 정의
                enum XDR_Normalized_Types
                {
                    /*
                        Network Based
                        // 캡쳐된 패킷에서 자신을 제외한 IP (외부) 값을 의미한다.
                    */
                    External_ipv4_with_port_and_protocol      // with port and protocol , if packet layer less than Transport, the port value was set 0 ~~!~!~
                };

                class XDR_Event
                {
                    private:
                        unsigned long long timeout_time;
                    public:
                        XDR_Event(
                            unsigned long long timeout_time = 10000000000
                        ):timeout_time(timeout_time)
                        {
                            _set_timeout_timestamp();
                        }

                        virtual ~XDR_Event() = default;


                        /*
                            In_Match

                            other Solution Raw-Log -> here
                        */

                        // Network based Match
                        virtual bool To_Match__External_ipv4_with_port_and_protocol( 

                            const SolutionPlatform& Caller_Platform, // 호줄한 로그 플랫폼에 따라 별도의 처리가 있을 수 있기 때문

                            const std::string& ProtocolName, 
                            const std::string& ExternalIp, 
                            const unsigned int& ExternalPort, 
                            const unsigned long long  Log_Start_Timestamp,
                            const unsigned long long  Log_End_Timestamp
                        )
                        {
                            throw std::runtime_error(" not implemented 'To_Match__External_ipv4_with_port_and_protocol' ");
                        }

                        /*
                            here -> To the other Solution Match Thread
                        */
                        // ?? (고민필요. 인자를 받을 때, 클래스 내 필드인 map을 인자로 받아서 직접 각 Child가 로직을 부여할 수  있도록 할 수 있음(호출시 무조건 스레드 잠금또는 동시성문제없어야함. ))


                        /*
                            Output
                        */
                       virtual json Get_Raw_Event()    // 로그를 가져옴
                       {
                            throw std::runtime_error(" not implemented 'Get_Raw_Event' ");
                       }
                       virtual std::string Get_SessionId() // 해당 로그의 대표적 세션ID를 알고 싶을 때
                       {
                            throw std::runtime_error(" not implemented 'Get_SessionId' ");
                       }

                       // CleanUp 비동기 스레드가 체크할 수 있음
                       bool Is_Timeout()
                       {
                            return ( timeoutTimestamp < XDR::Util::timestamp::Get_Real_Timestamp() ? true : false );
                       }

                    private:
                        unsigned long long timeoutTimestamp = 0;
                        void _set_timeout_timestamp()
                        {
                            timeoutTimestamp = ( XDR::Util::timestamp::Get_Real_Timestamp() + timeout_time );
                        }
                };

                class NDR_RAW_EVENT : public XDR_Event
                {

                    struct ProtocolInfos_Exclusive
                    {
                        std::string protocol_name;

                        std::string RemoteIp;
                        unsigned int RemotePort = 0;

                        bool operator<(const ProtocolInfos_Exclusive& other) const
                        {
                            if (protocol_name != other.protocol_name)
                                return protocol_name < other.protocol_name;
                            if (RemoteIp != other.RemoteIp)
                                return RemoteIp < other.RemoteIp;
                            return RemotePort < other.RemotePort;
                        }
                    };



                    


                    public:
                        NDR_RAW_EVENT(const json& ndr_raw)
                        :Raw_Event(ndr_raw)
                        {
                            /*
                                NDR Session Log -> XDR Mapping

                                -> json
                                    -> "packets"
                                        -> (list)
                                            -> check keys(protocol string but lower() in json.items() !!@@$$%@#)
                                                -> Example
                                                    {
                                                        "ethernet": {
                                                            "dst_mac": "ff:ff:ff:ff:ff:ff",
                                                            "ether_type": 2048,
                                                            "src_mac": "88:f4:da:a1:ec:58"
                                                            },
                                                        "ip": {
                                                            "dst_ip": "192.168.255.255",
                                                            "fragment_offset": 0,
                                                            "header_length": 20,
                                                            "is_fragment": false,
                                                            "protocol": 17,
                                                            "src_ip": "192.168.1.201",
                                                            "total_length": 72,
                                                            "ttl": 128,
                                                            "version": 4
                                                        }
                                                            .... + 
                                                    }
                            */
                            if ( ndr_raw.contains("packets") && ndr_raw["packets"].get<std::vector<json>>().size() )
                            {
                                // 무조건 있어야함!
                                // 계층별로 정보가 있기 때문이다. 
                                std::set< ProtocolInfos_Exclusive > RemoteNetworkInfo;
                                /*
                                    "events": [
                                    {
                                        "body": {
                                        "session_start": {
                                            "destinationip": "34.95.113.255",
                                            "destinationport": 443,
                                            "direction": "out",
                                            "interfacename": "enp3s0",
                                            "protocol": "tcp",
                                            "sourceip": "192.168.1.205",
                                            "sourceport": 50974
                                        }
                                        },
                                        "header": {
                                        "current_egress_packet_count": 1,
                                        "current_egress_packet_cycle_count": 0,
                                        "current_ingress_packet_count": 0,
                                        "current_ingress_packet_cycle_count": 0,
                                        "current_packet_size": 74,
                                        "current_packet_size_cycle_count": 0,
                                        "flow_session_id": "229adef7a3c6a166b2b8d17c5a1e961ed440279d8e2bc658c69888a9d61bdf79",
                                        "nano_timestamp": 1763218346668990700,
                                        "sensorid": "47691fdc8755a25a35cf956cd9cc5295b9fd47ed78e9a7cb985681864119546d"
                                        }
                                    },
                                    ,,,,,,,,,,,,,,,,,,,,,,, +
                                */
                                const auto& events = ndr_raw["events"].get<std::vector<json>>();

                                json event_at_0 = events.front();
                                json event_at_last = events.back();

                                is_inbound = ( event_at_0["body"]["session_start"]["direction"] == "in" ? true : false );
                                protocol_name = event_at_0["body"]["session_start"]["protocol"].get<std::string>();
                                ExternalIp = ( is_inbound ? event_at_0["body"]["session_start"]["sourceip"].get<std::string>() :  event_at_0["body"]["session_start"]["destinationip"].get<std::string>()  );
                                ExternalPort = ( is_inbound ? event_at_0["body"]["session_start"]["sourceport"].get<unsigned int>() :  event_at_0["body"]["session_start"]["destinationport"].get<unsigned int>()  );
                                

                                // Timestamp Start ~ End 추출
                                StartTimestamp = event_at_0["header"]["nano_timestamp"].get<unsigned long long>();
                                EndTimestamp = event_at_last["header"]["nano_timestamp"].get<unsigned long long>();
                            

                                // Flow Session ID 추출
                                NDR_Flow_Session_Id = event_at_0["header"]["flow_session_id"].get<std::string>();

                            }
                            else
                                throw std::runtime_error("No there key 'packets'");

                        }

                        // Field
                        json Raw_Event;
                        
                        unsigned long long StartTimestamp = 0;
                        unsigned long long EndTimestamp = 0;

                        bool is_inbound = false;
                        std::string protocol_name;
                        std::string ExternalIp;
                        unsigned int ExternalPort;

                        SolutionPlatform platform = SolutionPlatform::NDR;

                        std::string NDR_Flow_Session_Id;

                    std::string Get_SessionId() override
                    {
                        return NDR_Flow_Session_Id;
                    }
                    json Get_Raw_Event() override
                    {
                        return Raw_Event;
                    }


                    
                    bool To_Match__External_ipv4_with_port_and_protocol( 
                        const SolutionPlatform& Caller_Platform,
                        const std::string& arg_ProtocolName, 
                        const std::string& arg_ExternalIp, 
                        const unsigned int& arg_ExternalPort, 
                        const unsigned long long  arg_Log_Start_Timestamp,
                        const unsigned long long  arg_Log_End_Timestamp
                    ) override
                    {
                        // 외부 호출자에서 이것을 호출했을 때 매칭하는 작업을 진행.

                        if( Caller_Platform == SolutionPlatform::NDR )
                            // 충돌!
                            throw std::runtime_error("Cant Match Platform with same");


                        if(Caller_Platform == SolutionPlatform::EDR)
                        {
                            // 무조건 EDR에서의 타임스탬프가 이르다 -> EDR전체 2차원적 로그 Start - End 기준.
                            
                            if( arg_Log_Start_Timestamp < StartTimestamp )
                            {
                                if( arg_ProtocolName == protocol_name && arg_ExternalIp == ExternalIp && arg_ExternalPort )
                                {
                                    return true; // test
                                }
                            }
                            
                        }

                        return false;
                    }
                        
                };

                class EDR_RAW_EVENT : public XDR_Event
                {
                public:
                    // EDR 로그 내의 개별 네트워크 이벤트 정보를 저장하기 위한 구조체
                    struct NetworkConnectionInfo
                    {
                        std::string protocol;
                        std::string external_ip;
                        unsigned int external_port;
                        unsigned long long start_timestamp_nano;
                        unsigned long long end_timestamp_nano;
                    };

                private:
                    

                public:
                    EDR_RAW_EVENT(const json& edr_raw)
                    : Raw_Event(edr_raw)
                    {
                        // EDR 로그의 'events' 배열이 유효한지 확인
                        if (!edr_raw.contains("events") || !edr_raw["events"].is_array() || edr_raw["events"].empty())
                        {
                            throw std::runtime_error("Invalid EDR log: 'events' array is missing or empty.");
                        }

                        const auto& events = edr_raw["events"];

                        // 첫 번째 이벤트에서 Root Session ID 추출 (모든 이벤트가 동일한 Root ID를 가졌다고 가정)
                        if (events.front().contains("root_session_id")) {
                            Root_Session_Id = events.front()["root_session_id"].get<std::string>();
                        } else {
                            throw std::runtime_error("Invalid EDR log: 'root_session_id' is missing.");
                        }
                        
                        // EDR 로그 전체의 시작/끝 시간 및 네트워크 이벤트 정보 추출
                        bool first_timestamp = true;
                        for (const auto& event : events)
                        {
                            // 1. 전체 로그의 시작/끝 타임스탬프 갱신
                            if (event.contains("timestamp_nano")) {
                                unsigned long long current_ts = event["timestamp_nano"].get<unsigned long long>();
                                if (first_timestamp) {
                                    Log_Start_Timestamp = current_ts;
                                    Log_End_Timestamp = current_ts;
                                    first_timestamp = false;
                                } else {
                                    if (current_ts < Log_Start_Timestamp) Log_Start_Timestamp = current_ts;
                                    if (current_ts > Log_End_Timestamp) Log_End_Timestamp = current_ts;
                                }
                            }

                            // 2. 네트워크 이벤트 정보가 있다면 추출하여 저장
                            if (event.contains("network"))
                            {
                                const auto& net_info = event["network"];
                                NetworkConnectionInfo conn_info;

                                conn_info.protocol = net_info.value("protocol", "");
                                
                                // direction에 따라 외부 IP/Port 결정
                                std::string direction = net_info.value("direction", "unknown");
                                if (direction == "out") {
                                    conn_info.external_ip = net_info.value("dst_ip", "");
                                    conn_info.external_port = net_info.value("dst_port", 0);
                                } else { // "in" 또는 "unknown"의 경우 src를 외부로 간주
                                    conn_info.external_ip = net_info.value("src_ip", "");
                                    conn_info.external_port = net_info.value("src_port", 0);
                                }

                                conn_info.start_timestamp_nano = net_info["network_session_first_seen"].get<unsigned long long>();
                                conn_info.end_timestamp_nano = net_info["network_session_last_seen"].get<unsigned long long>();
                                
                                // 유효한 네트워크 정보만 추가
                                if (!conn_info.protocol.empty() && !conn_info.external_ip.empty()) {
                                    network_connections.push_back(conn_info);
                                }
                            }
                        }
                    }

                    std::string Get_SessionId() override
                    {
                        return Root_Session_Id;
                    }

                    json Get_Raw_Event() override
                    {
                        return Raw_Event;
                    }

                    // 이 EDR 이벤트가 가진 네트워크 연결 정보를 외부에서 사용할 수 있도록 getter 제공
                    // (XDR_Log_Combiner가 이 EDR 이벤트를 기준으로 다른 이벤트를 매칭할 때 사용)
                    const std::vector<NetworkConnectionInfo>& GetNetworkConnections() const
                    {
                        return network_connections;
                    }

                    bool To_Match__External_ipv4_with_port_and_protocol( 
                        const SolutionPlatform& Caller_Platform,
                        const std::string& arg_ProtocolName, 
                        const std::string& arg_ExternalIp, 
                        const unsigned int& arg_ExternalPort, 
                        const unsigned long long  arg_Log_Start_Timestamp,
                        const unsigned long long  arg_Log_End_Timestamp
                    ) override
                    {
                        // 같은 플랫폼끼리는 매칭하지 않음
                        if (Caller_Platform == SolutionPlatform::EDR)
                            throw std::runtime_error("Cannot match Platform with same (EDR to EDR)");
                        
                        
                        // 이 EDR 로그에 기록된 모든 네트워크 연결을 순회하며 매칭되는 것이 있는지 확인
                        for (const auto& conn : network_connections)
                        {
                            std::cout << "[EDR] To_Matched ! Called " << std::endl;
                            // 조건 1: 프로토콜, 외부 IP, 외부 포트가 모두 일치하는가?
                            bool is_net_info_matched = (conn.protocol == arg_ProtocolName &&
                                                        conn.external_ip == arg_ExternalIp &&
                                                        conn.external_port == arg_ExternalPort);

                            if (is_net_info_matched)
                            {
                                std::cout << "[EDR] is_net_info_matched TRUE" << std::endl;

                                std::cout << "[NDR Timestamp]" << arg_Log_Start_Timestamp << "~" << arg_Log_End_Timestamp << std::endl;
                                std::cout << "[EDR Timestamp]" << conn.start_timestamp_nano << "~" << conn.end_timestamp_nano << std::endl;

                                // 조건 2: 시간 범위가 겹치는가? (매우 중요)
                                // 두 시간 범위 [A_start, A_end]와 [B_start, B_end]가 겹칠 조건은
                                // (A_start <= B_end) AND (A_end >= B_start) 이다.
                                bool is_time_overlapped = (conn.start_timestamp_nano <= arg_Log_End_Timestamp &&
                                                        conn.end_timestamp_nano >= arg_Log_Start_Timestamp);
                                
                                if (is_time_overlapped)
                                {
                                    // 하나라도 모든 조건이 맞으면 즉시 true 반환
                                    std::cout << "[EDR] Mathed" << std::endl;
                                    return true;
                                }
                            }
                        }

                        // 모든 네트워크 연결을 확인했지만 맞는 것이 없으면 false 반환
                        return false;
                    }


                    // --- Fields ---
                    json Raw_Event;
                    SolutionPlatform platform = SolutionPlatform::EDR;

                    std::string Root_Session_Id; // EDR 로그 전체를 대표하는 세션 ID

                    // EDR 로그 전체의 시작과 끝 타임스탬프
                    unsigned long long Log_Start_Timestamp = 0;
                    unsigned long long Log_End_Timestamp = 0;

                    // EDR 로그 내에 포함된 모든 네트워크 연결 정보
                    std::vector<NetworkConnectionInfo> network_connections;
                };

            }


            namespace XDR_Raw_Log_Combine_System
            {
                class XDR_Log_Combiner
                {
                public:
                    XDR_Log_Combiner() = default;
                    ~XDR_Log_Combiner() { Stop(); }

                    bool Run()
                    {
                        if (is_running)
                            return false;

                        is_running = true;
                        MatchingHub_Matching_Loop_Thread = std::thread(&XDR_Log_Combiner::MatchingHub_Matching_Loop, this);
                        MatchingHub_CleanUp_Loop_Thread = std::thread(&XDR_Log_Combiner::MatchingHub_CleanUp_Loop, this);

                        std::cout << "[XDR_Log_Combiner] Started." << std::endl;
                        return true;
                    }

                    bool Stop()
                    {
                        if (!is_running)
                            return false;

                        is_running = false;
                        RAW_EVENT_QUEUE.stop();

                        if (MatchingHub_Matching_Loop_Thread.joinable())
                            MatchingHub_Matching_Loop_Thread.join();
                        if (MatchingHub_CleanUp_Loop_Thread.joinable())
                            MatchingHub_CleanUp_Loop_Thread.join();
                        
                        std::cout << "[XDR_Log_Combiner] Stopped." << std::endl;
                        return true;
                    }

                    bool AppendingRawLogs(const json& input_raw_log)
                    {
                        std::shared_ptr<Event::XDR_Event> XDR_MATCHER_PARSED = nullptr;

                        // 1. EDR 로그인지 파싱 시도
                        try
                        {
                            XDR_MATCHER_PARSED = std::make_shared<Event::EDR_RAW_EVENT>(input_raw_log);
                            std::cout << "[Parser] Parsed as EDR Event. Session ID: " << XDR_MATCHER_PARSED->Get_SessionId() << std::endl;
                        }
                        catch (...)
                        {
                            // 2. EDR 파싱 실패 시, NDR 로그인지 파싱 시도
                            try
                            {
                                XDR_MATCHER_PARSED = std::make_shared<Event::NDR_RAW_EVENT>(input_raw_log);
                                std::cout << "[Parser] Parsed as NDR Event. Session ID: " << XDR_MATCHER_PARSED->Get_SessionId() << std::endl;
                            }
                            catch (const std::exception& e)
                            {
                                // 두 파싱 모두 실패
                                std::cerr << "[Parser] Failed to parse log. Reason: " << e.what() << std::endl;
                            }
                        }
                        
                        if (!XDR_MATCHER_PARSED)
                            return false;

                        RAW_EVENT_QUEUE.put(std::move(XDR_MATCHER_PARSED));
                        return true;
                    }

                    bool Is_Running() const
                    {
                        return is_running;
                    }

                private:
                    std::map<
                        Event::SolutionPlatform,                 // EDR, NDR 등 플랫폼
                        std::map<
                            std::string,                         // Event Session Id
                            std::shared_ptr<Event::XDR_Event>    // Converted XDR Match Instance
                        >
                    > MatchingHub;

                    std::mutex MatchingHub_MUTEX;
                    std::atomic<bool> is_running = false;
                    
                    XDR::Util::Queue::Queue<std::shared_ptr<Event::XDR_Event>> RAW_EVENT_QUEUE;

                    std::thread MatchingHub_Matching_Loop_Thread;
                    std::thread MatchingHub_CleanUp_Loop_Thread;

                    void MatchingHub_Matching_Loop()
                    {
                        while (is_running)
                        {
                            std::shared_ptr<Event::XDR_Event> Consumed_Event = nullptr;
                            try
                            {
                                Consumed_Event = RAW_EVENT_QUEUE.get();
                                if (Consumed_Event)
                                {
                                    _matching(Consumed_Event);
                                }
                            }
                            catch (const std::exception&)
                            {
                                // Queue Stop Signal
                                return;
                            }
                        }
                    }

                    void MatchingHub_CleanUp_Loop()
                    {
                        while (is_running)
                        {
                            {
                                std::lock_guard<std::mutex> lock(MatchingHub_MUTEX);
                                for (auto& platform_pair : MatchingHub)
                                {
                                    auto& event_map = platform_pair.second;
                                    for (auto it = event_map.begin(); it != event_map.end(); )
                                    {
                                        if (it->second->Is_Timeout())
                                        {
                                            std::cout << "[CleanUp] Timeout event removed. Session ID: " << it->first << std::endl;
                                            it = event_map.erase(it);
                                        }
                                        else
                                        {
                                            ++it;
                                        }
                                    }
                                }
                            }
                            // 5초에 한번씩 체크
                            std::this_thread::sleep_for(std::chrono::seconds(5));
                        }
                    }

                    void _matching(std::shared_ptr<Event::XDR_Event>& new_event)
                    {
                        std::lock_guard<std::mutex> lock(MatchingHub_MUTEX);

                        bool is_matched = false;
                        std::string matched_session_id_to_remove; // 매칭된 상대방 세션 ID
                        Event::SolutionPlatform matched_platform_to_remove; // 매칭된 상대방 플랫폼

                        // dynamic_cast를 사용하여 실제 이벤트 타입을 확인
                        if (auto edr_event = std::dynamic_pointer_cast<Event::EDR_RAW_EVENT>(new_event))
                        {
                            // 새로 들어온 이벤트가 EDR -> 기존 NDR 이벤트들과 매칭 시도
                            auto& ndr_hub = MatchingHub[Event::SolutionPlatform::NDR];
                            for (const auto& ndr_pair : ndr_hub)
                            {
                                auto& ndr_event_ptr = ndr_pair.second;
                                // EDR 이벤트가 가진 모든 네트워크 연결 정보로 NDR 이벤트와 매칭 시도
                                for (const auto& conn_info : edr_event->GetNetworkConnections())
                                {
                                    if (ndr_event_ptr->To_Match__External_ipv4_with_port_and_protocol(
                                        Event::SolutionPlatform::EDR,
                                        conn_info.protocol,
                                        conn_info.external_ip,
                                        conn_info.external_port,
                                        conn_info.start_timestamp_nano,
                                        conn_info.end_timestamp_nano
                                    ))
                                    {
                                        std::cout << "\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" << std::endl;
                                        std::cout << "!! [MATCH FOUND] (EDR arrived) !!" << std::endl;
                                        std::cout << "!! EDR Event: " << edr_event->Get_SessionId() << std::endl;
                                        std::cout << "!! NDR Event: " << ndr_event_ptr->Get_SessionId() << std::endl;
                                        std::cout << "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n" << std::endl;

                                        is_matched = true;
                                        matched_session_id_to_remove = ndr_event_ptr->Get_SessionId();
                                        matched_platform_to_remove = Event::SolutionPlatform::NDR;
                                        break;
                                    }
                                }
                                if (is_matched) break;
                            }
                        }
                        else if (auto ndr_event = std::dynamic_pointer_cast<Event::NDR_RAW_EVENT>(new_event))
                        {
                            // 새로 들어온 이벤트가 NDR -> 기존 EDR 이벤트들과 매칭 시도
                            auto& edr_hub = MatchingHub[Event::SolutionPlatform::EDR];
                            std:: cout << "edr_hub_SIZE: " << edr_hub.size() << std::endl;
                            for (const auto& edr_pair : edr_hub)
                            {
                                auto& edr_event_ptr = edr_pair.second;
                                // EDR 이벤트의 To_Match 함수를 호출. NDR 정보는 ndr_event에서 직접 가져와 인자로 전달
                                if (edr_event_ptr->To_Match__External_ipv4_with_port_and_protocol(
                                    Event::SolutionPlatform::NDR,
                                    ndr_event->protocol_name,
                                    ndr_event->ExternalIp,
                                    ndr_event->ExternalPort,
                                    ndr_event->StartTimestamp,
                                    ndr_event->EndTimestamp
                                ))
                                {
                                    std::cout << "\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" << std::endl;
                                    std::cout << "!! [MATCH FOUND] (NDR arrived) !!" << std::endl;
                                    std::cout << "!! NDR Event: " << ndr_event->Get_SessionId() << std::endl;
                                    std::cout << "!! EDR Event: " << edr_event_ptr->Get_SessionId() << std::endl;
                                    std::cout << "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n" << std::endl;

                                    is_matched = true;
                                    matched_session_id_to_remove = edr_event_ptr->Get_SessionId();
                                    matched_platform_to_remove = Event::SolutionPlatform::EDR;
                                    break;
                                }
                            }
                        }

                        if (is_matched)
                        {
                            // 매칭된 기존 이벤트를 Hub에서 제거
                            MatchingHub[matched_platform_to_remove].erase(matched_session_id_to_remove);
                            // 새로 들어온 이벤트는 Hub에 추가하지 않음 (매칭되었으므로)
                        }
                        else
                        {
                            // 매칭에 실패하면, 새 이벤트를 Hub에 추가
                            if (std::dynamic_pointer_cast<Event::EDR_RAW_EVENT>(new_event))
                            {
                                MatchingHub[Event::SolutionPlatform::EDR][new_event->Get_SessionId()] = new_event;
                                std::cout << "[MatchingHub] EDR Event added. Session ID: " << new_event->Get_SessionId() << std::endl;
                            }
                            else if (std::dynamic_pointer_cast<Event::NDR_RAW_EVENT>(new_event))
                            {
                                MatchingHub[Event::SolutionPlatform::NDR][new_event->Get_SessionId()] = new_event;
                                std::cout << "[MatchingHub] NDR Event added. Session ID: " << new_event->Get_SessionId() << std::endl;
                            }
                        }
                    }
                };
            }
        }
    }
}

#endif