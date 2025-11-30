#ifndef VATEX_SPIENTIA_SIEM_HPP
#define VATEX_SPIENTIA_SIEM_HPP

#include <fmt/format.h>
#include "../httplib.h"
#include "../json.hpp"
#include "../Timestamp/timestamp.hpp"

namespace XDR
{
    namespace Util
    {
        namespace ToSiem
        {

            namespace Security_Event
            {

                // 위협 또는 보안 이벤트 발생 메이커 추적
                enum Event_detected_method
                {
                    rule,
                    machine_learning,
                    deep_learning,
                    intelligence
                };

                // 위협 또는 보안 이벤트 카테고리 (광범위)
                enum Event_Topic
                {

                };

                enum Platform
                {
                    unknown,
                    edr,
                    ndr
                };

                enum Severity
                {
                    info=1,
                    low,
                    medium,
                    high,
                    critical
                };
            }

            constexpr char* Security_Threat_URL = "/api/solution/siem/event/push/security-threat";
            constexpr char* RAW_ALL_URL = "/api/solution/siem/event/query/timestamp-range/raw-all";

            constexpr char* Query_EDR_by_Timestamp_URL = "/api/solution/siem/event/query/timestamp-range/raw-edr/event";
            constexpr char* Query_NDR_by_Timestamp_URL = "/api/solution/siem/event/query/timestamp-range/raw-ndr/event";

            // root_session_id기반 특정 솔루션 조회
            constexpr char* Query_EDR_by_root_session_id_URL = "/api/solution/siem/event/query/raw-edr/root_session";
            constexpr char* Query_NDR_by_root_session_id_URL = "/api/solution/siem/event/query/raw-ndr/root_session";

            class SiemClient
            {
                public:
                    SiemClient(
                        std::string server_ip = "127.0.0.1", // same endpoint
                        unsigned int server_port = 10302
                    ): Requester(server_ip, server_port)
                    {}
                    ~SiemClient() = default;

                    // 1. 보안 이벤트 ( EDR: Intelligence, Rule, ML 3가지의 정규화된 SIEM 결과 전달.)
                    bool Send_Security_Event(
                        const std::string& sender_platform,           // 이벤트 전송한 플랫폼 
                        const std::string& severity,                  // 심각도
                        const std::string& description,                     // 이벤트 이유
                        const std::string& response_description,             // 오탐 방지용 예외형 문구
                        const std::string& category,                // 이벤트 카테고리


                        const std::string& detected_method,         // 이벤트 탐지 방법/원인 경로
                        const unsigned long long& timestamp_nano    // 당시 타임스탬프
                    )
                    {
                        nlohmann::json PushEvent = {
                            {"platform", sender_platform },
                            {"description", description },
                            {"detected_method", detected_method },
                            {"response_description", response_description },
                            {"severity", severity },
                            {"category", category},
                            
                            {"timestamp_nano", timestamp_nano },
                            {"timestamp_nano_iso8601", XDR::Util::timestamp::To_Nano_Iso8601(timestamp_nano) }
                        };
                        return _sendPost(Security_Threat_URL, PushEvent);
                    }

                    // 2. Query timestamp 이벤트 
                    bool Query_Raw_ALL(
                        nlohmann::json& output,
                        unsigned long long start_nanotimestamp,
                        unsigned long long end_nanotimestamp = 0,
                        unsigned long long size = 100,
                        Security_Event::Platform except_solution = Security_Event::Platform::unknown // 해당 솔루션은 제외하고 모두 가져오기
                    )
                    {


                        // Parameter
                        std::multimap<std::string, std::string> Parms;
                        Parms.emplace("start_nano_timestamp", std::to_string(start_nanotimestamp));
                        if(end_nanotimestamp) Parms.emplace("end_nano_timestamp", std::to_string(end_nanotimestamp));
                        if(size) Parms.emplace("size",  std::to_string(size) );
                        

                        std::string output_res;
                        if(
                            _get(
                                RAW_ALL_URL,
                                Parms,
                                &output_res
                            )
                        )
                        {
                            auto response_json = nlohmann::json::parse( output_res );
                            if(!response_json.contains("status") || !response_json.contains("output") || !response_json["status"].get<bool>() )
                                return false;

                            // detail checking keys!!
                            /*
                                example
                                {
                                    "status": bool,
                                    "output": {
                                        "raw": {
                                            "솔루션 이름.. " : {
                                                "total": integer,
                                                "logs": std::vector<json> 
                                            }
                                        }
                                    }
                                }
                            */
                            if( !response_json["output"].contains("raw") )
                                return false;

                            switch (except_solution)
                            {
                                case Security_Event::Platform::edr:
                                {
                                    if( response_json["output"]["raw"].contains("edr") )
                                    {
                                        response_json["output"]["raw"].erase("edr");
                                    }
                                    break;
                                }
                                case Security_Event::Platform::ndr:
                                {
                                    if( response_json["output"]["raw"].contains("ndr") )
                                    {
                                        response_json["output"]["raw"].erase("ndr");
                                    }
                                    break;
                                }
                                
                            }

                            //std::cout << response_json.dump() << std::endl; 
                            output = response_json["output"];
                            
                            return true;
                        }
                        else
                            return false;
                    }

                    bool Query_EDR_by_Timestamp(
                        json& output,
                        unsigned long long start_nanotimestamp,
                        unsigned long long end_nanotimestamp = 0,
                        unsigned long long size = 1000
                    )
                    {
                        std::multimap<std::string, std::string> Parms;
                        Parms.emplace("start_nano_timestamp", std::to_string(start_nanotimestamp));
                        if(end_nanotimestamp) Parms.emplace("end_nano_timestamp", std::to_string(end_nanotimestamp));
                        if(size) Parms.emplace("size",  std::to_string(size) );

                        std::string output_res;
                        if(
                            _get(
                                Query_EDR_by_Timestamp_URL,
                                Parms,
                                &output_res
                            )
                        ){
                            auto response_json = nlohmann::json::parse( output_res );
                            if(!response_json.contains("status") || !response_json.contains("output") || !response_json["status"].get<bool>() )
                                return false;

                            output = response_json["output"];
                            return true;
                        }
                        else
                            return false;
                        
                    }

                    bool Query_NDR_by_Timestamp(
                        json& output,
                        
                        unsigned long long start_nanotimestamp,
                        unsigned long long end_nanotimestamp = 0,
                        unsigned long long size = 1000
                    )
                    {
                        std::multimap<std::string, std::string> Parms;
                        Parms.emplace("start_nano_timestamp", std::to_string(start_nanotimestamp));
                        Parms.emplace("end_nano_timestamp", std::to_string(end_nanotimestamp));
                        if(size) Parms.emplace("size",  std::to_string(size) );

                        std::string output_res;
                        if(
                            _get(
                                Query_NDR_by_Timestamp_URL,
                                Parms,
                                &output_res
                            )
                        ){
                            auto response_json = nlohmann::json::parse( output_res );
                            if(!response_json.contains("status") || !response_json.contains("output") || !response_json["status"].get<bool>() )
                                return false;

                            output = response_json["output"];
                            return true;
                        }
                        else
                            return false;
                        
                    }

                    bool Query_Raw_Event_by_root_session(
                        json& output,
                        const Security_Event::Platform& SolutionPlatform,
                        const std::string root_session_id,
                        unsigned long long size = 100
                    )
                    {
                        // Parameter
                        std::multimap<std::string, std::string> Parms;
                        Parms.emplace( "root_session_id", root_session_id );
                        Parms.emplace( "size", std::to_string(size) );

                        std::string URL_by_Platform = "";
                        if( SolutionPlatform ==  Security_Event::Platform::edr )
                            URL_by_Platform = "/api/solution/siem/event/query/raw-edr/root_session";
                        else if ( SolutionPlatform ==  Security_Event::Platform::ndr )
                            URL_by_Platform = "/api/solution/siem/event/query/raw-edr/root_session";
                        else
                            throw std::runtime_error( "Platform not found" );

                        std::string output_res;
                        if(
                            _get(
                                URL_by_Platform,
                                Parms,
                                &output_res
                            )
                        )
                        {
                            auto response_json = nlohmann::json::parse( output_res );
                            if(!response_json.contains("status") || !response_json.contains("output") || !response_json["status"].get<bool>() )
                                return false;

                            output = response_json["output"];
                            return true;
                        }
                        else
                            return false;
                    }

                private:
                    std::string server_ip;
                    unsigned int server_port;

                    httplib::Client Requester;


                    // get
                    bool _get(const std::string& Path, const std::multimap<std::string, std::string>& Parameters, std::string* output)
                    {
                        httplib::Headers headers;

                        auto res = Requester.Get(
                            Path,
                            Parameters,
                            headers
                        );
                        if(!res || res->status != 200)
                            return false;
                            
                        if(output)
                            *output = res->body;
                        return true;
                    }

                    // send post
                    template <typename T>
                    bool _sendPost(const std::string& Path, const T& body)
                    {
                        std::string BODY;
                        if constexpr( std::is_same_v<T, nlohmann::json> )
                        {
                            BODY = body.dump();
                        }
                        else if constexpr( std::is_same_v<T, std::string> )
                        {
                            BODY = body;
                        }

                        auto response = Requester.Post(
                            Path,
                            BODY,
                            "application/json"
                        );

                        if(!response || response->status != 200)
                            return false;
                        


                        return true;
                    }
            };
        }
    }
}

#endif