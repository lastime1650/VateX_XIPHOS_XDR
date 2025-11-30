#ifndef XDR_API_SERVER_HPP
#define XDR_API_SERVER_HPP

#include "../../util/util.hpp"

#include "../Server/XDRServer.hpp"

namespace XDR
{
    namespace Server
    {
        namespace API
        {
            class API_SERVER
            {
                public:
                    API_SERVER(const std::string& API_SERVER_IP, const unsigned int API_SERVER_PORT, XDR::Server::XDRServer& XDRBackend)
                    : API_SERVER_IP(API_SERVER_IP), API_SERVER_PORT(API_SERVER_PORT), XDRBackend(XDRBackend)
                    {

                    }
                    ~API_SERVER() = default;

                    bool Run()
                    {
                        if(is_running)
                            return false;
                        is_running = true;

                        // 타임스탬프 기반 모든 이벤트 상관분석
                        /*
                            1. 지정한 범위 내에서 모든 솔루션의 이벤트를 가져와서 분석하는 것.
                            2. 스코어링 및 발생한 위협 분석 및 이벤트를 타임스탬프로 정리
                        */
                        APISvr.Post(
                            "/api/solution/xdr/analysis/timestamp_range",
                            Analysis_TimestampRange
                        );

                        // 특정 솔루션 이벤트 앵커 기반 이벤트 상관분석
                        /*
                            특정 솔루션 이벤트중 하나를 기준 삼고, 그것과 관련한 다른 솔루션 이벤트를 조회하여 이벤트를 결합하고 분석하는 집중형 방식
                            예시)
                                기준: EDR의 어느 프로세스 2차원 JSON구조 로그.
                                    -> "기준"이벤트와 결합할 솔루션 이벤트 리스트
                                        -> 1. NDR의 패킷 세션
                                
                        */
                        APISvr.Post(
                            "/api/solution/xdr/analysis/anchor",
                            Analysis_Anchor
                        );

                        std::cout << "XDR Running" << std::endl;
                        APISvr.listen( API_SERVER_IP, API_SERVER_PORT ); // infinite Blocking
                        return true;
                    }

                    bool Stop()
                    {
                        if(!is_running)
                            return false;
                        is_running = false;
                        APISvr.stop();

                        return true;
                    }

                private:
                    XDR::Server::XDRServer& XDRBackend;

                    std::string API_SERVER_IP;
                    unsigned int API_SERVER_PORT;
                    httplib::Server APISvr;

                    bool is_running = false;


                    // => /api/solution/xdr/analysis/anchor
                    std::function<void(const httplib::Request&, httplib::Response&)> Analysis_Anchor = 
                        [this](const httplib::Request& req, httplib::Response& res)
                        {
                            /*
                                body  ->
                                {
                                    "root_session_id": ....         // required
                                    "size": >= 1000,                // option
                                    "platform": "ndr" or "edr" ...  // required
                                }
                            */
                           std::string root_session_id = "";
                           unsigned long size = 1000;
                           XDR::Util::ToSiem::Security_Event::Platform Platform;

                           try
                           {
                                /* code */
                                json ReqBody = json::parse(req.body);

                                if(!ReqBody.contains("root_session_id"))
                                {
                                    Set_API_FAILED_Output( "no 'root_session_id' key", res );
                                    return;
                                }
                                    

                                root_session_id = ReqBody["root_session_id"].get<std::string>();


                                if(!ReqBody.contains("platform"))
                                {
                                    Set_API_FAILED_Output( "no 'platform' key", res );
                                    return;
                                }
                                    

                                std::string tmp_platform = ReqBody["platform"].get<std::string>();
                                if  ( tmp_platform == "edr" )
                                    Platform = XDR::Util::ToSiem::Security_Event::Platform::edr;
                                else if ( tmp_platform == "ndr" )
                                    Platform = XDR::Util::ToSiem::Security_Event::Platform::ndr;
                                else
                                    {
                                        Set_API_FAILED_Output( "can't understand platform", res );
                                        return;
                                    }


                                if(ReqBody.contains("size"))
                                    size = ReqBody["size"].get<unsigned long>();
                                else
                                    size = 1000;


                                auto output = XDRBackend.Analysis_Anchor.StartAnalysis(
                                    root_session_id,
                                    Platform,
                                    size
                                );
                                if( output.has_value() )
                                {
                                    Set_API_SUCCESS_Output( output.value(), res );
                                }
                                else
                                {
                                    Set_API_FAILED_Output( "Analysis Failed", res );
                                }


                           }
                           catch(const std::exception& e)
                           {
                                std::cerr << e.what() << '\n';
                                Set_API_FAILED_Output( e.what(), res );
                           }
                           
                        };


                    // => /api/solution/xdr/analysis/timestamp_range
                    std::function<void(const httplib::Request&, httplib::Response&)> Analysis_TimestampRange = 
                        [this](const httplib::Request& req, httplib::Response& res)
                        {
                            
                            /*
                                body ->
                                {
                                    "timestamp": {
                                        "nano": {                       // 우선순위 1
                                            "start": int, -> required
                                            "end": int      -> optional
                                        },
                                        "iso8601": {                    // 우선순위 2
                                            "start": str, -> required
                                            "end": str      -> optional
                                        }
                                        
                                    },
                                    "size": 100 // 솔루션 당 최대 가져올 수 있는 이벤트 수
                                }
                            */
                            unsigned long long start_timestamp;
                            unsigned long long end_timestamp = 0;
                            unsigned int size = 1000;

                            auto Timestamp_Range_Json = json::parse( req.body );

                            

                            if(
                                !Timestamp_Range_Json.contains("timestamp") || 
                                !( Timestamp_Range_Json["timestamp"].contains("nano") || Timestamp_Range_Json["timestamp"].contains("iso8601") )
                            )
                            {
                                Set_API_FAILED_Output( "no timestamp or (nano , iso) key", res );
                                return;
                            }

                            size = Timestamp_Range_Json.value("size", 1000);

                            if( Timestamp_Range_Json["timestamp"].contains("nano") )
                            {
                                auto nano_timestamp = Timestamp_Range_Json["timestamp"]["nano"];
                                try
                                {
                                    start_timestamp = nano_timestamp["start"].get<unsigned long long>();

                                    if(nano_timestamp.contains("end"))
                                    {
                                        end_timestamp = nano_timestamp["end"].get<unsigned long long>();
                                    }
                                    else
                                    {
                                        end_timestamp = 0;
                                    }

                                }
                                catch(const std::exception& e)
                                {
                                    Set_API_FAILED_Output( e.what(), res );
                                    return;
                                }
                                
                            }
                            else if( Timestamp_Range_Json["timestamp"].contains("iso8601") )
                            {
                                auto iso_timestamp = Timestamp_Range_Json["timestamp"]["iso8601"];
                                try
                                {
                                    start_timestamp = XDR::Util::timestamp::Iso8601_To_Nano( iso_timestamp["start"].get<std::string>() );

                                    if(iso_timestamp.contains("end"))
                                    {
                                        end_timestamp = XDR::Util::timestamp::Iso8601_To_Nano( iso_timestamp["end"].get<std::string>() );
                                    }
                                    else
                                    {
                                        end_timestamp = 0;
                                    }

                                }
                                catch(const std::exception& e)
                                {
                                    Set_API_FAILED_Output( e.what(), res );
                                    return;
                                }
                            }

                            ///////
                            //std::cout << "start_timestamp: " << start_timestamp << std::endl; 
                            auto Analyzed = XDRBackend.Analysis_TimestampBased.StartAnalysis(start_timestamp, end_timestamp, size);
                            if(!Analyzed.has_value())
                            {
                                Set_API_FAILED_Output( "timestampBased_Analysis Failed", res );
                            }else
                            {
                                Set_API_SUCCESS_Output( Analyzed.value(), res );
                            }
                        };
                    















                    void Set_API_SUCCESS_Output(const json& Output, httplib::Response& res)
                    {

                        json success_output = json::object({
                            {"output", Output},
                            {"status", true}
                        });

                        res.body = success_output.dump();
                        return;
                    }
                    void Set_API_FAILED_Output(const std::string& Fail_Reason, httplib::Response& res)
                    {

                        json failed_output = json::object({
                            {"fail_reason", Fail_Reason},
                            {"output", {}},
                            {"status", false}
                        });

                        res.body = failed_output.dump();
                        return;
                    }
            };
        }
    }
}

#endif