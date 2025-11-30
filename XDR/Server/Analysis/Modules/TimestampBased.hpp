#ifndef XDR_TIMESTAMPBASED_HPP
#define XDR_TIMESTAMPBASED_HPP

#include "event_parser/parent.hpp"

#include "event_parser/edr.hpp"
#include "event_parser/ndr.hpp"


#include "../../../../util/util.hpp"





namespace XDR
{
    namespace Server
    {
        namespace Analysis
        {
            class TimestampBased
            {
                public:
                    TimestampBased( XDR::Util::ToSiem::SiemClient& SIEMClient )
                    : SIEMClient(SIEMClient)
                    {}

                    std::optional< json > StartAnalysis(unsigned long long StartTimestamp, unsigned long long EndTimestamp, unsigned int& size)
                    {
                        // SIEM내 모든 이벤트를 {타임스탬프 범위}만큼 수집
                        json Result_Range_Events;

                        // 쿼리
                        if( SIEMClient.Query_Raw_ALL(
                            Result_Range_Events,

                            StartTimestamp,
                            EndTimestamp,
                            size
                        ) )
                        {
                            
                            /*
                                로그 통합처리

                                Result_Range_Events -> 
                                    "여러 솔루션로그를 반환"
                                        => {
                                            "raw": {
                                                // 솔루션 key값 체크 필요
                                                "edr" : {
                                                    "total": int,
                                                    "logs": list[dict] // 0개이상 로그
                                                },
                                                "ndr" : {
                                                    "total": int,
                                                    "logs": list[dict] // 0개이상 로그
                                                },,,
                                            }
                                        }

                            */
                            
                            
                            _timestamp_analyse_start(Result_Range_Events);
                        }

                        return std::nullopt;
                    }

                private:

                    XDR::Util::ToSiem::SiemClient& SIEMClient;


                    json _timestamp_analyse_start(const json& RawEvents)
                    {
                        // raw 키 체크
                        if(!RawEvents.contains("raw"))
                            throw std::runtime_error("not found key raw");
                        
                        // 접근 후 솔루션 이벤트 체크
                        // 오름차순으로 로그가 정렬됨.
                        /*
                            하나씩 꺼내면서 
                            XDR룰 매치 + 인스턴스 생성
                        */
                        XDR::Server::Analysis::EventParser::EventParserManager RawEventManager;
                        
                        for(const auto&[Solution_name, V] : RawEvents["raw"].items() )
                        {
                            unsigned long long total = V["total"].get<unsigned long long>();
                            std::vector<json> logs = V["logs"].get<std::vector<json>>();
                            std::cout << Solution_name << " - len(logs): " << logs.size() << std::endl; 
                            // log 길이체크
                            if( logs.empty() )
                                continue;

                            /*
                                Support 솔루션들

                                + edr
                                + ndr
                            */
                            for(const auto& log : logs)
                            {
                                std::shared_ptr< XDR::Server::Analysis::EventParser::EventParserParent > Event = nullptr;
                                if (Solution_name == "edr")
                                {
                                    Event = std::make_shared< XDR::Server::Analysis::EventParser::RAW_EDR >(log);
                                }
                                else if (Solution_name == "ndr")
                                {
                                    Event = std::make_shared< XDR::Server::Analysis::EventParser::RAW_NDR >(log);
                                }
                                else
                                    continue; // Non-Support

                                RawEventManager.AppendEvent(Event);
                            }

                        }

                        /*
                            XDR 후속 처리 진행
                        */
                        std::cout <<

                        RawEventManager.ToJson()

                        << std::endl;

                        
                       
                        return RawEventManager.ToJson();
                    }

                    
            };
        }
    }
}

#endif