#ifndef XDR_ANCHORBASED_HPP
#define XDR_ANCHORBASED_HPP

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
            class AnchorBased
            {
                public:
                    AnchorBased( XDR::Util::ToSiem::SiemClient& SIEMClient )
                    : SIEMClient(SIEMClient)
                    {}

                    /*
                        앵커 기반 XDr분석은...

                        어느 한 솔루션(EDR또는 NDR등) 에서 수집된 RAW계열 원시 이벤트 "하나"를 선정하고, 해당 관련한 다른 RAW이벤트를 결합하고 분석하는 것이다.
                    */
                    std::optional< json > StartAnalysis(
                        const std::string& raw_event_root_session_id, 
                        const XDR::Util::ToSiem::Security_Event::Platform& Platform, 
                        unsigned int size=10000
                    )
                    {
                        json output;
                        if(
                            SIEMClient.Query_Raw_Event_by_root_session(
                                output,
                                Platform,
                                raw_event_root_session_id,
                                size
                            )
                        )
                        {
                            
                            return _anchor_analysis(output, Platform);
                        }
                        
                        return std::nullopt;
                    }

                private:
                    XDR::Util::ToSiem::SiemClient& SIEMClient;

                    json _anchor_analysis(const json& result, const XDR::Util::ToSiem::Security_Event::Platform& Platform)
                    {
                        XDR::Server::Analysis::EventParser::Anchor::AnchorManager AM;

                        if(Platform == XDR::Util::ToSiem::Security_Event::Platform::edr)
                        {
                            return _anchor_analysis_by_edr(result, AM);
                        }
                        else if (Platform == XDR::Util::ToSiem::Security_Event::Platform::ndr)
                        {
                            /* Preparing ...  */
                        }
                    }

                    json _anchor_analysis_by_edr(const json& edr_result, XDR::Server::Analysis::EventParser::Anchor::AnchorManager& Manager)
                    {
                        
                        auto results = edr_result["logs"].get<std::vector<json>>();
                        if(results.empty())
                            throw std::runtime_error("result logs empty");

                        unsigned long long index = 0;
                        unsigned long long start_timestamp = 0;
                        unsigned long long end_timestamp = 0;

                        for ( auto& log : results  ){

                            auto raw_log = std::make_shared< XDR::Server::Analysis::EventParser::RAW_EDR>(log);
                            /*
                                XDR - Anchor Manager - Append { Network }
                            */
                            if( auto NetworkEvent = raw_log->Get_XDR_ANCHOR_NETWORK_INFO() )
                            {
                                Manager.Append_Network_Info(
                                    raw_log->nano_timestamp,
                                    NetworkEvent.value()
                                );
                                std::cout << "Network 추가된" << std::endl; 
                            }

                            /*
                                XDR - Anchor Manager - Collapse Event <추후 결합 타임라인에 사용>
                            */
                            {
                                Manager.CollapseEvent(std::static_pointer_cast<XDR::Server::Analysis::EventParser::EventParserParent>(raw_log));
                            }


                            if(index == 0)
                                start_timestamp = raw_log->nano_timestamp;
                            else if (index ==  results.size() - 1 )
                                end_timestamp = raw_log->nano_timestamp;

                            ++index;
                        }

                        /*
                            1. EDR 제외 솔루션 로그 검색 
                            (타임스탬프로 1차적 쿼리)
                        */
                        json timestamp_result;
                        _timestamp_query_with_except(
                            timestamp_result,
                            
                            start_timestamp,
                            end_timestamp,
                            XDR::Util::ToSiem::Security_Event::Platform::edr
                        );


                        /*
                            2. 결합 직전, Matching 여부체크
                        */
                        std::map<std::string, std::vector< std::shared_ptr<XDR::Server::Analysis::EventParser::EventParserParent> > > related_events;
                        for (const auto&[solution_name, V] : timestamp_result["raw"].items())
                        {
                            auto logCount = V["total"].get<unsigned long long>();

                            for( const auto& log : V["logs"].get<std::vector<json>>() )
                            {

                                std::shared_ptr<XDR::Server::Analysis::EventParser::EventParserParent> ParentRaw = nullptr;

                                if( solution_name == "ndr" )
                                {
                                    auto raw_log = std::make_shared< XDR::Server::Analysis::EventParser::RAW_NDR>(log);

                                    if( auto NetworkEvent = raw_log->Get_XDR_ANCHOR_NETWORK_INFO() )
                                    {
                                        if( Manager.Matching_Network_Info(
                                            raw_log->root_session_id,
                                            raw_log->nano_timestamp,
                                            NetworkEvent.value()
                                        ) )
                                        {
                                            std::cout << "Matched" << std::endl;
                                            // 매칭기록은 manager에서 기록 // 
                                        }
                                    }

                                    
                                    ParentRaw = raw_log;
                                }

                                if(ParentRaw)
                                    related_events[ParentRaw->root_session_id].push_back(std::move( ParentRaw ));
                            }
                        }


                        /*
                            3. 결합.
                        */
                        
                        for( const auto&[RootSessionId, V] : related_events )
                        {
                            if( Manager.is_matched_event(RootSessionId) )
                            {
                                for (auto& rawevent : V)
                                    Manager.CollapseEvent(rawevent);
                            }
                        }

                        
                        std::cout << Manager.OutputAnchorXDRAnalyzed().dump() << std::endl;


                        return Manager.OutputAnchorXDRAnalyzed();
                    }

                    // Except timestamp Query
                    /*
                        1) 인자에 제공된 Platform을 제외하여 모든 raw 계열 솔루션 이벤트를 타임스탬프내 조회
                    */
                    bool _timestamp_query_with_except( 
                        json& output,

                        const unsigned long long& start_time, 
                        const unsigned long long& end_time,  
                        const XDR::Util::ToSiem::Security_Event::Platform& except_Platform,
                        const unsigned long long& size = 1000
                        
                    )
                    {
                        /*
                            #################################
                            std::cout 
                            << "start: " << start_time 
                            << "\nend: " << end_time
                            << std::endl;
                            #################################
                            #################################
                            start: 1763563075677665700
                            end: 1763563079635828700
                            #################################
                        */
                        


                        // 1763563078474446000
                        auto is_success = SIEMClient.Query_Raw_ALL(
                            output,
                            start_time,
                            0,
                            size,
                            except_Platform
                        );
                        if(!is_success)
                            return false;
                        else
                            return true;
                    }
            };
        }
    }
}

#endif