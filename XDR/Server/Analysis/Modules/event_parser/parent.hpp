#ifndef XDR_ANALYSIS_EVENT_PARSER_HPP
#define XDR_ANALYSIS_EVENT_PARSER_HPP

#include "../../../../../util/util.hpp" // nlohmann/json 라이브러리 포함 가정

namespace XDR {
    namespace Server {
        namespace Analysis {
            namespace EventParser {


                namespace GlobalStructs {

                    
                    enum class CyberKillChain {
                        Reconnaissance,     // 정찰 (TA0043)
                        Weaponization,      // 무기화 (TA0042 - Resource Development)
                        Delivery,           // 전달 (TA0001 - Initial Access)
                        Exploitation,       // 취약점 실행 (TA0002 - Execution)
                        Installation,       // 악성코드 설치 (TA0003 - Persistence, TA0005 - Defense Evasion)
                        CommandandControl,  // 컨트롤 (TA0011 - C2)
                        ActionsonObjectives // 공격목표 실행 (TA0010 - Exfiltration, TA0040 - Impact)
                    };

                    struct MitreAttack {
                        std::string tactic_id;
                        std::string technique_id;
                        std::optional<std::string> subtechnique_id;
                        std::vector<std::string> data_sources;

                        // Tactic -> Cyber Kill Chain
                        std::optional< CyberKillChain >  KillChain = std::nullopt;
                    };

                    struct RuleInfo {
                        std::string id;
                        std::string name;
                        std::string description;
                        std::string severity;
                        std::string operational_usage;
                        std::string false_positive;
                        std::vector<std::string> platforms;
                        std::vector<MitreAttack> mitreattacks;
                    };


                    struct Highlight {
                        unsigned long long nano_timestamp;
                        std::string nano_timestamp_iso;
                        
                        RuleInfo rule;

                    };
                }

                namespace GlobalFunctions
                {
                    // Raw_Event_by_Rule to AvgScore
                    std::optional< float > Get_Avg_Risk_Score(const std::vector<GlobalStructs::RuleInfo>& Rules)
                    {
                        if (Rules.empty()) return std::nullopt; // nullopt의 경우 집계 제외

                        float total_score = 0.0f;
                        int count = 0;

                        for (const auto& rule : Rules) {
                            float score = 0.0f;
                            std::string sev = rule.severity;
                            // 소문자 변환 생략 (이미 소문자로 들어온다고 가정)

                            if (sev == "critical") score = 100.0f;
                            else if (sev == "high") score = 70.0f;
                            else if (sev == "medium") score = 30.0f;
                            else if (sev == "low") score = 10.0f;
                            else continue;
                            total_score += score;
                            count++;
                        }

                        if(count == 0)// severity가 오로지 info만 있었던 경우.. 집계제외 
                            return std::nullopt; 

                        return (count > 0) ? (total_score / count) : 0.0f;
                    }

                    // Raw_Event_by_Rule to Highlights
                    std::optional< std::vector<GlobalStructs::Highlight>>Get_Highlight(const std::vector<GlobalStructs::RuleInfo>& Rules, unsigned long long& nano_timestamp, std::string& nano_timestamp_iso)
                    {
                        std::vector<GlobalStructs::Highlight> output;
        
                        // 이벤트 자체에 대한 기본 타임스탬프
                        unsigned long long ts = 0;
                        std::string ts_iso = "";
                        if (!nano_timestamp || nano_timestamp_iso.empty() || Rules.empty() ) return std::nullopt;

                        ts = nano_timestamp;
                        ts_iso = nano_timestamp_iso;

                        // 탐지된 Rule 기반 Highlight 생성
                        for (const auto& rule : Rules) {
                            GlobalStructs::Highlight h;
                            // Rule의 설명을 Highlight로 사용
                            h.rule = rule;
                            h.nano_timestamp = ts;
                            h.nano_timestamp_iso = ts_iso;
                            output.push_back(h);
                        }

                        if(output.empty())
                            // 매핑되지 않는 경우 기본값 (예: Installation으로 처리하거나 예외 처리)
                            return std::nullopt; 
                        else
                            return output;
                    }

                    // Raw_Event to MitreAttack
                    std::optional<std::vector<GlobalStructs::MitreAttack>> Get_MitreAttack(const std::vector<GlobalStructs::RuleInfo>& Rules)
                    {
                        std::vector<GlobalStructs::MitreAttack> output;

                        for(auto& Rule : Rules)
                        {
                            for (const auto& m : Rule.mitreattacks) {
                                output.push_back(m);
                            }
                        }

                        if(output.empty())
                            // 매핑되지 않는 경우 기본값 (예: Installation으로 처리하거나 예외 처리)
                            return std::nullopt; 
                        else
                            return output;
                    }

                    // MITRE_ATTACK to KillChain
                    std::optional< GlobalStructs::CyberKillChain > MitreAttack_Tactic_to_CyberKillChain(const std::string& MitreAttack_Tactic_id) {

                        GlobalStructs::CyberKillChain output;
                        // Reconnaissance (정찰)
                        if (MitreAttack_Tactic_id == "TA0043") 
                            return GlobalStructs::CyberKillChain::Reconnaissance ;
                        
                        // Weaponization (무기화) - Resource Development
                        else if (MitreAttack_Tactic_id == "TA0042")
                           return GlobalStructs::CyberKillChain::Weaponization ;
                        
                        // Delivery (전달) - Initial Access
                        else if (MitreAttack_Tactic_id == "TA0001")
                            return GlobalStructs::CyberKillChain::Delivery ;
                        
                        // Exploitation (취약점 실행) - Execution
                        else if (MitreAttack_Tactic_id == "TA0002")
                            return GlobalStructs::CyberKillChain::Exploitation ;
                        
                        // Installation (설치) - Persistence, Defense Evasion, Privilege Escalation
                        else if (MitreAttack_Tactic_id == "TA0003" || MitreAttack_Tactic_id == "TA0004" || MitreAttack_Tactic_id == "TA0005") 
                            return GlobalStructs::CyberKillChain::Installation ;
                        
                        // Command & Control (C2)
                        else if (MitreAttack_Tactic_id == "TA0011")
                            return GlobalStructs::CyberKillChain::CommandandControl ;
                        
                        // Actions on Objectives (목표 실행) - Exfiltration, Impact, Collection, etc.
                        else if (MitreAttack_Tactic_id == "TA0010" || MitreAttack_Tactic_id == "TA0040" || MitreAttack_Tactic_id == "TA0009" || MitreAttack_Tactic_id == "TA0007") 
                            return GlobalStructs::CyberKillChain::ActionsonObjectives ;
                        else
                            return std::nullopt; 

                    }

                    // Raw-Event to RulesInfo Structs
                    std::optional< std::vector<GlobalStructs::RuleInfo> > Get_RulesInfo(const json& raw_event)
                    {
                        std::vector<GlobalStructs::RuleInfo> output;
                        if (raw_event.contains("threat")) {
                            const auto& threat = raw_event.at("threat");
                            //this->intelligences = threat.value("intelligences", json::array());

                            if (threat.contains("rules") && threat.at("rules").is_array()) {
                                for (const auto& r_item : threat.at("rules")) {
                                    GlobalStructs::RuleInfo r;
                                    r.id = r_item.value("id", "");
                                    r.name = r_item.value("name", "");
                                    r.description = r_item.value("description", "");
                                    r.severity = r_item.value("severity", ""); // "critical", "high", etc.
                                    r.operational_usage = r_item.value("operational_usage", "");
                                    r.false_positive = r_item.value("false_positive", "");

                                    if (r_item.contains("platforms") && r_item.at("platforms").is_array()) {
                                        for (const auto& p : r_item.at("platforms")) r.platforms.push_back(p.get<std::string>());
                                    }

                                    if (r_item.contains("mitreattacks") && r_item.at("mitreattacks").is_array()) {
                                        for (const auto& m_item : r_item.at("mitreattacks")) {
                                            GlobalStructs::MitreAttack ma;
                                            ma.tactic_id = m_item.value("tactic_id", "");
                                            ma.technique_id = m_item.value("technique_id", "");
                                            ma.subtechnique_id = m_item.contains("subtechnique_id") ? 
                                                std::make_optional(m_item.value("subtechnique_id", "")) : std::nullopt;
                                            
                                            if (m_item.contains("data_sources") && m_item.at("data_sources").is_array()) {
                                                for (const auto& ds : m_item.at("data_sources")) ma.data_sources.push_back(ds.get<std::string>());
                                            }


                                            // tactic_id 기반 CyberKillChain 매핑
                                            ma.KillChain = MitreAttack_Tactic_to_CyberKillChain(ma.tactic_id);


                                            r.mitreattacks.push_back(ma);
                                        }
                                    }
                                    output.push_back(r);
                                }
                            }
                        }


                        if(output.empty())
                            return std::nullopt;
                        else
                            return output;
                    }
                }


                /*
                    다양한 솔루션 로그를 하나로 정규화하는 "부모클래스"

                    로그 하나당 이 부모 클래스를 가진다.
                    복수개로 관리하는 경우는 이 외의 로직에서 처리.
                */
               
                class EventParserParent {
                public:
                    EventParserParent(const json& Raw_Event)
                    : OriginalEvent(Raw_Event)
                    {
                        if( auto Rules = GlobalFunctions::Get_RulesInfo(Raw_Event) )
                            this->rules = Rules.value();
                    }
                    virtual ~EventParserParent() = default;

                    // 1. Highlight 반환
                    std::optional< std::vector<GlobalStructs::Highlight> > Get_Highlight()  {
                        return GlobalFunctions::Get_Highlight( this->rules, nano_timestamp, timestamp_nano_iso8601 );
                    }

                    // 2. 심각도 평균 점수 반환
                    std::optional< float > Get_Avg_Risk_Score()  {
                        return GlobalFunctions::Get_Avg_Risk_Score(this->rules);
                    }

                    // 3. 마이터어택 정보 반환
                    std::optional<std::vector<GlobalStructs::MitreAttack>> Get_MitreAttack()  {
                        return GlobalFunctions::Get_MitreAttack(this->rules);
                    }

                protected:
                    virtual bool _parsing(const json& input_siem_log) = 0;

                public:
                    unsigned long long nano_timestamp = 0;
                    std::string timestamp_nano_iso8601 = "";

                    std::string root_session_id = "";

                    std::vector<GlobalStructs::RuleInfo> rules;

                    json OriginalEvent;
                };

                /*
                    솔루션 이벤트 관리 ( 여러 RAW 이벤트를 하나로 관리 하는 부모 클래스)
                */
                class EventParserManager
                {
                    public:

                        bool AppendEvent(std::shared_ptr< EventParserParent > Event)
                        {
                            Events.push_back(
                                std::move(Event)
                            );
                        }

                        float Get_Avg_Risk_Score()
                        {
                            float avg_Risk_score = 0.0f;

                            unsigned int index = 0;
                            for(auto& test : Events)
                            {
                                if( auto score = test->Get_Avg_Risk_Score() )
                                {
                                    avg_Risk_score += score.value();
                                    ++index;
                                }
                            }

                            return ( avg_Risk_score > 0.0f ? ( avg_Risk_score / index ) : 0.0f );
                        }

                        std::vector<GlobalStructs::MitreAttack> Get_MitreAttack()
                        {
                            std::vector<GlobalStructs::MitreAttack> output;

                            for(auto& test : Events)
                            {
                                if(auto mitreattacks = test->Get_MitreAttack())
                                {
                                    for( auto& mitreattack : mitreattacks.value() )
                                    {
                                        output.push_back(mitreattack);
                                    }
                                }
                            }

                            return output;
                        }
                        // Get_TimeHighlights_in_json 으로 마이터어택 JSON 대체됨


                        std::vector<GlobalStructs::Highlight> Get_TimeHighlights()
                        {
                            std::vector<GlobalStructs::Highlight> output;

                            for(auto& test : Events)
                            {
                                if(auto highlights = test->Get_Highlight())
                                {
                                    for( auto& highlight : highlights.value() )
                                    {
                                        output.push_back(highlight);
                                    }
                                }
                            }

                            return output;
                        }
                        json Get_TimeHighlights_in_json()
                        {
                            json output_array = json::array();

                            
                            for(auto& test : Events)
                            {
                                if(auto highlights = test->Get_Highlight())
                                {
                                    for( auto& highlight : highlights.value() )
                                    {
                                        
                                        json MitreAttack_j_array = json::array();
                                        json KillChain_j_array = json::array();
                                        for( auto& MitreAttack : highlight.rule.mitreattacks )
                                        {
                                            MitreAttack_j_array.push_back(
                                                {
                                                    {"tactic_id", MitreAttack.tactic_id},
                                                    {"technique_id", MitreAttack.technique_id},
                                                    {"subtechnique_id", MitreAttack.subtechnique_id},
                                                    {"data_sources", MitreAttack.data_sources}
                                                }
                                            );

                                            KillChain_j_array.push_back(
                                                {
                                                    {"killchain", MitreAttack.KillChain}
                                                }
                                            );

                                            
                                        }
                                        
                                        
                                        output_array.push_back({
                                            {"description", highlight.rule.description},
                                            {"severity", highlight.rule.severity},
                                            {"nanotimestamp", highlight.nano_timestamp},
                                            {"nanotimestamp_iso", highlight.nano_timestamp_iso},
                                            {"false_positive", highlight.rule.false_positive},

                                            {"mitreattack", MitreAttack_j_array},
                                            {"killchain", KillChain_j_array}
                                        });
                                        
                                    }
                                }
                            }

                            return output_array;
                        }

                        std::vector<json> Get_OrignalLogs()
                        {
                            std::vector<json> logs;

                            for(auto& test : Events)
                                logs.push_back(test->OriginalEvent);
                            return logs;
                        }

                        json ToJson()
                        {
                            try
                            {
                                return json::object(
                                    {
                                        {"Timeline", Get_TimeHighlights_in_json()},
                                        {"risk_score", Get_Avg_Risk_Score() },
                                        {"logs", Get_OrignalLogs() }
                                    }
                                );
                            }
                            catch(const std::exception& e)
                            {
                                std::cerr << e.what() << '\n';
                                throw std::runtime_error(e.what());
                            }
                            
                        }

                    protected:
                        std::vector< std::shared_ptr< EventParserParent > > Events;
                };

                namespace Anchor
                {
                    struct InfoBase
                    {
                        unsigned long long nano_timestamp;
                        std::string iso_timestamp;
                    };

                    struct _NETWORKINFO : InfoBase
                    {
                        std::string protocol; // lower protocol name

                        std::string src_mac;
                        std::string dst_mac;

                        std::string src_ip;
                        unsigned int src_port=0;
                        std::string dst_ip;
                        unsigned int dst_port=0;

                        json toJson() const
                        {
                            return json::object({
                                {"protocol", protocol},
                                {"src_mac", src_mac},
                                {"dst_mac", dst_mac},
                                {"src_ip", src_ip},
                                {"src_port", src_port},
                                {"dst_ip", dst_ip},
                                {"dst_port", dst_port}
                            });
                        }
                    };

                    class AnchorManager{
                        public:

                            

                            ~AnchorManager() = default;

                            // Event Collapse (결합 관련한 모든 이벤트를 추가한다.)
                            void CollapseEvent( const std::shared_ptr< EventParserParent >& event )
                            {
                                collpased_events.push_back(event);
                            }

                            json OutputAnchorXDRAnalyzed()
                            {
                                // 1. Sort { Old -> New Timeline }
                                std::sort(
                                    collpased_events.begin(), collpased_events.end(),
                                    [](const std::shared_ptr< EventParserParent >& a, const std::shared_ptr< EventParserParent >& b)
                                    {
                                        return a->nano_timestamp < b->nano_timestamp;
                                    }
                                );


                                EventParserManager EventManager;
                                for ( auto& t : collpased_events)
                                    EventManager.AppendEvent(t);

                                return EventManager.ToJson();

                            }

                            void PrintCollapsedEvent()
                            {
                                std::sort(
                                    collpased_events.begin(), collpased_events.end(),
                                    [](const std::shared_ptr< EventParserParent >& a, const std::shared_ptr< EventParserParent >& b)
                                    {
                                        return a->nano_timestamp < b->nano_timestamp;
                                    }
                                );
                                for ( auto& t : collpased_events)
                                {
                                    std::cout << "time: " << t->nano_timestamp << "\n" << std::endl;
                                    std::cout << "json: " << t->OriginalEvent.dump() << "\n\n" << std::endl; 
                                }
                            }

                            // Anchor Target Ready Methods
                            // 1. Ready Network Info
                            bool Append_Network_Info(const unsigned long long& timestamp, const _NETWORKINFO& network_info)
                            {
                                network_infos[timestamp] = network_info;
                                return true;
                            }

                            // Matching by Sources
                            bool Matching_Network_Info( const std::string& raw_event_root_session_id, const unsigned long long& timestamp, const _NETWORKINFO& network_info)
                            {

                                if(MatchedSourceRootSessionId.find(raw_event_root_session_id) != MatchedSourceRootSessionId.end())
                                {
                                    // 이미 결합된 정보
                                    return true;
                                }

                                for( const auto &[ k_timestamp, v_network_info ] : network_infos )
                                {
                                    //std::cout << "k_t:" << k_timestamp << " - " << "arg_timestamp: " << timestamp << std::endl; 
                                    //if( timestamp >= k_timestamp )
                                    {
                                        std::cout << network_info.toJson() << "\n" << std::endl;
                                        if(_matching_networkinfo(network_info, v_network_info))
                                        {
                                            MatchedSourceRootSessionId[raw_event_root_session_id] = true;
                                            return true;
                                        }
                                    }
                                }
                                return false;
                            }

                            bool is_matched_event(const std::string& raw_event_root_session_id)
                            {
                                return ( MatchedSourceRootSessionId.find(raw_event_root_session_id) != MatchedSourceRootSessionId.end() ) ? true : false;
                            }

                        private:
                            std::vector< std::shared_ptr< EventParserParent > > collpased_events; // not considered timestamp ( 이 요소에 담긴 순서는 뒤죽박죽 )

                            bool _matching_networkinfo( const _NETWORKINFO& source, const _NETWORKINFO& target )
                            {
                                std::cout << "[COMPARE] dst_mac   : " << source.dst_mac 
          << "  <->  " << target.dst_mac << "\n";

std::cout << "[COMPARE] src_mac   : " << source.src_mac 
          << "  <->  " << target.src_mac << "\n";

std::cout << "[COMPARE] src_ip    : " << source.src_ip 
          << "  <->  " << target.src_ip << "\n";

std::cout << "[COMPARE] src_port  : " << source.src_port 
          << "  <->  " << target.src_port << "\n";

std::cout << "[COMPARE] dst_ip    : " << source.dst_ip 
          << "  <->  " << target.dst_ip << "\n";

std::cout << "[COMPARE] dst_port  : " << source.dst_port 
          << "  <->  " << target.dst_port << "\n";

                                if(
                                    source.dst_mac != target.dst_mac ||
                                    source.src_mac != target.src_mac ||
                                    source.src_ip != target.src_ip ||
                                    source.src_port != target.src_port ||
                                    source.dst_ip != target.dst_ip ||
                                    source.dst_port != target.dst_port
                                )
                                    return false;
                                else
                                    return true;
                            }

                            std::map<unsigned long long, _NETWORKINFO> network_infos;
                            std::map<std::string, bool> MatchedSourceRootSessionId; // Matched된 이벤트의 Root 세션 아이디 
                    };
                }
            }
        }
    }
}

#endif