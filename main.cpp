
#include "util/util.hpp"

#include "XDR/Server/XDRServer.hpp"
#include <thread>   // std::this_thread::sleep_for
#include <chrono>   // std::chrono::seconds

#include "XDR/APIServer/APIServer.hpp"
int main()
{
    /*
        XDR
        DataSource -> SIEM

        1) Get ALL Logs ! 
            => timestamp range
            => Anchor based
                -> if Get EDR LOg, extract start - end timestamp and query the other indexes
    */
    XDR::Server::XDRServer XDR_SERVER(
        /*
            VATEX SAPIENTIA SIEM API Connection
        */
        "192.168.1.205",
        10900
    );

    // API 서버
    XDR::Server::API::API_SERVER api("192.168.1.205", 39923, XDR_SERVER);
    api.Run();

    return 0;
}