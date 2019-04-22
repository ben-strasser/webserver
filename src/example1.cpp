#include "http_server.h"
#include <iostream>
#include <sstream>

int main(){
    io::http::Config config;
    config.port = 8888;
    io::http::run(
        config, 
        [](int worker_id, int worker_count, const io::http::Request&req, io::http::Response&res){
            std::ostringstream out;
            out << "Worker "<<worker_id << " of " << worker_count <<" works says hello and starts working on "<<req.resource << "\n";            
            res.body = out.str();
        },
        []{std::cerr << "Server is running. Hit CTRL+C once for graceful shutdown. Hit CTRL+C a second time to kill the server.\n";}
    );
    std::cerr << "Server was shutdown gracefully\n";
}
