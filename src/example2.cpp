#include "http_server.h"
#include <iostream>
#include <sstream>

const int max_num = 1000000;

struct ServerData{};

struct WorkerData{
    std::vector<bool>seen;
    
    WorkerData(int worker_id, int worker_count, const ServerData&server_data):
        seen(max_num, false){
        (void)worker_id;
        (void)worker_count;
        (void)server_data;
    }
};

int main(){
    io::http::Config config;
    config.port = 8888;
    ServerData server_data;
    io::http::run_with_worker_data<WorkerData>(
        config,
        server_data,
        [](int worker_id, int worker_count, const ServerData&server_data, WorkerData&worker_data, const io::http::Request&req, io::http::Response&res){
            (void)worker_id;
            (void)worker_count;
            (void)server_data;
            std::istringstream in(req.body);
            int num;
            while(in >> num){
                if(num < 0 || num >= max_num)
                    throw std::runtime_error("number out of bounds");
                worker_data.seen[num] = true;
            }
            std::ostringstream out;
            for(int i=0; i<max_num; ++i)
                if(worker_data.seen[i])
                    out << i << ' ';
            res.body = out.str();
            if(!res.body.empty())
                res.body.back() = '\n';
            else
                res.body = "\n";
        },
        []{std::cerr << "Server is running. Hit CTRL+C once for graceful shutdown. Hit CTRL+C a second time to kill the server.\n";}
    );
    std::cerr << "Server was shutdown gracefully\n";
}
