#include "http_server.h"

#include <exception>
#include <sstream>
#include <iostream>
using namespace std;


struct ServerData{
    int bar;
};

struct WorkerData{
    int foo;

    WorkerData(int worker_id, int worker_count, const ServerData&){
        cout << worker_id << " of "<< worker_count << " setup" << endl;
        foo = -worker_id;
    }

};

void Handler1(int worker_id, int worker_count, const io::http::Request&in, io::http::Response&out){
    std::ostringstream s;
    s << "Worker "<< worker_id << " of "<<worker_count << " says hello and gets to work on "<< in.resource;
    out.body = s.str();
}

void Handler2(int worker_id, int worker_count, const ServerData&sd, WorkerData&wd, const io::http::Request&in, io::http::Response&out){
    std::ostringstream s;
    s << "Worker "<< worker_id << " of "<<worker_count << " says hello and gets to work on "<< in.resource << " " << wd.foo << " " << sd.bar;
    out.body = s.str();
}

int main(){
        try{
                io::http::Config config;
                config.port = 8888;

                io::http::run(config, &Handler1, []{cout << "Server1 running"<<endl;});
                
                ServerData sd;

                (void)sd;

                sd.bar = 42;

                io::http::run_with_worker_data<WorkerData>(config, sd, &Handler2, []{cout << "Server2 running"<<endl;});

                cout << "Server exited" << endl;
        }catch(std::exception&err){
               cerr << err.what() << endl;
        }

        return 0;
}
