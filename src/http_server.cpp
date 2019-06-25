#include "http_server.h"
#include <utility>
#include <system_error>
#include <atomic>
#include <thread>
#include <exception>
#include <algorithm>
#include <condition_variable>
#include <mutex>
#include <chrono>

#include <string.h>
#include <assert.h>

#include <unistd.h>
#include <signal.h>
#include <netinet/in.h>

#ifdef GENERATE_TEST_CASES
//#define CATCH_CONFIG_MAIN
#include "catch.hpp"
#endif

namespace io{
    namespace http{
        Config::Config(){
            port = 8888;
            worker_count = std::thread::hardware_concurrency();
            install_int_signal_handler = true;
            max_request_body_size = 1<<23;
            max_request_resource_size = 1<<14;
            timeout_in_seconds = 10;
            print_exception_message_in_answer = true;
        }

        namespace{
            class SyncSocketSet{
            public:
                SyncSocketSet()noexcept;
                ~SyncSocketSet()noexcept;

                SyncSocketSet(const SyncSocketSet&)=delete;
                SyncSocketSet&operator=(const SyncSocketSet&)=delete;

                bool blocking_add(int socket)noexcept;
                void finish()noexcept;
                int blocking_remove()noexcept;

                static const int set_size = 8;
            private:
                std::atomic<int> set[set_size];
                std::atomic<bool> kill_flag;

                std::condition_variable cv_socket_added, cv_socket_removed;
                std::mutex m_socket_added, m_socket_removed;
            };

            static int next(int index)noexcept{
                ++index;
                if(index == SyncSocketSet::set_size)
                    return 0;
                else
                    return index;
            }

            SyncSocketSet::SyncSocketSet()noexcept{
                for(int i=0; i<set_size; ++i)
                    set[i].store(-1);
                kill_flag.store(false);
            }

            SyncSocketSet::~SyncSocketSet()noexcept{
                for(int i=0; i<set_size; ++i)
                    if(set[i] != -1){
                        int s = set[i].load();
                        shutdown(s, SHUT_RDWR);
                        close(s);
                    }
            }

            bool SyncSocketSet::blocking_add(int socket)noexcept{
                assert(socket >= 0);

                if(kill_flag.load())
                    return false;

                // start_index is used spread out values throughout the set to avoid
                // some old values staying in the set forever while new elements
                // being removed with higher priority.
                //
                // The mangled socket is used as drop in for a somewhat random
                // variable.
                int start_index = (socket & 7) ^ ((socket>>3) & 7);

                int i = start_index;
                for(;;){
                    if(set[i] == -1){
                        int expected = -1;
                        if(set[i].compare_exchange_weak(expected, socket)){
                            cv_socket_added.notify_one();
                            return true;
                        }
                    }
                    i = next(i);

                    if(i == start_index){
                        std::unique_lock<std::mutex> lock(m_socket_removed);
                        cv_socket_removed.wait_for(lock, std::chrono::milliseconds(100));
                    }
                }
            }

            int SyncSocketSet::blocking_remove()noexcept{
                int i = 0;
                for(;;){
                    int ret = set[i];
                    if(ret != -1){
                        if(set[i].compare_exchange_weak(ret, -1)){
                            cv_socket_removed.notify_one();
                            return ret;
                        }
                    }
                    i = next(i);

                    if(i == 0){
                        if(kill_flag.load()){
                            return -1;
                        }
                        {
                            std::unique_lock<std::mutex> lock(m_socket_added);
                            cv_socket_added.wait_for(lock, std::chrono::milliseconds(100));
                        }
                    }
                }
            }

            void SyncSocketSet::finish()noexcept{
                kill_flag.store(true);
                cv_socket_added.notify_one();
            }

            #ifdef GENERATE_TEST_CASES

            TEST_CASE("many_producer", "[socket_sync_set]"){
                const int max_integer = 1000000;
                const int thread_count = 1000;
                SyncSocketSet s;
                for(int i=0; i<thread_count; ++i){

                    std::thread([i, &s]{
                        for(int j=i; j<max_integer; j+=thread_count)
                            REQUIRE(s.blocking_add(j) == true);
                    }).detach();
                }
                std::vector<bool>seen(max_integer, false);
                int received_count = 0;
                while(received_count != max_integer){
                    int x = s.blocking_remove();
                    REQUIRE(x != -1);
                    REQUIRE(x < max_integer);
                    REQUIRE(seen[x] == false);
                    seen[x] = true;
                    ++received_count;
                }
                s.finish();
                REQUIRE(s.blocking_remove() == -1);
            }

            TEST_CASE("many_consumer", "[socket_sync_set]"){
                const int max_integer = 1000000;
                const int thread_count = 1000;
                SyncSocketSet s;

                std::vector<bool>seen(max_integer, false);
                std::mutex seen_mutex;

                std::vector<std::thread>thread_list(thread_count);
                for(int i=0; i<thread_count; ++i){
                    thread_list[i] = std::thread([&s, &seen, &seen_mutex]{
                        int x;
                        while(x = s.blocking_remove(), x != -1){
                            std::unique_lock<std::mutex>lock(seen_mutex);
                            REQUIRE(seen[x] == false);
                            seen[x] = true;
                        }
                    });
                }

                for(int i=0; i<max_integer; ++i)
                    REQUIRE(s.blocking_add(i) == true);

                s.finish();
                REQUIRE(s.blocking_add(42) == false);

                for(int i=0; i<thread_count; ++i)
                    thread_list[i].join();

                for(int i=0; i<max_integer; ++i)
                    REQUIRE(seen[i] == true);
            }


            #endif

            template<class F>
            struct Finally{
                F func;
                ~Finally(){
                    func();
                }
            };

            template<class F>
            Finally<F>finally(F f){
                return {std::move(f)};
            }

            std::atomic<bool> sigint_received(false);
            int sigint_replaced = 0;
            struct sigaction old_sigaction;

            void sigint_handler(int sig)noexcept{
                if(sig == SIGINT){
                    sigint_received.store(true);
                    sigaction(SIGINT, &old_sigaction, nullptr);
                }
            }

            char* format_unsigned_int_into(char*s, int n){
                if(n == 0){
                    *s++ = '0';
                }else{
                    char*b = s;
                    while(n != 0){
                        *s++ = n%10 + '0';
                        n /= 10;
                    }
                    std::reverse(b, s);
                }
                return s;
            }

            bool is_digit(char c){
                return '0' <= c && c <= '9';
            }

            bool is_space(char c){
                return c == ' ' || c == '\t';
            }

            bool parse_unsigned_int(const char*begin, const char*end, int*out){
                if(begin == end)
                    return false;
                int n = 0;
                while(begin != end){
                    if(!is_digit(*begin))
                        return false;
                    n *= 10;
                    n += *begin - '0';
                    ++begin;
                }
                *out = n;
                return true;
            }

            static char to_upper(char c){
                if('a'<= c && c <= 'z')
                    return c-'a'+'A';
                else
                    return c;
            }

            #ifdef GENERATE_TEST_CASES

            TEST_CASE("format_unsigned_int_into", "[int_formating]"){

                #define MY_TEST(STR, INT)\
                {\
                    char buf[100] = {0};\
                    char*ret = format_unsigned_int_into(buf, INT);\
                    REQUIRE(!strcmp(STR,buf));\
                    REQUIRE(*ret == 0);\
                    if(buf != ret)\
                        REQUIRE(*(ret-1) != 0);\
                    else\
                        REQUIRE(buf != ret);\
                }

                MY_TEST("0", 0);
                MY_TEST("1", 1);
                MY_TEST("12", 12);
                MY_TEST("21", 21);
                MY_TEST("123", 123);
                MY_TEST("9", 9);
                MY_TEST("99", 99);
                MY_TEST("999", 999);
                MY_TEST("9999", 9999);
                MY_TEST("10", 10);
                MY_TEST("100", 100);
                MY_TEST("1000", 1000);

                #undef MY_TEST
            }

            TEST_CASE("parse_unsigned_int", "[int_formating]"){

                #define MY_FAIL(STR)\
                {\
                    char str[] = STR;\
                    int out;\
                    bool ok = parse_unsigned_int(str, str+sizeof(str)-1, &out);\
                    REQUIRE(!ok);\
                }

                #define MY_PASS(STR, val)\
                {\
                    char str[] = STR;\
                    int out;\
                    bool ok = parse_unsigned_int(str, str+sizeof(str)-1, &out);\
                    REQUIRE(ok);\
                    REQUIRE(out == val);\
                }

                MY_FAIL("");
                MY_FAIL("A");
                MY_FAIL("42A");
                MY_FAIL("A42");
                MY_FAIL("4 2");

                MY_PASS("0", 0);
                MY_PASS("1", 1);
                MY_PASS("42", 42);
                MY_PASS("123", 123);
                MY_PASS("123789", 123789);

                #undef MY_FAIL
                #undef MY_PASS
            }

            #endif

            class HTTPRequestHeaderParser{
                std::string*resource;
                int max_request_resource_size;

                const char*error_msg;
                enum class State{
                    parse_verb,
                    parse_resource,
                    parse_protocol_version,
                    parse_header_line,
                    parse_body
                };
                State state;

                const static int max_buffer_size = 1<<11;
                char buffer[max_buffer_size];
                int buffer_size;



                bool is_uppercase_string_in_buffer(const char*s)noexcept{
                    for(int i=0; i<buffer_size; ++i){
                        if(*s == 0)
                            return false;
                        if(*s != to_upper(buffer[i]))
                            return false;
                        ++s;
                    }
                    return *s == 0;
                }

                bool does_buffer_start_with_uppercase_string(const char*s)noexcept{
                    for(int i=0; i<buffer_size; ++i){
                        if(*s == 0)
                            return true;
                        if(*s != to_upper(buffer[i]))
                            return false;
                        ++s;
                    }
                    return false;
                }

                int body_size;

            public:

                HTTPRequestHeaderParser(std::string*resource, int max_request_resource_size)noexcept:
                    resource(resource), max_request_resource_size(max_request_resource_size), error_msg(nullptr), state(State::parse_verb), buffer_size(0), body_size(0){
                    resource->clear();
                }

                const char*get_error()const noexcept {
                    return error_msg;
                }

                bool is_header_complete()const noexcept {
                    return state == State::parse_body;
                }

                int get_body_size()const noexcept{
                    return body_size;
                }

                void put(char c)noexcept{
                    assert(error_msg == nullptr);
                    switch(state){
                        case State::parse_verb:
                            if(c == ' '){
                                if(!is_uppercase_string_in_buffer("GET") && !is_uppercase_string_in_buffer("POST")){
                                    error_msg = "Only GET and POST supported";
                                }else{
                                    state = State::parse_resource;
                                }
                            }else{
                                if(buffer_size == max_buffer_size){
                                    error_msg = "HTTP verb too long";
                                }else{
                                    buffer[buffer_size++] = c;
                                }
                            }
                            break;
                        case State::parse_resource:
                            if(c == ' '){
                                buffer_size = 0;
                                state = State::parse_protocol_version;
                            }else{
                                if((int)resource->size() == max_request_resource_size){
                                    error_msg = "HTTP request resource larger than allowed";
                                }else{
                                    resource->push_back(c);
                                }
                            }
                            break;
                        case State::parse_protocol_version:
                            if(c == '\n'){
                                if(buffer_size != 0)
                                    if(buffer[buffer_size-1] == '\r')
                                        --buffer_size;

                                if(!is_uppercase_string_in_buffer("HTTP/1.1") && !is_uppercase_string_in_buffer("HTTP/1.0")){
                                    error_msg = "Only HTTP 1.1 and HTTP 1.0 supported";
                                }else{
                                    state = State::parse_header_line;
                                    buffer_size = 0;
                                }
                            }else{
                                if(buffer_size == max_buffer_size){
                                    error_msg = "HTTP protocol version too long";
                                }else{
                                    buffer[buffer_size++] = c;
                                }
                            }
                            break;
                        case State::parse_header_line:
                            if(c == '\n'){
                                if(buffer_size != 0)
                                    if(buffer[buffer_size-1] == '\r')
                                        --buffer_size;

                                if(buffer_size == 0){
                                    state = State::parse_body;
                                    break;
                                }

                                char content_length[] = "CONTENT-LENGTH";
                                if(does_buffer_start_with_uppercase_string(content_length)){
                                    int begin = sizeof(content_length)-1;
                                    int end = buffer_size;

                                    while(begin != end && is_space(buffer[begin]))
                                        ++begin;
                                    while(begin != end && is_space(buffer[end-1]))
                                        --end;
                                    if(begin == end || buffer[begin] != ':'){
                                        error_msg = "Colon missing after content-length in header";
                                    }else{
                                        ++begin;
                                        while(begin != end && is_space(buffer[begin]))
                                            ++begin;
                                        if(!parse_unsigned_int(buffer+begin, buffer+end, &body_size)){
                                            error_msg = "Cannot parse number in content-length header";
                                        }
                                    }
                                }

                                buffer_size = 0;
                            }else{
                                if(buffer_size != max_buffer_size){
                                    buffer[buffer_size++] = c;
                                }
                            }
                            break;
                        case State::parse_body:
                        default:
                            assert(false);
                    }
                }
            };

            #ifdef GENERATE_TEST_CASES
            TEST_CASE("HTTPRequestHeaderParser", "[http_header_request_parse]"){

                #define MY_PASS(REQ, RES, MAX_RES, LEN)\
                {\
                    std::string resource = "foobar";\
                    HTTPRequestHeaderParser parser(&resource, MAX_RES);\
                    char request[] = REQ;\
                    int index = 0;\
                    while(!parser.is_header_complete()){\
                        REQUIRE(request[index]!=0);\
                        parser.put(request[index]);\
                        ++index;\
                        REQUIRE(parser.get_error() == nullptr);\
                    }\
                    REQUIRE(resource == RES);\
                    REQUIRE(parser.get_body_size() == LEN);\
                    REQUIRE(index == sizeof(request)-1);\
                }

                MY_PASS("GET /foo HTTP/1.1\r\n\r\n", "/foo", 10, 0);
                MY_PASS("GeT / HtTp/1.1\r\n\r\n", "/", 100, 0);
                MY_PASS("post / HtTp/1.0\r\n\r\n", "/", 42, 0);
                MY_PASS("post / HtTp/1.0\r\n\n", "/", 42, 0);
                MY_PASS("post / HtTp/1.0\r\nbla: foo\r\n\r\n", "/", 42, 0);
                MY_PASS("post / HtTp/1.0\r\ncontent-length:  43\r\n bla: foo\r\n\r\n", "/", 42, 43);
                MY_PASS("post / HtTp/1.0\r\ncontent-Length:  0  \r\n bla: foo\n\n", "/", 42, 0);

                MY_PASS("post / HtTp/1.0\r\ncontent-Length  :  123  \n bla: foo\r\n\r\n", "/", 42, 123);

                #define MY_FAIL(REQ, MAX_RES)\
                {\
                    std::string resource = "foobar";\
                    HTTPRequestHeaderParser parser(&resource, MAX_RES);\
                    char request[] = REQ;\
                    int index = 0;\
                    bool ok = true;\
                    while(!parser.is_header_complete()){\
                        REQUIRE(request[index]!=0);\
                        parser.put(request[index]);\
                        ++index;\
                        if(parser.get_error() != nullptr){\
                            ok = false;\
                            break;\
                        }\
                    }\
                    REQUIRE(!ok);\
                }

                MY_PASS("GET /foo HTTP/1.1\r\n\r\n", "/foo", 4, 0);
                MY_FAIL("GET /foo HTTP/1.1\r\n\r\n", 3);

                MY_FAIL("GET /fooHTTP/1.1\r\n\r\n", 10);
                MY_FAIL("PEAK /foo HTTP/1.1\r\n\r\n", 10);

                MY_FAIL("GET /foo  HTTP/1.1\r\n\r\n", 100);

                #undef MY_PASS
                #undef MY_FAIL

            }
            #endif

            class HeaderFormatter{
            private:
                static const int max_msg_size = 1<<12;
                char msg[max_msg_size];
                int msg_size;
            public:
                HeaderFormatter():msg_size(0){}

                void append_cstr(const char*str)noexcept{
                    append_cstr(str, strlen(str));
                }

                void append_cstr(const char*str, int len)noexcept{
                    int remaining_space = max_msg_size - msg_size;
                    if(len > remaining_space)
                        len = remaining_space;
                    memcpy(msg + msg_size, str, len);
                    msg_size += len;
                }

                void append_unsigned_int(int i)noexcept{
                    msg_size = format_unsigned_int_into(msg+msg_size, i)-msg;
                }

                void append_str(const std::string&str)noexcept{
                    append_cstr(&str[0], str.size());
                }

                void append_char(char c)noexcept{
                    if(msg_size != max_msg_size)
                        msg[msg_size++] = c;
                }

                const char*begin()const noexcept{
                    return msg;
                }

                const char*end()const noexcept{
                    return begin() + size();
                }

                int size()const noexcept{
                    return msg_size;
                }
            };

            bool write_all(int conn_socket, const char*begin, const char*end)noexcept{
                while(begin != end){
                    int bytes_written = send(conn_socket, begin, end-begin, MSG_NOSIGNAL);
                    if(bytes_written < 0)
                        return false;
                    begin += bytes_written;
                }
                return true;
            }

            void answer_with_bad_request(int conn_socket)noexcept{
                char msg[] = "HTTP/1.0 400 Bad request\r\n";
                write_all(conn_socket, msg, msg + sizeof(msg)-1);
            };

            void answer_with_bad_request(int conn_socket, const char*error)noexcept{
                HeaderFormatter out;

                out.append_cstr("HTTP/1.0 400 Bad request\r\nContent-Length:");
                int len = strlen(error);
                out.append_unsigned_int(len);
                out.append_cstr("\r\n\r\n");
                out.append_cstr(error, len);

                write_all(conn_socket, out.begin(), out.end());
            };

            void answer_with_exception(int conn_socket, const char*error)noexcept{
                HeaderFormatter out;

                out.append_cstr("HTTP/1.0 500 Internal Server Error\r\nContent-Length:");

                const char*prefix = "exception: ";
                int prefix_len = strlen(prefix);
                int error_len = strlen(error);
                out.append_unsigned_int(error_len + prefix_len);
                out.append_cstr("\r\n\r\n");
                out.append_cstr(prefix, prefix_len);
                out.append_cstr(error, error_len);
                out.append_char('\n');
                
                write_all(conn_socket, out.begin(), out.end());
            };

            void answer_with_response(int conn_socket, const Response&response)noexcept{
                HeaderFormatter out;

                out.append_cstr("HTTP/1.0 ");
                out.append_unsigned_int(response.status);
                out.append_cstr("\r\nContent-Length:");
                out.append_unsigned_int(response.body.size());
                if(!response.mime_type.empty()){
                    out.append_cstr("\r\nContent-Type:");
                    out.append_str(response.mime_type);
                }
                out.append_cstr("\r\n\r\n");

                if(write_all(conn_socket, out.begin(), out.end()))
                    write_all(conn_socket, &response.body[0], &response.body[0]+response.body.size());
            };

            struct MemoryBuffer{
                static const int max_buffer_size = 1 << 16;
                int buffer_size;
                char buffer[max_buffer_size];
            };

            class HTTPRequestParser{
            private:
                Request*request;
                int max_request_body_size;
                HTTPRequestHeaderParser header_parser;
                const char*error_msg;
                int body_end;
            public:
                HTTPRequestParser(Request*request, int max_request_resource_size, int max_request_body_size):
                    request(request), max_request_body_size(max_request_body_size),
                    header_parser(&request->resource, max_request_resource_size),
                    error_msg(nullptr), body_end(0){
                    request->body.clear();
                }

                void put(const MemoryBuffer&buffer){
                    int pos_in_buffer = 0;
                    while(!header_parser.is_header_complete() && pos_in_buffer != buffer.buffer_size){
                        header_parser.put(buffer.buffer[pos_in_buffer]);
                        const char*err = header_parser.get_error();
                        if(err){
                            error_msg = err;
                            return;
                        }
                        ++pos_in_buffer;
                    }

                    if(!header_parser.is_header_complete())
                        return;

                    if(request->body.empty()){
                        int body_size = header_parser.get_body_size();
                        if(body_size > max_request_body_size){
                            error_msg = "HTTP request body larger than allowed";
                            return;
                        }
                        request->body.resize(header_parser.get_body_size());
                    }

                    int free_space_in_request_body = request->body.size() - body_end;
                    int bytes_to_copy = std::min(buffer.buffer_size-pos_in_buffer, free_space_in_request_body);

                    memcpy(&request->body[0] + body_end, buffer.buffer+pos_in_buffer, bytes_to_copy);
                    body_end += bytes_to_copy;
                    pos_in_buffer += bytes_to_copy;

                    if(body_end == (int)request->body.size() && pos_in_buffer != buffer.buffer_size){
                        error_msg = "Body size larger than content-length";
                        return;
                    }
                }

                bool is_request_complete()const noexcept{
                    return (int)request->body.size() == body_end && header_parser.is_header_complete();
                }

                const char*get_error()const noexcept{
                    return error_msg;
                }
            };

            #ifdef GENERATE_TEST_CASES
            TEST_CASE("HTTPRequestParser", "[http_request_parse]"){

                #define MY_PASS(MSG, CHUNK_SIZE, RESOURCE, BODY)\
                {\
                    Request request;\
                    MemoryBuffer buffer;\
                    HTTPRequestParser parser(&request, 100, 100);\
                    const char*in = MSG;\
                    const char*in_end = in + strlen(in);\
                    REQUIRE(parser.get_error() == nullptr);\
                    for(;;){\
                        buffer.buffer_size = 0;\
                        while(in != in_end && buffer.buffer_size < CHUNK_SIZE){\
                            buffer.buffer[buffer.buffer_size] = *in;\
                            ++in;\
                            ++buffer.buffer_size;\
                        }\
                        if(buffer.buffer_size == 0)\
                            break;\
                        parser.put(buffer);\
                        REQUIRE(parser.get_error() == nullptr);\
                    }\
                    REQUIRE(parser.is_request_complete());\
                    REQUIRE(request.resource == RESOURCE);\
                    REQUIRE(request.body == BODY);\
                }

                #define MY_FAIL(MSG, CHUNK_SIZE, RESOURCE, BODY)\
                {\
                    Request request;\
                    MemoryBuffer buffer;\
                    HTTPRequestParser parser(&request, 100, 100);\
                    const char*in = MSG;\
                    const char*in_end = in + strlen(in);\
                    REQUIRE(parser.get_error() == nullptr);\
                    bool ok = true;\
                    for(;;){\
                        buffer.buffer_size = 0;\
                        while(in != in_end && buffer.buffer_size < CHUNK_SIZE){\
                            buffer.buffer[buffer.buffer_size] = *in;\
                            ++in;\
                            ++buffer.buffer_size;\
                        }\
                        if(buffer.buffer_size == 0)\
                            break;\
                        parser.put(buffer);\
                        if(parser.get_error()){\
                            ok = false;\
                            break;\
                        }\
                        REQUIRE(parser.get_error() == nullptr);\
                    }\
                    if(parser.get_error() || !parser.is_request_complete()){\
                        ok = false;\
                        break;\
                    }\
                    REQUIRE(!ok);\
                }

                for(int i=1; i<50; ++i)
                    MY_PASS("GET /foo HTTP/1.1\r\ncontent-length:6\r\n\r\nBlabla", i, "/foo", "Blabla");

                for(int i=1; i<50; ++i)
                    MY_FAIL("GET /foo HTTP/1.1\r\ncontent-length:5\r\n\r\nBlabla", i, "/foo", "Blabla");

                for(int i=1; i<50; ++i)
                    MY_FAIL("GET /foo HTTP/1.1\r\ncontent-length:7\r\n\r\nBlabla", i, "/foo", "Blabla");

                for(int i=1; i<50; ++i)
                    MY_FAIL("GET /foo HTTP/1.1\r\n\r\nBlabla", i, "/foo", "Blabla");

                #undef MY_PASS
                #undef MY_FAIL

            }
            #endif

            const char* read_from_socket(int conn_socket, MemoryBuffer&buffer){
                int r = read(conn_socket, buffer.buffer, buffer.max_buffer_size);
                if(r < 0){
                    if(r == EAGAIN || r == EWOULDBLOCK)
                        return "call to read timed out";
                    else
                        return "internal server error during call to read while reading from socket";
                }else if(r == 0){
                    return "end of file/socket reached before HTTP request was completed";                
                }else{
                    buffer.buffer_size = r;
                    return nullptr;
                }
            }

            void thread_main(
                SyncSocketSet*socket_set,
                std::atomic<int>*started_worker_count, std::atomic<int>*finished_worker_count,
                int worker_id,
                Config config,
                detail::RequestHandler handler, void*user_data
            )noexcept{
                ++*started_worker_count;

                Request request;
                Response response;

                int conn_socket;
                while(conn_socket = socket_set->blocking_remove(), conn_socket != -1){

                    struct timeval tv;
                    tv.tv_sec = config.timeout_in_seconds;
                    tv.tv_usec = 0;
                    if(setsockopt(conn_socket, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv)<0)
                        continue;
                    if(setsockopt(conn_socket, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof tv)<0)
                        continue;

                    const char*err = nullptr;

                    HTTPRequestParser request_parser(&request, config.max_request_resource_size, config.max_request_body_size);
                    MemoryBuffer buffer;

                    while(!request_parser.is_request_complete()){
                        err = read_from_socket(conn_socket, buffer);
                        if(err)
                            break;

                        request_parser.put(buffer);
                        err = request_parser.get_error();
                        if(err)
                            break;
                    }

                    if(err){
                        answer_with_bad_request(conn_socket, err);
                    }else{
                        response.status = 200;
                        response.body = "Request handler did not modify body; This is an error in the code that uses the HTTP server\n";

                        try{
                            handler(worker_id, config.worker_count, user_data, request, response);
                            answer_with_response(conn_socket, response);
                        }catch(std::exception&err){
                            if(config.print_exception_message_in_answer)
                                answer_with_exception(conn_socket, err.what());
                            else
                                answer_with_bad_request(conn_socket);
                        }catch(...){
                            if(config.print_exception_message_in_answer)
                                answer_with_exception(conn_socket, "unknown exception");
                            else
                                answer_with_bad_request(conn_socket);
                        }
                    }
                    shutdown(conn_socket, SHUT_RDWR);
                    close(conn_socket);
                }
                ++*finished_worker_count;
            }
        }

        namespace detail{
            void run(Config config,
                RequestHandler request_handler,
                void*request_user_data,
                StartupHandler startup_handler,
                void*startup_user_data
            ){
                if(config.worker_count < 1)
                    throw std::runtime_error("worker_count must be at least 1");
                if(config.port < 0)
                    throw std::runtime_error("port must not be negative");
                if(config.max_request_body_size < 1)
                    throw std::runtime_error("max_request_body_size must be at least 1");
                if(config.max_request_resource_size < 1)
                    throw std::runtime_error("max_request_resource_size must be at least 1");

                int listing_socket = socket(AF_INET6, SOCK_STREAM, 0);
                if(listing_socket < 0){
                    int err = errno;
                    throw std::system_error(err, std::system_category(), "call to socket failed");
                }
                auto f1 = finally([&]{
                    close(listing_socket);
                });

                int val = 1;
                if(setsockopt(listing_socket, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val))<0){
                    int err = errno;
                    throw std::system_error(err, std::system_category(), "call to setsockopt failed");
                }

                sockaddr_in6 address;
                address.sin6_family = AF_INET6;
                address.sin6_port = htons(config.port);
                address.sin6_addr = in6addr_any;

                int bind_ret = bind(listing_socket, (struct sockaddr *) &address, sizeof(address));
                if(bind_ret < 0){
                    int err = errno;
                    throw std::system_error(err, std::system_category(), "call to bind failed");
                }
                int listen_ret = listen(listing_socket, 8);
                if(listen_ret < 0){
                    int err = errno;
                    throw std::system_error(err, std::system_category(), "call to listen failed");
                }

                if(config.install_int_signal_handler){
                    if(sigint_replaced != 0){
                        throw std::runtime_error("int signal handler already replaced, set install_int_signal_handler to false");
                    }
                }

                struct sigaction new_sigaction;
                struct sigaction old_sigaction;

                auto f2 = finally([&]{
                    if(config.install_int_signal_handler){
                        sigaction(SIGINT, &old_sigaction, nullptr);
                        sigint_replaced = 0;
                    }
                });

                if(config.install_int_signal_handler){
                    sigint_received.store(false);
                    sigint_replaced = 1;
                    new_sigaction.sa_handler = sigint_handler;
                    new_sigaction.sa_flags = 0;
                    sigemptyset(&new_sigaction.sa_mask);
                    sigaction(SIGINT, &new_sigaction, &old_sigaction);
                }

                SyncSocketSet socket_set;

                std::atomic<int> started_worker_count(0);
                std::atomic<int> finished_worker_count(0);

                auto wait_for_all_workers_to_finish = [&]{
                    while(started_worker_count.load() != finished_worker_count.load())
                        std::this_thread::sleep_for(std::chrono::microseconds(50));
                };

                auto f3 = finally([&]{
                    socket_set.finish();
                    wait_for_all_workers_to_finish();
                });

                int i=0;
                while(i<(int)config.worker_count){
                    std::thread(
                        thread_main, &socket_set,
                        &started_worker_count, &finished_worker_count, i,
                        config, request_handler, request_user_data
                    ).detach();
                    ++i;
                    while(started_worker_count.load()!=i){
                        std::this_thread::sleep_for(std::chrono::microseconds(50));
                    }
                }

                if(finished_worker_count.load() != 0)
                    throw std::runtime_error("some worker finished early");

                startup_handler(startup_user_data);

                for(;;){
                    if(sigint_received.load()){
                        socket_set.finish();
                        break;
                    }
                    // FIXME: If SIGINT happens when main thread is here, the signal is lost...
                    int conn_socket = accept(listing_socket, nullptr, 0);
                    if(conn_socket < 0){
                        int err = errno;
                        if(err == EINTR){
                            if(sigint_received.load()){
                                socket_set.finish();
                                break;
                            }
                        }
                        throw std::system_error(err, std::system_category(), "call to accept failed");
                    }
                    if(!socket_set.blocking_add(conn_socket)){
                        break;
                    }
                }

                wait_for_all_workers_to_finish();
            }   
        }
    }
}
