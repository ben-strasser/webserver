
CFLAGS=-std=c++11 -ggdb -Wall -Wextra
LDFLAGS=-pthread

all: bin/run_test bin/example1 bin/example2


build/http_server.test.o: src/catch.hpp src/http_server.h src/http_server.cpp
	@mkdir -p build
	g++ $(CFLAGS) -DGENERATE_TEST_CASES -c src/http_server.cpp -o build/http_server.test.o

build/http_server.o: src/http_server.h src/http_server.cpp
	@mkdir -p build
	g++ $(CFLAGS) -c src/http_server.cpp -o build/http_server.o

build/test_main.o: src/catch.hpp src/test_main.cpp
	@mkdir -p build
	g++ $(CFLAGS) src/test_main.cpp -c -o build/test_main.o

bin/run_test: build/http_server.test.o build/test_main.o
	@mkdir -p bin
	g++ $(LDFLAGS) build/http_server.test.o build/test_main.o -o bin/run_test

build/example1.o: src/catch.hpp src/example1.cpp
	@mkdir -p build
	g++ $(CFLAGS) src/example1.cpp -c -o build/example1.o

build/example2.o: src/catch.hpp src/example2.cpp
	@mkdir -p build
	g++ $(CFLAGS) src/example2.cpp -c -o build/example2.o

bin/example1: build/http_server.o build/example1.o
	@mkdir -p bin
	g++ $(LDFLAGS) build/http_server.o build/example1.o -o bin/example1

bin/example2: build/http_server.o build/example2.o
	@mkdir -p bin
	g++ $(LDFLAGS) build/http_server.o build/example2.o -o bin/example2
