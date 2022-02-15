IDIR = ./src
CXX=g++
CFLAGS=-g -Wall -Wextra -std=c++17 -pedantic
CRFLAGS=-Wall -Wextra -std=c++17 -pedantic -O3 -DNDEBUG
TARGET=ScrUplServer
FILES=./src/*.cpp
IDIR=./src
LIB=-lssl -lcrypto -lpthread

all: $(TARGET)

$(TARGET):
	$(CXX) -o $(TARGET) $(FILES) $(CFLAGS) -I$(IDIR) $(LIB)

release:
	$(CXX) -o $(TARGET) $(FILES) $(CRFLAGS) -I$(IDIR) $(LIB)


clean: 
	rm $(TARGET)
