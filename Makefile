CXXFLAGS =
LDFLAGS = -lpcap
TARGET = tcp_block

SRCS := $(wildcard *.cpp)
OBJS := $(patsubst %.cpp,%.o,$(SRCS))

all: $(TARGET)

debug: CXXFLAGS += -DDEBUG -g
debug: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) -o $@ $^ $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $<

clean:
	rm -rf $(TARGET) *.o
	
.PHONY: all clean
