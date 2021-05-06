TARGET := restClient
SOURCES := $(wildcard src/*.c src/*.cpp)
OBJECTS := $(patsubst %.c,%.o, $(patsubst %.cpp,%.o,$(SOURCES)))

INCLUDE := -Isrc
LIBPATH :=
LIBS := -lcurl -lboost_system -lpthread

CXX := g++

FLAGS := -Wall -Wextra -Wpedantic
CXXFLAGS := $(FLAGS) -std=c++11

all: $(OBJECTS)
	$(CXX) $(CXXFLAGS) $(INCLUDE) $(OBJECTS) -o $(TARGET) $(LIBPATH) $(LIBS)

%.o: src/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm src/*.o
	rm $(TARGET)