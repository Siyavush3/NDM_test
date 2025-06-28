# Компилятор C++
CXX = g++


CXXFLAGS = -std=c++17 -Wall -Wextra -g

# Имя исполняемого файла
TARGET = ping_mac

SRC_DIR = src


SOURCES = $(wildcard $(SRC_DIR)/*.cpp)


OBJECTS = $(SOURCES:.cpp=.o)


all: $(TARGET)


$(TARGET): $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJECTS)

$(SRC_DIR)/%.o: $(SRC_DIR)/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@


clean:
	rm -f $(TARGET) $(OBJECTS)

# Объявляем цели, которые не являются файлами
.PHONY: all clean