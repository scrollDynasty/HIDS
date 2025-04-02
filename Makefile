.PHONY: build clean run setup bot test help

# Переменные для компиляции
CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2
LDFLAGS = -ljsoncpp -lssl -lcrypto

# Пути
SRC_DIR = src
INCLUDE_DIR = include
BUILD_DIR = build
BIN_DIR = bin

# Исходные файлы
SRCS = $(wildcard $(SRC_DIR)/*.cpp) $(wildcard $(SRC_DIR)/**/*.cpp)
OBJS = $(patsubst $(SRC_DIR)/%.cpp,$(BUILD_DIR)/%.o,$(SRCS))

# Имя исполняемого файла
TARGET = $(BIN_DIR)/hids

# Цель по умолчанию
all: build

# Справка
help:
	@echo "Доступные команды:"
	@echo "  make build       - Собрать проект HIDS"
	@echo "  make clean       - Очистить временные файлы и сборку"
	@echo "  make run         - Запустить HIDS"
	@echo "  make bot         - Запустить Telegram-бота"
	@echo "  make setup       - Настроить систему (установить зависимости)"
	@echo "  make test        - Запустить тестовое уведомление"
	@echo "  make help        - Показать эту справку"

# Создание директорий
$(BUILD_DIR) $(BIN_DIR):
	mkdir -p $@
	mkdir -p $(BUILD_DIR)/modules
	mkdir -p $(BUILD_DIR)/utils
	mkdir -p $(BUILD_DIR)/alert

# Компиляция
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -I$(INCLUDE_DIR) -c $< -o $@

# Сборка
build: $(BIN_DIR) $(OBJS)
	$(CXX) $(OBJS) $(LDFLAGS) -o $(TARGET)
	@echo "Сборка завершена. Исполняемый файл: $(TARGET)"

# Очистка
clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)
	@echo "Проект очищен."

# Запуск HIDS
run: build
	sudo ./$(TARGET)

# Запуск бота
bot:
	cd hids_bot && ../.venv/bin/python bot.py

# Настройка системы
setup:
	@echo "Установка зависимостей для HIDS..."
	sudo apt-get update
	sudo apt-get install -y build-essential libjsoncpp-dev python3-pip python3-venv
	
	@echo "Создание виртуального окружения и установка зависимостей для Telegram-бота..."
	python3 -m venv .venv
	.venv/bin/pip install -r hids_bot/requirements.txt
	
	@echo "Создание директории для сокета..."
	sudo mkdir -p /var/run/hids
	sudo chmod 777 /var/run/hids
	
	@echo "Настройка завершена."

# Тестирование
test:
	@echo "Отправка тестового уведомления в HIDS..."
	.venv/bin/python test_hids_alert.py