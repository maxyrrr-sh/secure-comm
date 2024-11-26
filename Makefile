AES_BIN_NAME = aes
SRC_DIR = ./src
BIN_DIR = ./bin
PACKAGES = $(SRC_DIR)/...

LDFLAGS = -s -w -lssl -lcrypto -pthread

.PHONY: all build clean deps test run install

$(BIN_DIR):
	@mkdir -p $(BIN_DIR)

all: clean build

build: $(BIN_DIR)
	@echo "Збірка Go проекту..."
	cd src && go build -o ../bin/secure_comm 		

	@echo "Збірка C++ проекту..."
	g++ -std=c++17 src/aes/main.cpp -o bin/aes -lssl -lcrypto -pthread
clean:
	@echo "Очищення проекту..."
	rm -rf $(BIN_DIR)/*
	cd $(SRC_DIR) && $(GO) clean -modcache

test:
	@echo "Запуск тестів Go..."
	cd $(SRC_DIR) && $(GO) test ./...
	@echo "Запуск тестів C++..."
	# Додайте команду для тестів C++, якщо є

run: build
	@echo "Запуск Go проекту..."
	$(BIN_DIR)/$(BINARY_NAME)_go
	@echo "Запуск C++ проекту..."
	$(BIN_DIR)/$(BINARY_NAME)_cpp

install: build
	@echo "Встановлення Go додатку..."
	sudo cp $(BIN_DIR)/$(BINARY_NAME)_go /usr/local/bin/
	@echo "Встановлення C++ додатку..."
	sudo cp $(BIN_DIR)/$(BINARY_NAME)_cpp /usr/local/bin/
	@mkdir -p /etc/secure-comm
	@cp -r $(SRC_DIR)/keys /etc/secure-comm/ 2>/dev/null || true
	@echo "Додатки встановлено успішно"

help:
	@echo "Доступні команди:"
	@echo "  make            - встановити залежності та зібрати проект"
	@echo "  make build      - зібрати проект"
	@echo "  make install    - встановити додатки в систему"
	@echo "  make clean      - видалити артефакти збірки"
	@echo "  make test       - запустити тести"
	@echo "  make run        - запустити проекти"
