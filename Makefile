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
clean:
	@echo "Очищення проекту..."
	cp bin/aes aes
	rm -rf $(BIN_DIR)/*
	mv aes bin/aes	

run: build
	@echo "Запуск Go проекту..."
	$(BIN_DIR)/$(BINARY_NAME)_go
	@echo "Запуск C++ проекту..."
	$(BIN_DIR)/$(BINARY_NAME)_cpp

