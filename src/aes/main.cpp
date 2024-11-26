#include <filesystem>
#include <fstream>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <thread>
#include <vector>

class AESCrypto {
  private:
    static const int KEY_SIZE = 32;   // AES-256
    static const int BLOCK_SIZE = 16; // AES block size
    static const int IV_SIZE = 16;    // AES IV size

    std::vector<unsigned char> key;
    std::vector<unsigned char> iv;

    void handleErrors() {
        std::cerr << "OpenSSL Error" << std::endl;
        exit(1);
    }

  public:
    AESCrypto() : key(KEY_SIZE), iv(IV_SIZE) {}

    void generateKey() {
        if (RAND_bytes(key.data(), KEY_SIZE) != 1) {
            handleErrors();
        }
        if (RAND_bytes(iv.data(), IV_SIZE) != 1) {
            handleErrors();
        }
    }

    void saveKey(const std::string &filename) {
        std::ofstream keyFile(filename, std::ios::binary);
        keyFile.write(reinterpret_cast<const char *>(key.data()), KEY_SIZE);
        keyFile.write(reinterpret_cast<const char *>(iv.data()), IV_SIZE);
    }

    void loadKey(const std::string &filename) {
        std::ifstream keyFile(filename, std::ios::binary);
        keyFile.read(reinterpret_cast<char *>(key.data()), KEY_SIZE);
        keyFile.read(reinterpret_cast<char *>(iv.data()), IV_SIZE);
    }

    void processFile(const std::string &inputFile,
                     const std::string &outputFile, bool encrypt) {
        std::ifstream input(inputFile, std::ios::binary);
        std::ofstream output(outputFile, std::ios::binary);

        if (!input || !output) {
            std::cerr << "File open error" << std::endl;
            return;
        }

        // Determine file size
        input.seekg(0, std::ios::end);
        size_t fileSize = input.tellg();
        input.seekg(0, std::ios::beg);

        // Read entire file
        std::vector<unsigned char> buffer(fileSize);
        input.read(reinterpret_cast<char *>(buffer.data()), fileSize);

        // Perform encryption/decryption
        std::vector<unsigned char> outputBuffer(fileSize + BLOCK_SIZE);

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            std::cerr << "CTX allocation failed" << std::endl;
            return;
        }

        int outlen = 0, totalOutlen = 0;

        if (encrypt) {
            EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(),
                               iv.data());
            EVP_EncryptUpdate(ctx, outputBuffer.data(), &outlen, buffer.data(),
                              fileSize);
            totalOutlen += outlen;
            EVP_EncryptFinal_ex(ctx, outputBuffer.data() + outlen, &outlen);
            totalOutlen += outlen;
        } else {
            EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(),
                               iv.data());
            EVP_DecryptUpdate(ctx, outputBuffer.data(), &outlen, buffer.data(),
                              fileSize);
            totalOutlen += outlen;
            EVP_DecryptFinal_ex(ctx, outputBuffer.data() + outlen, &outlen);
            totalOutlen += outlen;
        }

        outputBuffer.resize(totalOutlen);
        output.write(reinterpret_cast<char *>(outputBuffer.data()),
                     totalOutlen);

        EVP_CIPHER_CTX_free(ctx);
    }
};

int main(int argc, char *argv[]) {
    if (argc < 3) {
        std::cerr << "Usage:" << std::endl;
        std::cerr << "Encrypt: " << argv[0] << " --encrypt <input_file>"
                  << std::endl;
        std::cerr << "Decrypt: " << argv[0]
                  << " --decrypt <input_file> -k <key_file>" << std::endl;
        return 1;
    }

    AESCrypto crypto;
    std::string mode = argv[1];
    std::string inputFile = argv[2];

    try {
        if (mode == "--encrypt") {
            std::string outputFile = inputFile + ".enc";
            crypto.generateKey();
            crypto.saveKey("aes_key.bin");
            crypto.processFile(inputFile, outputFile, true);
            std::cout << "File encrypted: " << outputFile << std::endl;
        } else if (mode == "--decrypt") {
            if (argc != 5 || std::string(argv[3]) != "-k") {
                std::cerr << "Key file required for decryption" << std::endl;
                return 1;
            }

            std::string keyFile = argv[4];
            std::string outputFile = inputFile + ".dec";

            crypto.loadKey(keyFile);
            crypto.processFile(inputFile, outputFile, false);

            std::cout << "File decrypted: " << outputFile << std::endl;
        } else {
            std::cerr << "Invalid mode. Use --encrypt or --decrypt"
                      << std::endl;
            return 1;
        }
    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
