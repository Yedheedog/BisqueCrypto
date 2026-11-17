#include "BisqueCrypto.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <vector>

int main() {
    const char* keys[] = {
        "vuyWQSjlknpJF54ib36txVse",
        "anotherValid24ByteKey1234"
    };
    MD159 crypto;

    for (int i = 0; i < 64; ++i) {
        const char* key = keys[i % 2];
        const auto status = crypto.InitializeKey(key, static_cast<uint32_t>(std::strlen(key)));
        if (status != 0) {
            std::cerr << "InitializeKey failed on iteration " << i << ": " << status << "\n";
            return 1;
        }
    }

    const uint8_t plaintext[16] = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
    };
    std::vector<uint8_t> encrypted;
    std::vector<uint8_t> decrypted;
    crypto.Encrypt(plaintext, sizeof(plaintext), encrypted);
    crypto.Decrypt(encrypted.data(), static_cast<uint32_t>(encrypted.size()), decrypted);

    if (decrypted.size() != sizeof(plaintext) ||
        !std::equal(std::begin(plaintext), std::end(plaintext), decrypted.begin())) {
        std::cerr << "Post-reinitialization crypto round-trip failed\n";
        return 2;
    }

    std::cout << "Repeated key initialization and cleanup: PASS\n";
    return 0;
}
