#include "BisqueCrypto.h"

#include <cstdlib>
#include <cstring>
#include <limits>
#include <new>
#include <string>
#include <vector>
#include <zlib.h>

#if defined(_WIN32)
#define BISQUE_EXPORT __declspec(dllexport)
#else
#define BISQUE_EXPORT __attribute__((visibility("default")))
#endif

namespace {
struct InflateResult {
    std::vector<uint8_t> bytes;
    bool ok = false;
};

InflateResult inflate_all(const uint8_t* input, size_t input_size) {
    InflateResult result;
    if ((!input && input_size) || input_size > std::numeric_limits<uInt>::max())
        return result;

    z_stream stream{};
    stream.next_in = const_cast<Bytef*>(reinterpret_cast<const Bytef*>(input));
    stream.avail_in = static_cast<uInt>(input_size);
    if (inflateInit(&stream) != Z_OK)
        return result;

    uint8_t chunk[8192];
    int status = Z_OK;
    while (status == Z_OK) {
        stream.next_out = chunk;
        stream.avail_out = sizeof(chunk);
        status = inflate(&stream, Z_NO_FLUSH);
        const size_t produced = sizeof(chunk) - stream.avail_out;
        result.bytes.insert(result.bytes.end(), chunk, chunk + produced);
    }
    const int end_status = inflateEnd(&stream);
    result.ok = (status == Z_STREAM_END && end_status == Z_OK);
    if (!result.ok)
        result.bytes.clear();
    return result;
}

void* copy_to_malloc(const uint8_t* data, size_t size) {
    if (size == std::numeric_limits<size_t>::max())
        return nullptr;
    void* output = std::malloc(size + 1);
    if (!output)
        return nullptr;
    if (size)
        std::memcpy(output, data, size);
    static_cast<uint8_t*>(output)[size] = 0;
    return output;
}
} // namespace

extern "C" {

BISQUE_EXPORT void* CreateFromKey(const char* key) {
    if (!key)
        return nullptr;
    try {
        MD159* instance = new (std::nothrow) MD159();
        if (!instance)
            return nullptr;
        const int64 status = instance->InitializeKey(key, static_cast<uint32>(std::strlen(key)));
        if (status != 0) {
            delete instance;
            return nullptr;
        }
        return instance;
    } catch (...) {
        return nullptr;
    }
}

BISQUE_EXPORT void* Encrypt(void* instance, const char* data, int length) {
    if (!instance || !data || length <= 0)
        return nullptr;
    try {
        const size_t plain_size = static_cast<size_t>(length);
        const size_t padded_size = (plain_size + 15u) & ~size_t(15u);
        if (padded_size < plain_size || padded_size > std::numeric_limits<uint32>::max())
            return nullptr;

        std::vector<uint8_t> padded(padded_size, 0);
        std::memcpy(padded.data(), data, plain_size);
        std::vector<uint8_t> encrypted;
        static_cast<MD159*>(instance)->Encrypt(padded.data(),
            static_cast<uint32>(padded.size()), encrypted);
        const std::string encoded = RB64Encode(encrypted.data(),
            static_cast<uint32>(encrypted.size()));
        return copy_to_malloc(reinterpret_cast<const uint8_t*>(encoded.data()), encoded.size());
    } catch (...) {
        return nullptr;
    }
}

BISQUE_EXPORT int Decrypt(void* instance, const char* data, char** output) {
    if (output)
        *output = nullptr;
    if (!instance || !data || !output || data[0] == '\0')
        return 0;
    try {
        const std::vector<uint8_t> decoded = RB64Decode(data);
        if (decoded.empty() || decoded.size() > std::numeric_limits<uint32>::max())
            return 0;
        std::vector<uint8_t> plaintext;
        static_cast<MD159*>(instance)->Decrypt(decoded.data(),
            static_cast<uint32>(decoded.size()), plaintext);
        if (plaintext.size() > static_cast<size_t>(std::numeric_limits<int>::max()))
            return 0;
        *output = static_cast<char*>(copy_to_malloc(plaintext.data(), plaintext.size()));
        return *output ? static_cast<int>(plaintext.size()) : 0;
    } catch (...) {
        return 0;
    }
}

BISQUE_EXPORT int DecryptNTY(void* instance, const char* data, uint32 size,
                             char** output, bool is_compressed) {
    if (output)
        *output = nullptr;
    if (!instance || !data || !output || size < 16 || size > (1u << 30))
        return 0;
    try {
        uint32 encrypted_size = bswap32(*reinterpret_cast<const uint32*>(data + 4));
        if (encrypted_size == 0 || encrypted_size > size - 16)
            return 0;

        std::vector<uint8_t> decrypted;
        static_cast<MD159*>(instance)->DecryptMD144(
            reinterpret_cast<const uint8_t*>(data) + 16, encrypted_size, decrypted);

        std::vector<uint8_t> final_bytes;
        if (is_compressed) {
            InflateResult inflated = inflate_all(decrypted.data(), decrypted.size());
            if (!inflated.ok)
                return 0;
            final_bytes = std::move(inflated.bytes);
        } else {
            final_bytes = std::move(decrypted);
        }
        if (final_bytes.size() > static_cast<size_t>(std::numeric_limits<int>::max()))
            return 0;
        *output = static_cast<char*>(copy_to_malloc(final_bytes.data(), final_bytes.size()));
        return *output ? static_cast<int>(final_bytes.size()) : 0;
    } catch (...) {
        return 0;
    }
}

BISQUE_EXPORT void ReleaseInst(void* instance) {
    delete static_cast<MD159*>(instance);
}

BISQUE_EXPORT void ReleaseBuffer(void* buffer) {
    std::free(buffer);
}

} // extern "C"
