#pragma once
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <sodium.h>

#define REDIS_HOST "127.0.0.1"
#define REDIS_PORT 6379

using namespace std;
using json = nlohmann::json;

// ---------- Helper Fonksiyonlar ----------

inline redisContext* connection_var() {
    redisContext* c = redis_connection(REDIS_HOST, REDIS_PORT);
    return c;
}

inline string hex_to_string(const unsigned char* key, size_t size) {
    ostringstream oss;
    for (size_t i = 0; i < size; i++) {
        oss << hex << setfill('0') << setw(2)
            << static_cast<int>(key[i]);
    }
    return oss.str();
}

inline string secret_key_generator(size_t size = 32) {
    unsigned char* secret_key = new unsigned char[size];
    randombytes_buf(secret_key, size);
    string key = hex_to_string(secret_key, size);
    delete[] secret_key;
    return key;
}

inline string base64_encode(const unsigned char* data, size_t len) {
    BIO* bio, * b64;
    BUF_MEM* bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    BIO_write(bio, data, len);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);

    string encoded(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);

    return encoded;
}

inline vector<unsigned char> base64_decode(const string& encoded) {
    BIO* bio, *b64;
    int decodeLen = encoded.length();
    vector<unsigned char> buffer(decodeLen);

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(encoded.data(), encoded.length());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    int length = BIO_read(bio, buffer.data(), decodeLen);
    BIO_free_all(bio);

    if (length < 0) {
        throw runtime_error("Base64 decode başarısız!");
    }

    buffer.resize(length);
    return buffer;
}

// ---------- CryptMessage Sınıfı ----------

class CryptMessage {
private:
    string plaintext_str;
    vector<unsigned char> plaintext;
    vector<unsigned char> aad;
    json general_json;

public:
    // AES-GCM
    json aes_gcm_encrypt_string();
    string aes_gcm_decrypt();

    // ChaCha20-Poly1305
    json encrypt_ChaCha20();
    string decrypt_ChaCha20();

    // Getter / Setter (inline)
    [[nodiscard]] inline string plaintext_str1() const { return plaintext_str; }
    inline void set_plaintext_str(const string &plaintext_str) { this->plaintext_str = plaintext_str; }

    [[nodiscard]] inline vector<unsigned char> plaintext1() const { return plaintext; }
    inline void set_plaintext(const vector<unsigned char> &plaintext) { this->plaintext = plaintext; }

    [[nodiscard]] inline vector<unsigned char> aad1() const { return aad; }
    inline void set_aad(const vector<unsigned char> &aad) { this->aad = aad; }

    [[nodiscard]] inline json general_json1() const { return general_json; }
    inline void set_general_json(const json &general_json) { this->general_json = general_json; }
};
