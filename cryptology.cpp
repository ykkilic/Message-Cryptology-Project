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
#include <hiredis/hiredis.h>
#include "redis_utils.h"

#define REDIS_HOST "127.0.0.1"
#define REDIS_PORT 6379

using namespace std;
using json = nlohmann::json;

string hex_to_string(const unsigned char* key, size_t size);
string secret_key_generator(size_t size = 32); // 256 bit için 32 byte
string base64_encode(const unsigned char* data, size_t len);
vector<unsigned char> base64_decode(const string& encoded);
void set_to_redis(int user_id, const json& value);
RedisResult get_from_redis(int user_id);
void delete_from_redis(int user_id);

class CryptMessage {
    private:
        string plaintext_str;
        vector<unsigned char> plaintext;
        vector<unsigned char> aad;
        json general_json;

    public:
        json aes_gcm_encrypt_string() {
            const string plaintextf = this->plaintext_str;
            const string hex_key = secret_key_generator(32); // 256-bit için 32 byte
            vector<unsigned char> key(hex_key.size() / 2);
            for (size_t i = 0; i < key.size(); i++) {
                string byteString = hex_key.substr(i * 2, 2);
                key[i] = (unsigned char) strtol(byteString.c_str(), nullptr, 16);
            }

            EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
            if (!ctx) throw runtime_error("EVP_CIPHER_CTX_new failed");

            // 12 byte IV
            vector<unsigned char> iv(12);
            RAND_bytes(iv.data(), iv.size());

            if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr))
                throw runtime_error("EncryptInit failed");
            if (1 != EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()))
                throw runtime_error("EncryptInit key/iv failed");

            vector<unsigned char> ciphertext(plaintextf.size());
            int len;
            if (1 != EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                                       reinterpret_cast<const unsigned char*>(plaintextf.c_str()), plaintextf.size()))
                throw runtime_error("EncryptUpdate failed");

            int ciphertext_len = len;
            if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len))
                throw runtime_error("EncryptFinal failed");
            ciphertext_len += len;
            ciphertext.resize(ciphertext_len);

            vector<unsigned char> tag(16);
            if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data()))
                throw runtime_error("Get tag failed");

            EVP_CIPHER_CTX_free(ctx);

            json data;
            data["key"] = base64_encode(key.data(), key.size());
            data["nonce"] = base64_encode(iv.data(), iv.size());
            data["ciphertext"] = base64_encode(ciphertext.data(), ciphertext.size());
            data["tag"] = base64_encode(tag.data(), tag.size());

            general_json["AES"] = data;
            return data;
        }

        string aes_gcm_decrypt() {
            json aes_json = this->general_json["AES"];
            if (!aes_json.contains("key") || !aes_json.contains("nonce") ||
                !aes_json.contains("ciphertext") || !aes_json.contains("tag")) {
                    throw runtime_error("AES-GCM verileri general_json içinde eksik!");
            }

            vector<unsigned char> key = base64_decode(aes_json["key"]);
            vector<unsigned char> iv = base64_decode(aes_json["nonce"]);
            vector<unsigned char> ciphertext = base64_decode(aes_json["ciphertext"]);
            vector<unsigned char> tag = base64_decode(aes_json["tag"]);

            EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
            if (!ctx) throw runtime_error("EVP_CIPHER_CTX_new failed");

            if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr))
                throw runtime_error("DecryptInit failed");
            if (1 != EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()))
                throw runtime_error("DecryptInit key/iv failed");

            // AAD varsa buraya ekleyebilirsin:
            if (!aad.empty()) {
                int len;
                if (1 != EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(), aad.size()))
                    throw runtime_error("Decrypt AAD failed");
            }

            vector<unsigned char> plaintext(ciphertext.size());
            int len;
            if (1 != EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()))
                throw runtime_error("DecryptUpdate failed");
            int plaintext_len = len;

            // Tag'i set et
            if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.size(), tag.data()))
                throw runtime_error("Set tag failed");

            // Final
            int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
            EVP_CIPHER_CTX_free(ctx);

            if (ret <= 0) {
                throw runtime_error("DecryptFinal failed! Tag doğrulaması geçersiz.");
            }
            plaintext_len += len;
            plaintext.resize(plaintext_len);

            return string(plaintext.begin(), plaintext.end());
        }

        json encrypt_ChaCha20() {
            // plaintext_str'dan plaintext vector'üne veri aktar
            plaintext.assign(plaintext_str.begin(), plaintext_str.end());

            // 256-bit key üret
            const string hex_key = secret_key_generator(32); // 32 byte = 256 bit

            vector<unsigned char> key(hex_key.size() / 2);
            for (size_t i = 0; i < key.size(); i++) {
                string byteString = hex_key.substr(i * 2, 2);
                key[i] = (unsigned char) strtol(byteString.c_str(), nullptr, 16);
            }

            // 96-bit nonce üret (12 byte)
            vector<unsigned char> nonce(12);
            randombytes_buf(nonce.data(), nonce.size());

            EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
            if (!ctx) throw runtime_error("EVP_CIPHER_CTX_new failed");

            if (1 != EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr))
                throw runtime_error("EncryptInit failed");

            if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, nonce.size(), nullptr))
                throw runtime_error("Set IV length failed");

            if (1 != EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()))
                throw runtime_error("EncryptInit key/nonce failed");

            // AAD ekle (opsiyonel)
            if (!aad.empty()) {
                int len;
                if (1 != EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(), aad.size()))
                    throw runtime_error("Encrypt AAD failed");
            }

            // Şifreleme - plaintext vector'ü artık dolu
            vector<unsigned char> ciphertext(plaintext.size());
            int len;
            if (1 != EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size()))
                throw runtime_error("EncryptUpdate failed");
            int ciphertext_len = len;

            if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len))
                throw runtime_error("EncryptFinal failed");
            ciphertext_len += len;
            ciphertext.resize(ciphertext_len);

            // Tag al
            vector<unsigned char> tag(16);
            if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, tag.size(), tag.data()))
                throw runtime_error("Get tag failed");

            EVP_CIPHER_CTX_free(ctx);

            // Base64 encode + JSON'a koy
            json data;
            data["key"]        = base64_encode(key.data(), key.size());
            data["nonce"]      = base64_encode(nonce.data(), nonce.size());
            data["ciphertext"] = base64_encode(ciphertext.data(), ciphertext.size());
            data["tag"]        = base64_encode(tag.data(), tag.size());

            general_json["chacha"] = data;
            return data;
        }

        string decrypt_ChaCha20() {
            if (!general_json.contains("chacha")) {
                throw runtime_error("ChaCha20 verisi general_json içinde bulunamadı!");
            }

            // JSON'dan değerleri oku
            json data = general_json["chacha"];
            vector<unsigned char> key       = base64_decode(data["key"]);
            vector<unsigned char> nonce     = base64_decode(data["nonce"]);
            vector<unsigned char> ciphertext= base64_decode(data["ciphertext"]);
            vector<unsigned char> tag       = base64_decode(data["tag"]);

            EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
            if (!ctx) throw runtime_error("EVP_CIPHER_CTX_new failed");

            if (1 != EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr))
                throw runtime_error("DecryptInit failed");

            if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, nonce.size(), nullptr))
                throw runtime_error("Set IV length failed");

            if (1 != EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()))
                throw runtime_error("DecryptInit key/nonce failed");

            // AAD varsa ekle
            if (!aad.empty()) {
                int len;
                if (1 != EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(), aad.size()))
                    throw runtime_error("Decrypt AAD failed");
            }

            // Ciphertext çöz
            vector<unsigned char> plaintext(ciphertext.size());
            int len, plaintext_len;
            if (1 != EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()))
                throw runtime_error("DecryptUpdate failed");
            plaintext_len = len;

            // Tag ayarla
            if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, tag.size(), (void*)tag.data()))
                throw runtime_error("Set tag failed");

            // Final
            int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
            EVP_CIPHER_CTX_free(ctx);

            if (ret > 0) {
                plaintext_len += len;
                plaintext.resize(plaintext_len);
                return string(reinterpret_cast<char*>(plaintext.data()), plaintext.size());
            } else {
                throw runtime_error("Decryption failed: Tag mismatch!");
            }
        }

        [[nodiscard]] inline string plaintext_str1() const {
            return plaintext_str;
        }

        void set_plaintext_str(const string &plaintext_str) {
            this->plaintext_str = plaintext_str;
        }

        [[nodiscard]] vector<unsigned char> plaintext1() const {
            return plaintext;
        }

        void set_plaintext(const vector<unsigned char> &plaintext) {
            this->plaintext = plaintext;
        }

        [[nodiscard]] vector<unsigned char> aad1() const {
            return aad;
        }

        void set_aad(const vector<unsigned char> &aad) {
            this->aad = aad;
        }

        [[nodiscard]] json general_json1() const {
            return general_json;
        }

        void set_general_json(const json &general_json) {
            this->general_json = general_json;
        }
};

string hex_to_string(const unsigned char* key, size_t size) {
    ostringstream oss;
    for (size_t i = 0; i < size; i++) {
        oss << hex << setfill('0') << setw(2)
            << static_cast<int>(key[i]);
    }
    return oss.str();
}

string secret_key_generator(size_t size) {
    unsigned char* secret_key = new unsigned char[size];
    randombytes_buf(secret_key, size);
    string key = hex_to_string(secret_key, size);
    delete[] secret_key;
    return key;
}

string base64_encode(const unsigned char* data, size_t len) {
    BIO* bio, * b64;
    BUF_MEM* bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    // newline eklenmesin
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    BIO_write(bio, data, len);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);

    string encoded(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);

    return encoded;
}

vector<unsigned char> base64_decode(const string& encoded) {
    BIO* bio, *b64;
    int decodeLen = encoded.length();
    vector<unsigned char> buffer(decodeLen);

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(encoded.data(), encoded.length());
    bio = BIO_push(b64, bio);

    // newline'ları dikkate alma
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    int length = BIO_read(bio, buffer.data(), decodeLen);
    BIO_free_all(bio);

    if (length < 0) {
        throw runtime_error("Base64 decode başarısız!");
    }

    buffer.resize(length); // Gerçek uzunluğa göre kısalt
    return buffer;
}

json encrypt_2layer(const string& message, int user_id) {
    // Layer 1: AES-GCM
    CryptMessage crypt_layer1;
    crypt_layer1.set_plaintext_str(message);
    json encrypted_message_aes = crypt_layer1.aes_gcm_encrypt_string();

    // Layer 2: ChaCha20
    CryptMessage crypt_layer2;
    crypt_layer2.set_plaintext_str(encrypted_message_aes.dump());
    json encrypted_chacha = crypt_layer2.encrypt_ChaCha20();

    // Redis'e tüm JSON'u atıyoruz (anahtarlar + nonce dahil)
    set_to_redis(user_id, encrypted_chacha);

    return encrypted_chacha;
}

string decrypt_2layer(int user_id) {
    try {
        // 1) Redis'ten ChaCha20 çıktısını al (key/nonce/tag içeriyor)
        RedisResult result = get_from_redis(user_id);
        if (result.value.empty()) {
            throw runtime_error("Redis'ten boş değer geldi.");
        }

        json encrypted_chacha = json::parse(result.value);

        // 2) ChaCha20 çöz
        CryptMessage decrypt_layer1;
        json pre_general_json1;
        pre_general_json1["chacha"] = encrypted_chacha;
        decrypt_layer1.set_general_json(pre_general_json1);

        string decrypted_layer1_raw = decrypt_layer1.decrypt_ChaCha20();

        // Bu JSON aslında AES çıktısını içeriyor
        json encrypted_message_aes;
        try {
            encrypted_message_aes = json::parse(decrypted_layer1_raw);
        } catch (...) {
            throw runtime_error("ChaCha20 sonrası AES JSON parse edilemedi!");
        }

        // 3) AES-GCM çöz
        CryptMessage decrypt_layer2;
        json pre_general_json2;
        pre_general_json2["AES"] = encrypted_message_aes;
        decrypt_layer2.set_general_json(pre_general_json2);

        string plaintext = decrypt_layer2.aes_gcm_decrypt();

        // 4) Redis'ten veriyi sil (opsiyonel)
        delete_from_redis(user_id);

        return plaintext;
    } catch (const exception& e) {
        cerr << "decrypt_2layer hata: " << e.what() << endl;
        throw;
    }
}

redisContext* connection_var() {
    redisContext* c = redis_connection(REDIS_HOST, REDIS_PORT);
    return c;
}

void set_to_redis(int user_id, const json& value) {
    redisContext* c = nullptr;
    try {
        c = connection_var();
        if (!c) {
            throw runtime_error("Redis bağlantısı başarısız!");
        }

        string key = to_string(user_id);
        string jsn_string = value.dump();
        set_redis(c, key.c_str(), jsn_string.c_str());
        redisFree(c);
    } catch (const exception& e) {
        if (c) redisFree(c);
        cout << "HATA: " << e.what() << endl;
        throw runtime_error(e.what());
    }
}

RedisResult get_from_redis(int user_id) {
    redisContext* c = nullptr;
    try {
        c = connection_var();
        if (!c) {
            throw runtime_error("Redis bağlantısı başarısız!");
        }

        string key = to_string(user_id);
        RedisResult r = get_redis(c, key.c_str());

        if (!r.ok) {
            cerr << "Hata: " << r.value << endl;
            throw runtime_error("Redis get failed: " + r.value);
        }
        redisFree(c);
        return r;
    } catch (const exception& e) {
        if (c) redisFree(c);
        cerr << "Redisten Veri Alma Hatası: " << e.what() << endl;
        throw runtime_error("Redis get failed");
    }
}

void delete_from_redis(int user_id) {
    redisContext* c = nullptr;
    try {
        c = connection_var();
        if (!c) {
            throw runtime_error("Redis bağlantısı başarısız!");
        }

        string key = to_string(user_id);
        RedisResult r = redis_delete(c, key.c_str());
        if (!r.ok) {
            cerr << "DEL hata: " << r.value << endl;
        } else {
            cout << "DEL " << key << " -> key silindi" << endl;
        }
        redisFree(c);
    } catch (const exception& e) {
        if (c) redisFree(c);
        cout << "Hata: " << e.what() << endl;
        throw runtime_error("Redis delete failed");
    }
}

// int main() {
//     if (sodium_init() < 0) {
//         throw runtime_error("Could not initialize libsodium.");
//     }
//
//     try {
//         string message = "Merhaba Benim Adım Yiğit Kağan Kılıç";
//         cout << "Orijinal mesaj: " << message << endl;
//
//         json encrypted_message = encrypt_2layer(message, 1);
//         cout << "Şifrelenmiş mesaj: " << encrypted_message.dump(4) << endl;
//
//         string decrypted_message = decrypt_2layer(1);
//         cout << "Çözülmüş mesaj: " << decrypted_message << endl;
//
//     } catch (const exception &e) {
//         cout << "ERROR: " << e.what() << endl;
//         return -1;
//     }
//
//     return 0;
// }