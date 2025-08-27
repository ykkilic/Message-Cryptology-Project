#ifndef REDIS_UTILS_H
#define REDIS_UTILS_H

#include <string>
#include <hiredis/hiredis.h>

struct RedisResult {
    bool ok;                 // Komut başarılı mı
    std::string type;        // Tipi (string, integer, nil, error, array)
    std::string value;       // Eğer string ise değer
    long long intValue;      // Eğer integer ise değer
};

// Redis bağlantısı
redisContext* redis_connection(const char* host, int port);

// SET komutu (her veri tipini destekler)
template<class> inline constexpr bool always_false = false;

template<typename T>
void set_redis(redisContext* conn, const char* key, T value) {
    std::string command;

    if constexpr (std::is_same_v<T, std::string> || std::is_same_v<T, const char*>) {
        command = std::string("SET ") + key + " " + value;
    } else if constexpr (std::is_integral_v<T>) {
        command = std::string("SET ") + key + " " + std::to_string(value);
    } else if constexpr (std::is_floating_point_v<T>) {
        command = std::string("SET ") + key + " " + std::to_string(value);
    } else {
        static_assert(always_false<T>, "Unsupported type");
    }

    redisReply* reply = (redisReply*)redisCommand(conn, command.c_str());
    if (!reply) throw std::runtime_error("Redis SET failed");

    if (reply->type == REDIS_REPLY_STATUS && strcasecmp(reply->str, "OK") == 0) {
        std::cout << "SET başarılı: " << key << " -> " << command.substr(4 + strlen(key) + 1) << std::endl;
    } else {
        throw std::runtime_error("Redis SET hata");
    }

    freeReplyObject(reply);
}
// GET komutu
RedisResult get_redis(redisContext* conn, const char* key);

// DEL komutu
RedisResult redis_delete(redisContext* conn, const char* key);

#endif // REDIS_UTILS_H
