#include <iostream>
#include <stdexcept>
#include <sstream>
#include <type_traits>
#include <hiredis/hiredis.h>

using namespace std;

struct RedisResult {
    bool ok;                 // Komut başarılı mı
    string type;        // Tipi (string, integer, nil, error, array)
    string value;       // Eğer string ise değer
    long long intValue;      // Eğer integer ise değer
};

redisContext* redis_connection(const char* host, int port) {
    redisContext* conn = redisConnect(host, port);
    // cout << "here" << endl;
    if (conn == nullptr) {
        throw runtime_error("Bağlantı Başarısız");
    }
    if (conn->err) {
        if (conn) {
            cerr << "Redis bağlantı hatası: " << conn->errstr << endl;
            redisFree(conn);
            throw runtime_error("Redis Bağlantı Hatası");
        }
    }
    cout << "Bağlantı Başarılı" << endl;
    return conn;
}

template<class> inline constexpr bool always_false = false;

template<typename T>
void set_redis(redisContext* conn, const char* key, T value) {
    string command;

    if constexpr (is_same_v<T, string> || is_same_v<T, const char*>) {
        command = string("SET ") + key + " " + value;
    } else if constexpr (is_integral_v<T>) {      // int, long, bool
        command = string("SET ") + key + " " + to_string(value);
    } else if constexpr (is_floating_point_v<T>) { // float, double
        command = string("SET ") + key + " " + to_string(value);
    } else {
        static_assert(always_false<T>, "Unsupported type");
    }

    redisReply* reply = (redisReply*)redisCommand(conn, command.c_str());
    if (!reply) throw runtime_error("Redis SET failed");

    if (reply->type == REDIS_REPLY_STATUS && strcasecmp(reply->str, "OK") == 0) {
        cout << "SET başarılı: " << key << " -> " << command.substr(4 + strlen(key) + 1) << endl;
    } else {
        throw runtime_error("Redis SET hata");
    }

    freeReplyObject(reply);
}


RedisResult get_redis(redisContext* conn, const char* key) {
    redisReply* reply = (redisReply*)redisCommand(conn, "GET %s", key);
    if (reply == nullptr) {
        throw runtime_error("Değer Set Edilemedi");
    }
    RedisResult result;
    result.ok = true;
    result.intValue = 0;
    if(reply->type == REDIS_REPLY_ERROR) {
        result.ok = false;
        result.type = "error";
        result.value = reply->str ? reply->str : "";
    } else if(reply->type == REDIS_REPLY_INTEGER) {
        result.type = "integer";
        result.intValue = reply->integer;
    } else if(reply->type == REDIS_REPLY_NIL) {
        result.type = "nil";
        result.value = "";  // Key yok
    } else if(reply->type == REDIS_REPLY_STRING) {
        result.type = "string";
        result.value = reply->str ? reply->str : "";
    } else if(reply->type == REDIS_REPLY_ARRAY) {
        result.type = "array";
    }
    freeReplyObject(reply);
    cout << "YKKYKYKKYKYKYK: " <<result.value << endl;
    return result;
}

RedisResult redis_delete(redisContext* conn, const char* key) {
    redisReply* reply = (redisReply*)redisCommand(conn, "DEL %s", key);
        if (reply == nullptr) {
        throw runtime_error("Değer Silinemedi");
    }
    if (!reply) throw runtime_error("Redis DEL komutu başarısız");

    RedisResult result;
    result.ok = true;
    result.intValue = 0;

    if (reply->type == REDIS_REPLY_ERROR) {
        result.ok = false;
        result.type = "error";
        result.value = reply->str ? reply->str : "";
    }
    else if (reply->type == REDIS_REPLY_INTEGER) {
        result.type = "integer";
        result.intValue = reply->integer; // kaç key silindi
    }
    else {
        result.ok = false;
        result.type = "unknown";
    }

    freeReplyObject(reply);
    return result;
}

// int main() {
//     string host = "127.0.0.1";
//     int port = 6379;
//     redisContext* c = redis_connection(host.c_str(), port);

//     string key = "foo";
//     int value = 5;
//     set_redis(c, key.c_str(), value);

//     try {
//         // Örnek: foo key'ini al
//         RedisResult r = get_redis(c, "foo");

//         if (!r.ok) {
//             cerr << "Hata: " << r.value << endl;
//         } else if (r.type == "string") {
//             cout << "String" << endl;
//             cout << "GET foo -> " << r.value << endl;
//         } else if (r.type == "integer") {
//             cout << "Integer" << endl;
//             cout << "GET foo -> " << r.intValue << endl;
//         } else if (r.type == "nil") {
//             cout << "GET foo -> key bulunamadı" << endl;
//         }
//     } catch (const exception& e) {
//         cerr << "Exception: " << e.what() << endl;
//     }

//     RedisResult r = redis_delete(c, "foo");

//     if (!r.ok) {
//         cerr << "DEL hata: " << r.value << endl;
//     } else {
//         cout << "DEL foo -> " << r.intValue << " key silindi" << endl;
//     }

//     redisFree(c);

//     return 1;
// }

