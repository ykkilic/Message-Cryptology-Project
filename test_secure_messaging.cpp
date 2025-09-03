#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <openssl/evp.h>
#include <chrono>
#include <libpq-fe.h>
#include "redis_utils.h"
#include "db_utils.h"
#include "cryptology.h"

using namespace std;

constexpr const char* CONN_INFO = "host=localhost port=5432 dbname=blockchain user=postgres password=Bjk1903";

string sha256(const string &input) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int length = 0;

    EVP_MD_CTX* context = EVP_MD_CTX_new();
    EVP_DigestInit_ex(context, EVP_sha256(), nullptr);
    EVP_DigestUpdate(context, input.c_str(), input.size());
    EVP_DigestFinal_ex(context, hash, &length);
    EVP_MD_CTX_free(context);

    stringstream ss;
    for (unsigned int i = 0; i < length; ++i)
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    return ss.str();
}

double get_current_timestamp() {
    auto now = chrono::system_clock::now();
    double duration_float = chrono::duration_cast<chrono::microseconds>(
        now.time_since_epoch()
    ).count() / 1e6;
    return duration_float;
}

class Block {
    private:
        int index;
        float timestamp;
        string data;
        string previousHash;
        int nonce = 0;
        string hash = calculateHash();
    public:
        Block(int inx, float tmstmp, string dt, string prevHash) {
            this->index = inx;
            this->timestamp = tmstmp;
            this->data = dt;
            this->previousHash = prevHash;
        }

        string calculateHash() {
            string value = to_string(this->index) + to_string(this->timestamp) + this->data + this->previousHash + to_string(this->nonce);
            return sha256(value);
        }

        void mineBlock(int difficulty){
            string target(difficulty, '0');
            int attempt = 0;
            while (hash.substr(0, difficulty) != target) {
                this->nonce++;
                this->hash = calculateHash();
                attempt++;
            }
            cout << "Blok Madenciliği başarıyla yapıldı! Hash: " << this->hash << endl;
            cout << "Deneme Sayısı: " << attempt << endl;
        }

        // GETTER METHODS
        int& getIndex(){
            return index;
        }
        float& getTimestamp() {
            return timestamp;
        }
        string& getData() {
            return data;
        }
        string& getPreviousHash() {
            return previousHash;
        }
        int& getNonce() {
            return nonce;
        }
        string& getHash() {
            return hash;
        }
};

class Blockchain {
    private:
        vector<Block> chain;
        int difficulty;
        int userId;
    public:

        Blockchain(int difficult, int user_id){
            this->chain.push_back(create_genesis_block());
            this->difficulty = difficult;
            this->userId = user_id;
        }

        Block create_genesis_block(){
            return Block(0, get_current_timestamp(), "Genesis Block", "0");
        }
        Block get_last_block(){
            return chain.back();
        }
        void add_block(string data){
            Block last_block = get_last_block();
            Block new_block = Block(this->chain.size(), get_current_timestamp(), data, last_block.getHash());
            new_block.mineBlock(this->difficulty);
            this->chain.push_back(new_block);
        }

        vector<Block>& getChain() {
            return this->chain;
        }

        int getDifficulty() {
            return this->difficulty;
        }

        int getUserId() {
            return this->userId;
        }

        void setUserId(int user_id) {
            this->userId = user_id;
        }
};

bool is_chain_valid(Blockchain& blockchain){
    for (size_t i = 1; i < blockchain.getChain().size(); ++i) {
        Block& current = blockchain.getChain()[i];
        Block& previous = blockchain.getChain()[i-1];
        if (current.getHash() != current.calculateHash()) {
            return false;
        }
        if (current.getPreviousHash() != previous.getHash()) {
            return false;
        }
    }
    return true;
}

void print_chain(Blockchain& blockchain){
    for (Block block : blockchain.getChain()) {
        cout << "---------------------------------------------" << endl;
        cout << "Index: " << block.getIndex() << endl;
        cout << "Timestamp: " << block.getTimestamp() << endl;
        cout << "Data: " << block.getData() << endl;
        cout << "Previous Hash: " << block.getPreviousHash() << endl;
        cout << "Hash: " << block.getHash() << endl;
        cout << "---------------------------------------------" << endl;
    }
    cout << "Blockchain uzunluğu: " << blockchain.getChain().size() << endl;
}

void insert_blockchain_to_db(Blockchain& blockchain) {
    PGconn* conn = connection(CONN_INFO);
    PGresult* res = nullptr;

    for (Block block : blockchain.getChain()) {
        int *indis = &(block.getIndex());
        float *tmstmp = &(block.getTimestamp());
        string *data = &(block.getData());
        string *previous_hash = &(block.getPreviousHash());
        int *nonce = &(block.getNonce());
        string *hash = &(block.getHash());

        string control_query = "SELECT EXISTS (SELECT 1 FROM blockchain WHERE data ='"+ *data +"' AND user_id = '"+to_string(blockchain.getUserId())+"');";
        PGresult* control = exec_query(conn, control_query.c_str());

        if (!control) {
            cerr << "exec_query null döndü!" << endl;
            PQfinish(conn);
            return;
        }

        bool exists = (strcmp(PQgetvalue(control, 0, 0), "t") == 0);
        PQclear(control);

        if (exists) {
            cout << "Veri Zaten Mevcut" << endl;
            continue;
        } else {
            string query = "INSERT INTO blockchain(block_index, timestamp, data, previous_hash, nonce, hash, user_id, difficulty) VALUES ("
               + to_string(*indis) + ", "
               + to_string(*tmstmp) + ", "
               + "'" + *data + "', "
               + "'" + *previous_hash + "', "
               + to_string(*nonce) + ", "
               + "'" + *hash + "'"+ ", "
               + to_string(blockchain.getUserId()) + ","
               + to_string(blockchain.getDifficulty() + 5551) +");";

            res = exec_query(conn, query.c_str());
            if (res) {
                PQclear(res);
            }
        }
    }
    PQfinish(conn);
}

// Redis'te her block için benzersiz anahtar kullanarak şifreleme anahtarlarını sakla
void set_to_redis_with_block(int user_id, int block_index, const json& encrypted_data) {
    redisContext* conn = connection_var();
    if (!conn) {
        throw runtime_error("Redis bağlantısı başarısız!");
    }

    string key = "user:" + to_string(user_id) + ":block:" + to_string(block_index);
    string value = encrypted_data.dump();

    try {
        set_redis(conn, key.c_str(), value);
        cout << "Redis'e kaydedildi: " << key << endl;
    } catch (const exception& e) {
        redisFree(conn);
        throw runtime_error("Redis SET başarısız: " + string(e.what()));
    }

    redisFree(conn);
}

// Redis'ten belirli block için veri al
RedisResult get_from_redis_with_block(int user_id, int block_index) {
    redisContext* conn = connection_var();
    if (!conn) {
        throw runtime_error("Redis bağlantısı başarısız!");
    }

    string key = "user:" + to_string(user_id) + ":block:" + to_string(block_index);

    RedisResult result;
    try {
        result = get_redis(conn, key.c_str());
    } catch (const exception& e) {
        result.ok = false;
        result.value = "Redis GET hatası: " + string(e.what());
    }

    redisFree(conn);
    return result;
}

// Redis'ten belirli key'i sil
void delete_from_redis_with_block(int user_id, int block_index) {
    redisContext* conn = connection_var();
    if (!conn) {
        throw runtime_error("Redis bağlantısı başarısız!");
    }

    string key = "user:" + to_string(user_id) + ":block:" + to_string(block_index);

    try {
        RedisResult result = redis_delete(conn, key.c_str());
        if (result.ok) {
            cout << "Redis'ten silindi: " << key << endl;
        } else {
            cout << "Redis silme hatası: " << result.value << endl;
        }
    } catch (const exception& e) {
        cout << "Redis delete hatası: " << e.what() << endl;
    }

    redisFree(conn);
}

// Belirli block için çözme fonksiyonu
string decrypt_2layer_with_block(int user_id, int block_index) {
    try {
        // Redis'ten belirli block için şifreleme bilgilerini al
        RedisResult result = get_from_redis_with_block(user_id, block_index);
        if (!result.ok || result.value.empty()) {
            throw runtime_error("Redis'ten veri alınamadı: " + result.value);
        }

        json encrypted_chacha = json::parse(result.value);

        cout << "DLKSDSKDSLKDSLKDSLKDSK" << endl;

        // ChaCha20 çöz
        CryptMessage decrypt_layer1;
        json pre_general_json1;
        pre_general_json1["chacha"] = encrypted_chacha;
        decrypt_layer1.set_general_json(pre_general_json1);

        string decrypted_layer1_raw = decrypt_layer1.decrypt_ChaCha20();

        // AES JSON parse et
        json encrypted_message_aes;
        try {
            encrypted_message_aes = json::parse(decrypted_layer1_raw);
        } catch (...) {
            throw runtime_error("ChaCha20 sonrası AES JSON parse edilemedi!");
        }

        // AES-GCM çöz
        CryptMessage decrypt_layer2;
        json pre_general_json2;
        pre_general_json2["AES"] = encrypted_message_aes;
        decrypt_layer2.set_general_json(pre_general_json2);

        string plaintext = decrypt_layer2.aes_gcm_decrypt();

        // Başarılı çözme sonrası Redis key'ini sil (opsiyonel)
        // delete_from_redis_with_block(user_id, block_index);

        return plaintext;
    } catch (const exception& e) {
        cerr << "decrypt_2layer_with_block hata: " << e.what() << endl;
        throw;
    }
}

// Şifreleme fonksiyonu - her block için benzersiz key ile
json encrypt_2layer_with_block(const string& message, int user_id, int block_index) {
    // Layer 1: AES-GCM
    CryptMessage crypt_layer1;
    crypt_layer1.set_plaintext_str(message);
    json encrypted_message_aes = crypt_layer1.aes_gcm_encrypt_string();

    // Layer 2: ChaCha20
    CryptMessage crypt_layer2;
    crypt_layer2.set_plaintext_str(encrypted_message_aes.dump());
    json encrypted_chacha = crypt_layer2.encrypt_ChaCha20();

    // Redis'e block bazlı kaydet
    set_to_redis_with_block(user_id, block_index, encrypted_chacha);

    return encrypted_chacha;
}

vector<string> encrypt_message(Blockchain& blockchain, vector<string> data, int user_id) {
    try {
        for (int i = 0; i < data.size(); i++) {
            // Her block için benzersiz indeks kullan (genesis block hariç)
            int block_index = blockchain.getChain().size(); // Yeni block'un index'i

            // 2 katmanlı şifreleme - block index ile
            json encrypted_message = encrypt_2layer_with_block(data[i], user_id, block_index);

            // Blockchain'e sadece ciphertext yazıyoruz
            data[i] = encrypted_message["ciphertext"];

            // Blockchain'e block ekle
            blockchain.add_block(data[i]);

            cout << "Block " << block_index << " şifrelendi ve eklendi" << endl;
        }

        // Blockchain'i DB'ye kaydet
        insert_blockchain_to_db(blockchain);

        return data;
    } catch (exception& e) {
        throw runtime_error(e.what());
    }
}

void decrypt_chain(int user_id) {
    PGconn* conn = connection(CONN_INFO);
    string control_query = "SELECT block_index, data FROM blockchain WHERE user_id=" + to_string(user_id) + " ORDER BY block_index";
    PGresult* res = exec_query(conn, control_query.c_str());

    if (!res) {
        throw runtime_error("exec_query failed");
    }

    int rowCount = PQntuples(res);

    cout << "Toplam " << rowCount << " block bulundu" << endl;

    // Her block için çözme işlemi
    for (int i = 0; i < rowCount; ++i) {
        const char* block_index_str = PQgetvalue(res, i, 0);
        const char* ciphertext = PQgetvalue(res, i, 1);

        if (!block_index_str || !ciphertext) continue;

        int block_index = atoi(block_index_str);

        cout << "\n--- Block " << block_index << " ---" << endl;
        cout << "Ciphertext (DB): " << ciphertext << endl;

        // Genesis block'u çözmeye çalışma
        if (block_index == 0 && string(ciphertext) == "Genesis Block") {
            cout << "Genesis Block - Çözme işlemi yapılmadı" << endl;
            continue;
        }

        try {
            // Block index ile çöz
            string decrypted = decrypt_2layer_with_block(user_id, block_index);
            cout << "Çözülen veri: " << decrypted << endl;
        } catch (const exception& e) {
            cerr << "Decrypt hatası (block " << block_index << "): " << e.what() << endl;
        }
    }

    PQclear(res);
    PQfinish(conn);
}

int main() {
    // Test için yeni veri şifreleme
    const int difficulty = 1;
    int user_id = 1;
    Blockchain blockchain(difficulty, user_id);

    int counter = 0;
    while (counter < 10000) {
        vector<string> messageList;
        messageList.push_back("İlk Veri");
        messageList.push_back("Merhaba Ben Yiğit Kağan Kılıç");
        messageList.push_back("Türkiyede Yaşıyorum");
        messageList.push_back("Babamın ismi İsmail");
        messageList.push_back("En Büyük Allah");
        messageList.push_back("Blok Veri");

        cout << "=== Şifreleme İşlemi ===" << endl;
        encrypt_message(blockchain, messageList, user_id);
        user_id++;
        counter++;
    }


    // vector<string> messageList;
    // messageList.push_back("İlk Veri");
    // messageList.push_back("Merhaba Ben Yiğit Kağan Kılıç");
    // messageList.push_back("Türkiyede Yaşıyorum");
    // messageList.push_back("Babamın ismi İsmail");
    // messageList.push_back("En Büyük Allah");
    // messageList.push_back("Blok Veri");
    //
    //
    // cout << "=== Şifreleme İşlemi ===" << endl;
    // encrypt_message(blockchain, messageList, user_id);
    //
    // cout << "\n=== Blockchain Yazdırma ===" << endl;
    // print_chain(blockchain);
    //
    // cout << "\n=== Çözme İşlemi ===" << endl;
    // decrypt_chain(user_id);

    return 0;
}