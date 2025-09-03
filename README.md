Encrypted Blockchain Implementation
A C++ implementation of a proof-of-work blockchain with advanced two-layer encryption (AES-GCM + ChaCha20) and database persistence.
🔧 Features
Proof-of-Work Mining: Configurable difficulty mining system
Two-Layer Encryption:
Layer 1: AES-GCM encryption
Layer 2: ChaCha20 encryption
Database Persistence: PostgreSQL integration for blockchain storage
Redis Caching: Encrypted key management using Redis
Block Validation: Complete blockchain integrity verification
SHA-256 Hashing: Secure block hashing using OpenSSL
📋 Prerequisites
Dependencies
OpenSSL: For cryptographic functions
PostgreSQL: Database storage (libpq-dev)
Redis: Key-value storage for encryption keys
Custom Libraries:
redis_utils.h
db_utils.h
cryptology.h
System Requirements
C++11 or higher
PostgreSQL server
Redis server
Linux/Unix environment (recommended)
🚀 Installation
1. Install System Dependencies
   Ubuntu/Debian:
   bash
   sudo apt-get update
   sudo apt-get install libssl-dev libpq-dev redis-server postgresql postgresql-contrib
   CentOS/RHEL:
   bash
   sudo yum install openssl-devel postgresql-devel redis
2. Database Setup
   sql
   -- Create database
   CREATE DATABASE blockchain;

-- Create user
CREATE USER postgres WITH PASSWORD 'Bjk1903';
GRANT ALL PRIVILEGES ON DATABASE blockchain TO postgres;

-- Create table
CREATE TABLE blockchain (
id SERIAL PRIMARY KEY,
block_index INTEGER NOT NULL,
timestamp REAL NOT NULL,
data TEXT NOT NULL,
previous_hash VARCHAR(64) NOT NULL,
nonce INTEGER NOT NULL,
hash VARCHAR(64) NOT NULL,
user_id INTEGER NOT NULL,
difficulty INTEGER NOT NULL
);
3. Redis Setup
   bash
# Start Redis server
sudo systemctl start redis-server
sudo systemctl enable redis-server

# Verify Redis is running
redis-cli ping
4. Compilation
   bash
# Clone the repository
git clone <repository-url>
cd blockchain-project

# Compile
g++ -std=c++11 -o blockchain main.cpp -lssl -lcrypto -lpq -lredis
🎯 Usage
Basic Example
cpp
#include "blockchain.h"

int main() {
const int difficulty = 2;  // Mining difficulty
int user_id = 1;

    // Create blockchain
    Blockchain blockchain(difficulty, user_id);
    
    // Prepare data
    vector<string> messages = {
        "First Block Data",
        "Hello Blockchain",
        "Encrypted Message"
    };
    
    // Encrypt and add to blockchain
    encrypt_message(blockchain, messages, user_id);
    
    // Print blockchain
    print_chain(blockchain);
    
    // Decrypt and display
    decrypt_chain(user_id);
    
    return 0;
}
Configuration
Update database connection in the code:
cpp
constexpr const char* CONN_INFO = "host=localhost port=5432 dbname=blockchain user=postgres password=YourPassword";
🔐 Encryption Process
Input: Plain text message
Layer 1: AES-GCM encryption
Layer 2: ChaCha20 encryption
Storage:
Ciphertext stored in blockchain
Encryption keys stored in Redis with unique block identifiers
Mining: Proof-of-work mining with configurable difficulty
Database: Complete blockchain stored in PostgreSQL
🏗️ Architecture
Core Classes
Block
Stores block data (index, timestamp, data, hash, nonce)
Implements proof-of-work mining
Hash calculation using SHA-256
Blockchain
Manages chain of blocks
Validates blockchain integrity
Configurable mining difficulty
Key Functions
encrypt_2layer_with_block(): Two-layer encryption
decrypt_2layer_with_block(): Two-layer decryption
is_chain_valid(): Blockchain validation
insert_blockchain_to_db(): Database persistence
🔧 API Reference
Core Functions
cpp
// Blockchain Management
Blockchain(int difficulty, int user_id);
void add_block(string data);
bool is_chain_valid(Blockchain& blockchain);

// Encryption/Decryption
json encrypt_2layer_with_block(const string& message, int user_id, int block_index);
string decrypt_2layer_with_block(int user_id, int block_index);

// Database Operations
void insert_blockchain_to_db(Blockchain& blockchain);
void decrypt_chain(int user_id);

// Redis Operations
void set_to_redis_with_block(int user_id, int block_index, const json& encrypted_data);
RedisResult get_from_redis_with_block(int user_id, int block_index);
📊 Performance
The current implementation includes a stress test loop that:
Creates 10,000 users
Each user adds 6 encrypted blocks
Total: 60,000 encrypted blocks
Demonstrates scalability and performance
🛡️ Security Features
SHA-256: Cryptographically secure hashing
AES-GCM: Authenticated encryption with 256-bit keys
ChaCha20: Stream cipher for additional security layer
Proof-of-Work: Prevents blockchain manipulation
Key Isolation: Separate Redis keys per user and block
🚨 Important Notes
Database Credentials: Change default PostgreSQL credentials in production
Redis Security: Configure Redis authentication for production use
Key Management: Encryption keys are stored in Redis - ensure Redis persistence
Mining Difficulty: Higher difficulty increases security but reduces performance
🐛 Troubleshooting
Common Issues
Database Connection Failed:
bash
# Check PostgreSQL status
sudo systemctl status postgresql
# Check connection
psql -h localhost -U postgres -d blockchain
Redis Connection Failed:
bash
# Check Redis status
sudo systemctl status redis-server
# Test connection
redis-cli ping
Compilation Errors:
bash
# Install missing headers
sudo apt-get install build-essential
# Check library paths
pkg-config --cflags --libs openssl
📄 License
This project is licensed under the MIT License - see the LICENSE file for details.
🤝 Contributing
Fork the repository
Create your feature branch (git checkout -b feature/AmazingFeature)
Commit your changes (git commit -m 'Add some AmazingFeature')
Push to the branch (git push origin feature/AmazingFeature)
Open a Pull Request
📞 Support
For support and questions:
Create an issue in the GitHub repository
Check the troubleshooting section above
Review the code documentation
⚠️ Warning: This is an educational/experimental implementation. Do not use in production without thorough security review and testing.
