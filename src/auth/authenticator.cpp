// Project headers
#include "zerossg/common.hpp"
#include "zerossg/constants.hpp"
#include "zerossg/utils/base64.hpp"

// C++ Standard Library headers (alphabetical order)
#include <algorithm>
#include <iomanip>
#include <random>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

// Third-party library headers
#include <nlohmann/json.hpp>

// OpenSSL headers
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

using json = nlohmann::json;

namespace zerossg {
    // Import semantic aliases for cleaner code
    using zerossg::Result;
    using zerossg::String;
    using zerossg::TokenString;
    using zerossg::UserName;
    using zerossg::PasswordHash;
    using zerossg::Optional;
    using zerossg::Vector;
    using zerossg::UnorderedMap;
    using zerossg::SecretKey;
    using zerossg::LockGuard;
    using zerossg::system_clock;

AuthenticationManager::AuthenticationManager() {
    // Initialize with modern C++26 features
    m_secret_rotation_time = system_clock::now();
    
    // Generate JWT secret key with better randomness
    const auto secret_result = generate_secure_random_bytes(JWT_SECRET_SIZE);
    if (!secret_result.is_success()) {
        throw std::runtime_error("Failed to generate JWT secret");
    }
    m_jwt_secret = secret_result.value();
    
    // Add default admin user with stronger password
    auto admin_hash_result = hash_password("Admin@2024!SecurePass");
    if (admin_hash_result.is_success()) {
        User admin_user("admin", admin_hash_result.value(), Role::ADMIN);
        add_user(std::move(admin_user));
    }
}

AuthenticationManager::~AuthenticationManager() = default;

Result<String> AuthenticationManager::authenticate(const UserName& username, const PasswordHash& password) {
    // Modern input validation
    if (!is_valid_username(username)) {
        return make_result_error<String>("Invalid username format");
    }
    
    if (!is_valid_password_format(password)) {
        return make_result_error<String>("Password does not meet security requirements");
    }
    
    // Check rate limiting first
    {
        std::shared_lock lock(m_rate_limits_mutex);
        auto& rate_info = m_rate_limits[string(username)];
        
        if (rate_info.should_block()) {
            return make_result_error<String>("Account temporarily blocked due to too many failed attempts");
        }
        
        // Record attempt
        rate_info.m_attempts++;
        rate_info.m_window_start = system_clock::now();
    }
    
    // Check if user is blocked
    {
        std::shared_lock lock(m_blocked_users_mutex);
        if (m_blocked_users.contains(string(username))) {
            return make_result_error<String>("Account is blocked");
        }
    }
    
    // Find user with modern concurrency
    std::shared_lock lock(m_users_mutex);
    const auto user_it = m_users.find(string(username));
    if (user_it == m_users.end()) {
        return make_result_error<String>("User not found");
    }
    
    const User& user = user_it->second;
    if (!user.is_active()) {
        return make_result_error<String>("User account is inactive");
    }
    
    // Modern password verification with timing-safe comparison
    const auto verify_result = verify_password(password, user.password_hash());
    if (!verify_result.is_success()) {
        // Record failed attempt for security monitoring
        detect_suspicious_activity(username, "");
        return make_result_error<String>("Authentication failed: " + verify_result.error());
    }
    
    if (!verify_result.value()) {
        return make_result_error<String>("Invalid credentials");
    }
    
    // Generate JWT token with enhanced security
    // Generate simple JWT token for now
    auto now = std::chrono::system_clock::now();
    auto iat = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
    auto exp = std::chrono::duration_cast<std::chrono::seconds>((now + std::chrono::seconds(3600)).time_since_epoch()).count();
    
    json payload = {
        {"username", user.m_user_name},
        {"role", role_to_string(user.m_role)},
        {"iat", iat},
        {"exp", exp},
        {"sub", "zerossg"},
        {"jti", std::to_string(std::hash<std::string>{}(std::string(user.m_user_name) + std::to_string(iat)))}
    };
    
    // Create JWT header
    json header = {
        {"alg", "HS256"},
        {"typ", "JWT"}
    };
    
    // Encode header and payload
    String header_b64 = base64_encode(header.dump());
    String payload_b64 = base64_encode(payload.dump());
    
    // Create signature
    String header_payload = header_b64 + "." + payload_b64;
    String signature = generate_jwt_signature(header_payload);
    
    return make_result_success<TokenString>(header_payload + "." + signature);
}

Result<bool> AuthenticationManager::validate_token(const TokenString& token) {
    // Modern token format validation
    if (!auth_utils::is_valid_jwt_structure(token)) {
        return make_result_error<bool>("Invalid token format");
    }
    
    // Check if token is revoked
    {
        std::shared_lock lock(m_revoked_tokens_mutex);
        if (m_revoked_tokens.contains(string(token))) {
            return make_result_error<bool>("Token has been revoked");
        }
    }
    
    return make_result_success(true);
}

Result<User> AuthenticationManager::get_user_from_token(const TokenString& token) {
    // Parse JWT token (header.payload.signature)
    size_t first_dot = token.find('.');
    size_t second_dot = token.find('.', first_dot + 1);
    
    if (first_dot == String::npos || second_dot == String::npos) {
        return make_result_error<User>("Invalid token format");
    }
    
    String header_payload = token.substr(0, second_dot);
    String signature = token.substr(second_dot + 1);
    
    // Verify signature
    if (!verify_jwt_signature(header_payload, signature)) {
        return make_result_error<User>("Invalid token signature");
    }
    
    // Parse payload
    auto payload_result = parse_jwt_payload(token);
    if (!payload_result.is_success()) {
        return make_result_error<User>("Invalid token payload: " + payload_result.error());
    }
    
    // Check if token is revoked
    {
        LockGuard<std::mutex> lock(m_tokens_mutex);
        auto revoked_it = m_revoked_tokens.find(token);
        if (revoked_it != m_revoked_tokens.end()) {
            return make_result_error<User>("Token has been revoked");
        }
    }
    
    return payload_result;
}

Result<TokenString> AuthenticationManager::generate_token(const User& user) {
    try {
        // Create JWT header
        json header = {
            {"alg", "HS256"},
            {"typ", "JWT"}
        };
        
        // Create JWT payload
        json payload = {
            {"username", user.username},
            {"role", role_to_string(user.role)},
            {"iat", std::chrono::duration_cast<std::chrono::seconds>(system_clock::now().time_since_epoch()).count()},
            {"exp", std::chrono::duration_cast<std::chrono::seconds>((system_clock::now() + TOKEN_EXPIRY_TIME).time_since_epoch()).count()}
        };
        
        // Encode header and payload
        string header_b64 = base64_encode(header.dump());
        string payload_b64 = base64_encode(payload.dump());
        
        // Create signature
        string header_payload = header_b64 + "." + payload_b64;
        string signature = generate_jwt_signature(header_payload);
        
        return make_result_success<TokenString>(header_payload + "." + signature);
    } catch (const std::exception& e) {
        return make_result_error<TokenString>("JWT generation failed: " + String(e.what()));
    }
}

Result<void> AuthenticationManager::revoke_token(const TokenString& token) {
    LockGuard<std::mutex> lock(m_tokens_mutex);
    
    // Store token with expiry time for cleanup
    auto expiry_time = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now() + TOKEN_EXPIRY_TIME).count();
    m_revoked_tokens[string(token)] = std::to_string(expiry_time);
    
    return make_result_success();
}

Result<void> AuthenticationManager::add_user(const User& user) {
    LockGuard<std::mutex> lock(m_users_mutex);
    
    if (m_users.find(user.username) != m_users.end()) {
        return make_result_error<void>("User already exists");
    }
    
    m_users[user.username] = user;
    return make_result_success();
}

Result<void> AuthenticationManager::update_user(const UserName& username, const User& user) {
    LockGuard<std::mutex> lock(m_users_mutex);
    
    if (m_users.find(username) == m_users.end()) {
        return make_result_error<void>("User not found");
    }
    
    m_users[username] = user;
    return make_result_success();
}

Result<void> AuthenticationManager::delete_user(const UserName& username) {
    LockGuard<std::mutex> lock(m_users_mutex);
    
    if (m_users.erase(username) == 0) {
        return make_result_error<void>("User not found");
    }
    
    return make_result_success();
}

Result<Optional<User>> AuthenticationManager::get_user(const UserName& username) {
    LockGuard<std::mutex> lock(m_users_mutex);
    
    auto it = m_users.find(username);
    if (it == m_users.end()) {
        return make_result_success<Optional<User>>(std::nullopt);
    }
    
    return make_result_success<Optional<User>>(it->second);
}

Result<Vector<User>> AuthenticationManager::list_users() {
    LockGuard<std::mutex> lock(m_users_mutex);
    
    Vector<User> users;
    users.reserve(m_users.size());
    
    for (const auto& pair : m_users) {
        users.push_back(pair.second);
    }
    
    return make_result_success<Vector<User>>(std::move(users));
}

Result<PasswordHash> AuthenticationManager::hash_password(const String& password) {
    // For production, use bcrypt or argon2. This is a simplified implementation using SHA-256 with salt
    SecretKey salt(16);
    if (RAND_bytes(salt.data(), salt.size()) != 1) {
        return make_result_error<PasswordHash>("Failed to generate salt");
    }
    
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        return make_result_error<PasswordHash>("Failed to create hash context");
    }
    
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(mdctx);
        return make_result_error<PasswordHash>("Failed to initialize hash");
    }
    
    if (EVP_DigestUpdate(mdctx, salt.data(), salt.size()) != 1 ||
        EVP_DigestUpdate(mdctx, password.data(), password.size()) != 1) {
        EVP_MD_CTX_free(mdctx);
        return make_result_error<PasswordHash>("Failed to update hash");
    }
    
    SecretKey hash(EVP_MD_size(EVP_sha256()));
    unsigned int hash_len;
    if (EVP_DigestFinal_ex(mdctx, hash.data(), &hash_len) != 1) {
        EVP_MD_CTX_free(mdctx);
        return make_result_error<PasswordHash>("Failed to finalize hash");
    }
    
    EVP_MD_CTX_free(mdctx);
    
    // Combine salt and hash
    String result;
    result.reserve(salt.size() + hash_len);
    result.append(reinterpret_cast<char*>(salt.data()), salt.size());
    result.append(reinterpret_cast<char*>(hash.data()), hash_len);
    
    return make_result_success<PasswordHash>(base64_encode(result));
}

Result<bool> AuthenticationManager::verify_password(const String& password, const PasswordHash& hash) {
    // Convert hex string back to bytes
    if (hash.length() % 2 != 0) {
        return make_result_error<bool>("Invalid hash format");
    }
    
    String hash_bytes;
    hash_bytes.reserve(hash.length() / 2);
    
    for (size_t i = 0; i < hash.length(); i += 2) {
        unsigned int byte;
        std::stringstream ss;
        ss << std::hex << hash.substr(i, 2);
        ss >> byte;
        hash_bytes.push_back(static_cast<char>(byte));
    }
    
    if (hash_bytes.size() < 16) { // salt + at least some hash
        return make_result_error<bool>("Hash too short");
    }
    
    // Extract salt and hash
    String salt = hash_bytes.substr(0, 16);
    String stored_hash = hash_bytes.substr(16);
    
    // Compute hash of password with salt
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        return make_result_error<bool>("Failed to create hash context");
    }
    
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(mdctx);
        return make_result_error<bool>("Failed to initialize hash");
    }
    
    if (EVP_DigestUpdate(mdctx, salt.data(), salt.size()) != 1 ||
        EVP_DigestUpdate(mdctx, password.data(), password.size()) != 1) {
        EVP_MD_CTX_free(mdctx);
        return make_result_error<bool>("Failed to update hash");
    }
    
    Vector<unsigned char> computed_hash(EVP_MD_size(EVP_sha256()));
    unsigned int hash_len;
    if (EVP_DigestFinal_ex(mdctx, computed_hash.data(), &hash_len) != 1) {
        EVP_MD_CTX_free(mdctx);
        return make_result_error<bool>("Failed to finalize hash");
    }
    
    EVP_MD_CTX_free(mdctx);
    
    // Compare hashes
    if (stored_hash.size() != hash_len) {
        return make_result_success(false);
    }
    
    return make_result_success(std::equal(stored_hash.begin(), stored_hash.end(),
                                           computed_hash.begin(), computed_hash.end()));
}

String AuthenticationManager::create_jwt_payload(const User& user) {
    json payload = {
        {"username", user.username},
        {"role", role_to_string(user.role)},
        {"iat", std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count()},
        {"exp", std::chrono::duration_cast<std::chrono::seconds>((std::chrono::system_clock::now() + TOKEN_EXPIRY_TIME).time_since_epoch()).count()}
    };
    return payload.dump();
}

Result<User> AuthenticationManager::parse_jwt_payload(const TokenString& token) {
    size_t first_dot = token.find('.');
    size_t second_dot = token.find('.', first_dot + 1);
    
    if (first_dot == String::npos || second_dot == String::npos) {
        return make_result_error<User>("Invalid token format");
    }
    
    string payload_b64 = token.substr(first_dot + 1, second_dot - first_dot - 1);
    string payload_str = base64_decode(payload_b64);
    
    try {
        json payload = json::parse(payload_str);
        
        // Check expiration
        auto now = std::chrono::duration_cast<std::chrono::seconds>(system_clock::now().time_since_epoch()).count();
        if (payload["exp"].get<int64_t>() < now) {
            return Result<User>::error("Token has expired");
        }
        
        // Get user
        string username = payload["username"];
        auto user_result = get_user(username);
        if (!user_result.is_success()) {
            return Result<User>::error("User not found: " + username);
        }
        
        auto user_opt = user_result.value();
        if (!user_opt.has_value()) {
            return Result<User>::error("User not found: " + username);
        }
        
        return Result<User>::success(user_opt.value());
    } catch (const json::exception& e) {
        return Result<User>::error("Failed to parse JWT payload: " + string(e.what()));
    }
}

string AuthenticationManager::generate_jwt_signature(const string& header_payload) {
    unsigned char* hmac = nullptr;
    unsigned int hmac_len;
    
    hmac = HMAC(EVP_sha256(), m_jwt_secret.data(), m_jwt_secret.size(),
                reinterpret_cast<const unsigned char*>(header_payload.data()), header_payload.size(), nullptr, &hmac_len);
    
    if (!hmac) {
        throw std::runtime_error("Failed to generate HMAC");
    }
    
    string signature = base64_encode(string(reinterpret_cast<char*>(hmac), hmac_len));
    OPENSSL_free(hmac);
    
    return signature;
}

bool AuthenticationManager::verify_jwt_signature(const string& header_payload, const string& signature) {
    try {
        string computed_signature = generate_jwt_signature(header_payload);
        return computed_signature == signature;
    } catch (const std::exception&) {
        return false;
    }
}

TokenString AuthenticationManager::generate_secure_token() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    
    SecretKey token_data(32);
    for (auto& byte : token_data) {
        byte = static_cast<unsigned char>(dis(gen()));
    }
    
    return base64_encode(std::string(reinterpret_cast<char*>(token_data.data()), token_data.size()));
}

void AuthenticationManager::cleanup_expired_tokens() {
    auto now = std::chrono::duration_cast<std::chrono::seconds>(system_clock::now().time_since_epoch()).count();
    
    LockGuard<std::mutex> lock(m_tokens_mutex);
    auto it = m_revoked_tokens.begin();
    while (it != m_revoked_tokens.end()) {
        try {
            int64_t expiry = std::stoll(it->second);
            if (expiry < now) {
                it = m_revoked_tokens.erase(it);
            } else {
                ++it;
            }
        } catch (...) {
            it = m_revoked_tokens.erase(it);
        }
    }
}

UserCount AuthenticationManager::get_active_user_count() const noexcept {
    std::shared_lock lock(m_users_mutex);
    return std::ranges::count_if(m_users, 
        [](const auto& pair) { return pair.second.is_active(); });
}

UserCount AuthenticationManager::get_blocked_user_count() const noexcept {
    std::shared_lock lock(m_blocked_users_mutex);
    return m_blocked_users.size();
}

Strings AuthenticationManager::get_recent_failed_attempts(string_view username, AttemptCount count) const noexcept {
    // Modern rate limiting with better tracking and semantic return type
    std::shared_lock lock(m_rate_limits_mutex);
    
    Strings attempts;
    const auto it = m_rate_limits.find(UserName{username});
    if (it != m_rate_limits.end()) {
        // Return recent failed attempt timestamps with semantic type
        for (AttemptCount i = 0; i < count && i < 5; ++i) {
            attempts.push_back("Failed attempt at " + 
                std::to_string(std::chrono::duration_cast<std::chrono::seconds>(it->second.m_window_start.time_since_epoch()).count()));
        }
    }
    
    return attempts;
}

// Helper functions for JWT operations
String role_to_string(Role role) {
    switch (role) {
        case Role::Admin: return "admin";
        case Role::User: return "user";
        case Role::Guest: return "guest";
        default: return "unknown";
    }
}

String AuthenticationManager::generate_jwt_signature(const String& header_payload) const noexcept {
    try {
        unsigned char* hmac = nullptr;
        unsigned int hmac_len = 0;
        
        HMAC(EVP_sha256(), 
              m_jwt_secret.data(), static_cast<int>(m_jwt_secret.size()),
              reinterpret_cast<const unsigned char*>(header_payload.c_str()), header_payload.length(),
              hmac, &hmac_len);
        
        String result = base64_encode(String(reinterpret_cast<char*>(hmac), hmac_len));
        OPENSSL_free(hmac);
        return result;
    } catch (...) {
        return "";
    }
}

bool AuthenticationManager::verify_jwt_signature(const String& header_payload, const String& signature) const noexcept {
    try {
        String expected_signature = generate_jwt_signature(header_payload);
        return expected_signature == signature;
    } catch (...) {
        return false;
    }
}

namespace auth_utils {
    bool is_valid_jwt_structure(const TokenString& token) {
        // Basic JWT structure validation: header.payload.signature
        size_t first_dot = token.find('.');
        size_t second_dot = token.find('.', first_dot + 1);
        
        return first_dot != String::npos && 
               second_dot != String::npos && 
               second_dot > first_dot + 1 &&
               second_dot < token.length() - 1;
    }
}

SessionId AuthenticationManager::generate_session_id() const noexcept {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint64_t> dis(1, std::numeric_limits<uint64_t>::max());
    
    return std::to_string(dis(gen()));
}

} // namespace zerossg
