#include "zerossg/utils/base64.hpp"
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <nlohmann/json.hpp>
#include <random>
#include <sstream>
#include <iomanip>
#include <ranges>
#include <algorithm>

using json = nlohmann::json;

namespace zerossg {

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

Result<string> AuthenticationManager::authenticate(string_view username, string_view password) {
    // Modern input validation
    if (!is_valid_username(username)) {
        return make_result_error<string>("Invalid username format");
    }
    
    if (!is_valid_password(password)) {
        return make_result_error<string>("Password does not meet security requirements");
    }
    
    // Check rate limiting first
    {
        std::shared_lock lock(m_rate_limits_mutex);
        auto& rate_info = m_rate_limits[string(username)];
        
        if (rate_info.should_block()) {
            return make_result_error<string>("Account temporarily blocked due to too many failed attempts");
        }
        
        // Record attempt
        rate_info.m_attempts++;
        rate_info.m_window_start = system_clock::now();
    }
    
    // Check if user is blocked
    {
        std::shared_lock lock(m_blocked_users_mutex);
        if (m_blocked_users.contains(string(username))) {
            return make_result_error<string>("Account is blocked");
        }
    }
    
    // Find user with modern concurrency
    std::shared_lock lock(m_users_mutex);
    const auto user_it = m_users.find(string(username));
    if (user_it == m_users.end()) {
        return make_result_error<string>("User not found");
    }
    
    const User& user = user_it->second;
    if (!user.is_active()) {
        return make_result_error<string>("User account is inactive");
    }
    
    // Modern password verification with timing-safe comparison
    const auto verify_result = verify_password(password, user.password_hash());
    if (!verify_result.is_success()) {
        // Record failed attempt for security monitoring
        detect_suspicious_activity(username, "");
        return make_result_error<string>("Authentication failed: " + verify_result.error());
    }
    
    if (!verify_result.value()) {
        return make_result_error<string>("Invalid credentials");
    }
    
    // Generate JWT token with enhanced security
    auto token_result = generate_token_with_claims(user, {
        {"iat", std::to_string(std::chrono::duration_cast<std::chrono::seconds>(system_clock::now().time_since_epoch()).count())},
        {"exp", std::to_string(std::chrono::duration_cast<std::chrono::seconds>((system_clock::now() + TOKEN_EXPIRY_TIME).time_since_epoch()).count())},
        {"sub", "zerossg"},
        {"jti", generate_session_id()}
    });
    
    if (!token_result.is_success()) {
        return make_result_error<string>("Token generation failed: " + token_result.error());
    }
    
    // Reset failed attempts on successful authentication
    {
        std::shared_lock lock(m_rate_limits_mutex);
        m_rate_limits[string(username)].reset();
    }
    
    return token_result;
}

Result<bool> AuthenticationManager::validate_token(string_view token) {
    // Modern token format validation
    if (!auth_utils::is_valid_jwt_structure(token)) {
        return make_result_error<bool>("Invalid token format");
Result<User> AuthenticationManager::get_user_from_token(const string& token) {
    // Parse JWT token (header.payload.signature)
    size_t first_dot = token.find('.');
    size_t second_dot = token.find('.', first_dot + 1);
    
    if (first_dot == string::npos || second_dot == string::npos) {
        return Result<User>::error("Invalid token format");
    }
    
    string header_payload = token.substr(0, second_dot);
    string signature = token.substr(second_dot + 1);
    
    // Verify signature
    if (!verify_jwt_signature(header_payload, signature)) {
        return Result<User>::error("Invalid token signature");
    }
    
    // Parse payload
    auto payload_result = parse_jwt_payload(token);
    if (!payload_result.is_success()) {
        return Result<User>::error("Invalid token payload: " + payload_result.error());
    }
    
    // Check if token is revoked
    {
        std::lock_guard<std::mutex> lock(m_tokens_mutex);
        auto revoked_it = m_revoked_tokens.find(token);
        if (revoked_it != m_revoked_tokens.end()) {
            return Result<User>::error("Token has been revoked");
        }
    }
    
    return payload_result;
}

Result<string> AuthenticationManager::generate_token(const User& user) {
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
        
        return Result<string>::success(header_payload + "." + signature);
    } catch (const std::exception& e) {
        return Result<string>::error("JWT generation failed: " + string(e.what()));
    }
}

Result<void> AuthenticationManager::revoke_token(const string& token) {
    std::lock_guard<std::mutex> lock(m_tokens_mutex);
    
    // Store token with expiry time for cleanup
    auto expiry_time = std::chrono::duration_cast<std::chrono::seconds>(
        system_clock::now() + TOKEN_EXPIRY_TIME).count();
    m_revoked_tokens[token] = std::to_string(expiry_time);
    
    return Result<void>::success();
}

Result<void> AuthenticationManager::add_user(const User& user) {
    std::lock_guard<std::mutex> lock(m_users_mutex);
    
    if (m_users.find(user.username) != m_users.end()) {
        return Result<void>::error("User already exists");
    }
    
    m_users[user.username] = user;
    return Result<void>::success();
}

Result<void> AuthenticationManager::update_user(const string& username, const User& user) {
    std::lock_guard<std::mutex> lock(m_users_mutex);
    
    if (m_users.find(username) == m_users.end()) {
        return Result<void>::error("User not found");
    }
    
    m_users[username] = user;
    return Result<void>::success();
}

Result<void> AuthenticationManager::delete_user(const string& username) {
    std::lock_guard<std::mutex> lock(m_users_mutex);
    
    if (m_users.erase(username) == 0) {
        return Result<void>::error("User not found");
    }
    
    return Result<void>::success();
}

Result<optional<User>> AuthenticationManager::get_user(const string& username) {
    std::lock_guard<std::mutex> lock(m_users_mutex);
    
    auto it = m_users.find(username);
    if (it == m_users.end()) {
        return Result<optional<User>>::success(std::nullopt);
    }
    
    return Result<optional<User>>::success(it->second);
}

Result<vector<User>> AuthenticationManager::list_users() {
    std::lock_guard<std::mutex> lock(m_users_mutex);
    
    vector<User> users;
    users.reserve(m_users.size());
    
    for (const auto& pair : m_users) {
        users.push_back(pair.second);
    }
    
    return Result<vector<User>>::success(std::move(users));
}

Result<string> AuthenticationManager::hash_password(const string& password) {
    // For production, use bcrypt or argon2. This is a simplified implementation using SHA-256 with salt
    vector<unsigned char> salt(16);
    if (RAND_bytes(salt.data(), salt.size()) != 1) {
        return Result<string>::error("Failed to generate salt");
    }
    
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        return Result<string>::error("Failed to create hash context");
    }
    
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(mdctx);
        return Result<string>::error("Failed to initialize hash");
    }
    
    if (EVP_DigestUpdate(mdctx, salt.data(), salt.size()) != 1 ||
        EVP_DigestUpdate(mdctx, password.data(), password.size()) != 1) {
        EVP_MD_CTX_free(mdctx);
        return Result<string>::error("Failed to update hash");
    }
    
    vector<unsigned char> hash(EVP_MD_size(EVP_sha256()));
    unsigned int hash_len;
    if (EVP_DigestFinal_ex(mdctx, hash.data(), &hash_len) != 1) {
        EVP_MD_CTX_free(mdctx);
        return Result<string>::error("Failed to finalize hash");
    }
    
    EVP_MD_CTX_free(mdctx);
    
    // Combine salt and hash
    string result;
    result.reserve(salt.size() + hash_len);
    result.append(reinterpret_cast<char*>(salt.data()), salt.size());
    result.append(reinterpret_cast<char*>(hash.data()), hash_len);
    
    // Convert to hex for storage
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (unsigned char byte : result) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    
    return Result<string>::success(ss.str());
}

Result<bool> AuthenticationManager::verify_password(const string& password, const string& hash) {
    // Convert hex string back to bytes
    if (hash.length() % 2 != 0) {
        return Result<bool>::error("Invalid hash format");
    }
    
    string hash_bytes;
    hash_bytes.reserve(hash.length() / 2);
    
    for (size_t i = 0; i < hash.length(); i += 2) {
        unsigned int byte;
        std::stringstream ss;
        ss << std::hex << hash.substr(i, 2);
        ss >> byte;
        hash_bytes.push_back(static_cast<char>(byte));
    }
    
    if (hash_bytes.size() < 16) { // salt + at least some hash
        return Result<bool>::error("Hash too short");
    }
    
    // Extract salt and hash
    string salt = hash_bytes.substr(0, 16);
    string stored_hash = hash_bytes.substr(16);
    
    // Compute hash of password with salt
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        return Result<bool>::error("Failed to create hash context");
    }
    
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(mdctx);
        return Result<bool>::error("Failed to initialize hash");
    }
    
    if (EVP_DigestUpdate(mdctx, salt.data(), salt.size()) != 1 ||
        EVP_DigestUpdate(mdctx, password.data(), password.size()) != 1) {
        EVP_MD_CTX_free(mdctx);
        return Result<bool>::error("Failed to update hash");
    }
    
    vector<unsigned char> computed_hash(EVP_MD_size(EVP_sha256()));
    unsigned int hash_len;
    if (EVP_DigestFinal_ex(mdctx, computed_hash.data(), &hash_len) != 1) {
        EVP_MD_CTX_free(mdctx);
        return Result<bool>::error("Failed to finalize hash");
    }
    
    EVP_MD_CTX_free(mdctx);
    
    // Compare hashes
    if (stored_hash.size() != hash_len) {
        return Result<bool>::success(false);
    }
    
    return Result<bool>::success(std::equal(stored_hash.begin(), stored_hash.end(),
                                           computed_hash.begin(), computed_hash.end()));
}

string AuthenticationManager::create_jwt_payload(const User& user) {
    json payload = {
        {"username", user.username},
        {"role", role_to_string(user.role)},
        {"iat", std::chrono::duration_cast<std::chrono::seconds>(system_clock::now().time_since_epoch()).count()},
        {"exp", std::chrono::duration_cast<std::chrono::seconds>((system_clock::now() + TOKEN_EXPIRY_TIME).time_since_epoch()).count()}
    };
    return payload.dump();
}

Result<User> AuthenticationManager::parse_jwt_payload(const string& token) {
    size_t first_dot = token.find('.');
    size_t second_dot = token.find('.', first_dot + 1);
    
    if (first_dot == string::npos || second_dot == string::npos) {
        return Result<User>::error("Invalid token format");
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

string AuthenticationManager::generate_secure_token() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    
    vector<unsigned char> token_data(32);
    for (auto& byte : token_data) {
        byte = static_cast<unsigned char>(dis(gen));
    }
    
    return base64_encode(string(reinterpret_cast<char*>(token_data.data()), token_data.size()));
}

void AuthenticationManager::cleanup_expired_tokens() {
    auto now = std::chrono::duration_cast<std::chrono::seconds>(system_clock::now().time_since_epoch()).count();
    
    std::lock_guard<std::mutex> lock(m_tokens_mutex);
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

} // namespace zerossg
