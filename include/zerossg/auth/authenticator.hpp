#pragma once

#include "zerossg/interfaces.hpp"
#include <unordered_map>
#include <mutex>
#include <openssl/evp.h>
#include <openssl/rand.h>

namespace zerossg {

class AuthenticationManager : public IAuthenticator {
public:
    AuthenticationManager();
    ~AuthenticationManager() override;
    
    // IAuthenticator interface
    Result<string> authenticate(const string& username, const string& password) override;
    Result<bool> validate_token(const string& token) override;
    Result<User> get_user_from_token(const string& token) override;
    Result<string> generate_token(const User& user) override;
    Result<void> revoke_token(const string& token) override;
    
    // User management
    Result<void> add_user(const User& user);
    Result<void> update_user(const string& username, const User& user);
    Result<void> delete_user(const string& username);
    Result<optional<User>> get_user(const string& username);
    Result<vector<User>> list_users();
    
    // Password utilities
    static Result<string> hash_password(const string& password);
    static Result<bool> verify_password(const string& password, const string& hash);
    
private:
    // JWT operations
    string create_jwt_payload(const User& user);
    Result<User> parse_jwt_payload(const string& token);
    string generate_jwt_signature(const string& header_payload);
    bool verify_jwt_signature(const string& header_payload, const string& signature);
    
    // Token management
    string generate_secure_token();
    void cleanup_expired_tokens();
    
    // Data storage
    unordered_map<string, User> m_users;
    unordered_map<string, string> m_revoked_tokens; // token -> expiry_time
    mutable std::mutex m_users_mutex;
    mutable std::mutex m_tokens_mutex;
    
    // JWT secret key
    vector<unsigned char> m_jwt_secret;
    
    // Configuration
    static constexpr size_t JWT_SECRET_SIZE = 32;
    static constexpr seconds TOKEN_EXPIRY_TIME{3600}; // 1 hour
    static constexpr size_t BCRYPT_ROUNDS = 12;
};

} // namespace zerossg
