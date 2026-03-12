#pragma once

// C++23 module imports
import zerossg.interfaces;
import zerossg.common;
import zerossg.types;
import zerossg.std;

// Standard library imports
#include <mutex>
#include <unordered_map>
#include <string_view>

// OpenSSL headers
#include <openssl/evp.h>
#include <openssl/rand.h>

namespace zerossg {

class AuthenticationManager : public IAuthenticator {
public:
    AuthenticationManager();
    ~AuthenticationManager() override;
    
    // IAuthenticator interface with modern error handling
    Result<String> authenticate(const UserName& username, const PasswordHash& password) override;
    Result<bool> validate_token(const TokenString& token) override;
    Result<User> get_user_from_token(const TokenString& token) override;
    Result<TokenString> generate_token(const User& user) override;
    Result<void> revoke_token(const TokenString& token) override;
    
    // Modern user management with move semantics
    Result<void> add_user(const User& user) noexcept;
    Result<void> update_user(const UserName& username, const User& user) noexcept;
    Result<void> delete_user(const UserName& username) noexcept;
    Result<Optional<User>> get_user(const UserName& username) const noexcept;
    Result<Vector<User>> list_users() const noexcept;
    
    // Modern password utilities with constexpr support where possible
    static Result<PasswordHash> hash_password(const String& password) noexcept;
    static Result<bool> verify_password(const String& password, const PasswordHash& hash) noexcept;
    
    // Modern token management with better security
    Result<TokenString> generate_token_with_claims(const User& user, 
                                          const std::unordered_map<std::string, std::string>& claims) noexcept;
    Result<bool> validate_token_with_claims(string_view token, 
                                           const std::unordered_map<std::string, std::string>& required_claims) noexcept;
    
    // Security utilities
    Result<void> block_user(string_view username, seconds duration) noexcept;
    Result<bool> is_user_blocked(string_view username) const noexcept;
    Result<void> cleanup_expired_tokens() noexcept;
    
    // Statistics and monitoring with semantic return types
    [[nodiscard]] UserCount get_active_user_count() const noexcept;
    [[nodiscard]] UserCount get_blocked_user_count() const noexcept;
    [[nodiscard]] Strings get_recent_failed_attempts(string_view username, size_t count) const noexcept;

private:
    // Modern JWT operations with better security
    String create_jwt_payload(const User& user, 
                           const UnorderedMap<String, String>& claims = {}) const noexcept;
    Result<User> parse_jwt_payload(const TokenString& token) const noexcept;
    String generate_jwt_signature(const String& header_payload) const noexcept;
    bool verify_jwt_signature(const String& header_payload, const String& signature) const noexcept;
    
    // Modern token management with enhanced security
    TokenString generate_secure_token() noexcept;
    SessionId generate_session_id() const noexcept;
    bool is_token_blacklisted(const TokenString& token) const noexcept;
    
    // Modern data storage with better concurrency
    mutable std::mutex m_users_mutex;
    mutable std::mutex m_tokens_mutex;
    mutable std::mutex m_blocked_users_mutex;
    mutable std::mutex m_revoked_tokens_mutex;
    
    UnorderedMap<UserName, User> m_users;
    UnorderedMap<TokenString, String> m_revoked_tokens;
    UnorderedMap<UserName, system_clock::time_point> m_blocked_users;
    
    // Enhanced JWT secret with rotation support
    SecretKey m_jwt_secret;
    system_clock::time_point m_secret_rotation_time;
    
    // Modern configuration with constexpr
    static constexpr size_t JWT_SECRET_SIZE = 32;
    static constexpr seconds TOKEN_EXPIRY_TIME{3600}; // 1 hour
    static constexpr size_t BCRYPT_ROUNDS = 12;
    static constexpr seconds SECRET_ROTATION_INTERVAL{86400}; // 24 hours
    static constexpr size_t MAX_FAILED_ATTEMPTS = 5;
    static constexpr seconds FAILED_ATTEMPT_WINDOW{900}; // 15 minutes
    
    // Rate limiting
    struct RateLimitInfo {
        size_t m_attempts{0};
        system_clock::time_point m_window_start{system_clock::now()};
        bool m_blocked{false};
        
        [[nodiscard]] bool should_block() const noexcept {
            return m_attempts >= MAX_FAILED_ATTEMPTS;
        }
        
        void reset() noexcept {
            m_attempts = 0;
            m_window_start = system_clock::now();
            m_blocked = false;
        }
    };
    
    unordered_map<string, RateLimitInfo> m_rate_limits;
    
    // Modern helper methods
    void rotate_jwt_secret() noexcept;
    bool is_jwt_secret_expired() const noexcept;
    void cleanup_expired_data() noexcept;
    Result<vector<unsigned char>> generate_secure_random_bytes(size_t count) const noexcept;
    
    // Modern validation methods
    bool is_valid_username(string_view username) const noexcept;
    bool is_valid_password(string_view password) const noexcept;
    bool is_valid_token_format(string_view token) const noexcept;
    
    // Modern security checks
    Result<void> check_password_strength(string_view password) const noexcept;
    Result<void> detect_suspicious_activity(string_view username, string_view client_ip) const noexcept;
};

// Modern authentication utilities
namespace auth_utils {
    // constexpr password strength validation
    constexpr bool is_strong_password(string_view password) noexcept {
        if (password.size() < 8) return false;
        
        bool has_upper = false, has_lower = false, has_digit = false, has_special = false;
        
        for (char c : password) {
            if (std::isupper(c)) has_upper = true;
            else if (std::islower(c)) has_lower = true;
            else if (std::isdigit(c)) has_digit = true;
            else if (std::ispunct(c) || std::isgraph(c)) has_special = true;
        }
        
        return has_upper && has_lower && has_digit && has_special;
    }
    
    // constexpr username validation
    constexpr bool is_valid_username_format(string_view username) noexcept {
        if (username.empty() || username.size() < 3 || username.size() > 32) {
            return false;
        }
        
        return std::ranges::all_of(username, [](char c) {
            return std::isalnum(c) || c == '_';
        });
    }
    
    // constexpr token validation
    constexpr bool is_valid_jwt_structure(string_view token) noexcept {
        const auto dot_count = std::ranges::count(token, '.');
        return dot_count == 2; // header.payload.signature
    }
    
    // Modern secure comparison function
    constexpr bool secure_equals(string_view a, string_view b) noexcept {
        if (a.size() != b.size()) return false;
        return std::ranges::equal(a, b);
    }
    
    // Modern timing-safe comparison
    constexpr bool timing_safe_equals(string_view a, string_view b) noexcept {
        if (a.size() != b.size()) return false;
        
        volatile auto result = true;
        for (size_t i = 0; i < a.size(); ++i) {
            if (a[i] != b[i]) {
                result = false;
            }
        }
        
        return result;
    }
}

} // namespace zerossg
