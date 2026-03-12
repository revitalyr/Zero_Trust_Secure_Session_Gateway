export module zerossg.auth.authenticator;

// C++23 module imports
export import zerossg.common;
export import zerossg.types;
import zerossg.interfaces;
export import <memory>;
export import <shared_mutex>;
export import <unordered_map>;

export namespace zerossg {

// AuthenticationManager class implementation
export class AuthenticationManager : public IAuthenticator {
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
                                          const UnorderedMap<String, String>& claims) noexcept;
    Result<bool> validate_token_with_claims(const TokenString& token, 
                                           const UnorderedMap<String, String>& required_claims) noexcept;
    
    // Security utilities
    Result<void> block_user(const UserName& username, Seconds duration) noexcept;
    Result<bool> is_user_blocked(const UserName& username) const noexcept;
    Result<void> cleanup_expired_tokens() noexcept;
    
    // Statistics and monitoring with semantic return types
    [[nodiscard]] UserCount get_active_user_count() const noexcept;
    [[nodiscard]] UserCount get_blocked_user_count() const noexcept;
    [[nodiscard]] Strings get_recent_failed_attempts(const UserName& username, AttemptCount count) const noexcept;

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
    mutable std::shared_mutex m_users_mutex;
    mutable std::shared_mutex m_tokens_mutex;
    mutable std::shared_mutex m_blocked_users_mutex;
    mutable std::shared_mutex m_revoked_tokens_mutex;
    
    UnorderedMap<UserName, User> m_users;
    UnorderedMap<TokenString, String> m_revoked_tokens;
    UnorderedMap<UserName, system_clock::time_point> m_blocked_users;
    
    // Enhanced JWT secret with rotation support
    SecretKey m_jwt_secret;
    system_clock::time_point m_secret_rotation_time;
    
    // Modern configuration with constexpr
    static constexpr size_t JWT_SECRET_SIZE = 32;
    static constexpr Seconds TOKEN_EXPIRY_TIME{Seconds(3600)}; // 1 hour
    static constexpr size_t BCRYPT_ROUNDS = 12;
    static constexpr Seconds SECRET_ROTATION_INTERVAL{Seconds(86400)}; // 24 hours
    static constexpr Seconds MAX_LOGIN_ATTEMPTS{Seconds(5)}; // 5 attempts
    static constexpr Seconds BLOCK_DURATION{Seconds(900)}; // 15 minutes
};

} // namespace zerossg
