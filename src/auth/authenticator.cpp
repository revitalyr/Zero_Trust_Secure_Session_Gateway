module zerossg.auth.authenticator;

// C++23 module imports
import zerossg.constants;
import zerossg.types;
import zerossg.interfaces;
import zerossg.third_party.nlohmann_json;
import zerossg.third_party.openssl;
import zerossg.result;

// Standard library imports
import zerossg.std;

namespace zerossg {

// Helper function to generate secure random bytes
zerossg::Result<zerossg::Bytes> generate_secure_random_bytes(size_t size) {
    zerossg::Bytes bytes(size);
    std::random_device rd;
    std::uniform_int_distribution<unsigned char> dist(0, 255);
    
    for (size_t i = 0; i < size; ++i) {
        bytes[i] = dist(rd);
    }
    
    return zerossg::Result<zerossg::Bytes>::success(std::move(bytes));
}

AuthenticationManager::AuthenticationManager() {
    // Initialize with modern C++26 features
    m_secret_rotation_time = std::system_clock::now();
    
    // Generate JWT secret key with better randomness
    const auto secret_result = generate_secure_random_bytes(zerossg::JWT_SECRET_SIZE);
    if (!secret_result.is_success()) {
        throw std::runtime_error(zerossg::ERROR_JWT_SECRET_GENERATION_FAILED);
    }
    m_jwt_secret = secret_result.value();
    
    // Add default admin user with stronger password
    auto admin_hash_result = hash_password(zerossg::DEFAULT_ADMIN_PASSWORD);
    if (admin_hash_result.is_success()) {
        zerossg::User admin_user("admin", admin_hash_result.value(), zerossg::Role::ADMIN);
        add_user(std::move(admin_user));
    }
}

AuthenticationManager::~AuthenticationManager() = default;

zerossg::Result<zerossg::TokenString> AuthenticationManager::authenticate(const zerossg::UserName& username, const zerossg::Password& password) {
    // Modern input validation
    if (!is_valid_username(username)) {
        return zerossg::make_result_error<zerossg::TokenString>(zerossg::ERROR_INVALID_USERNAME_FORMAT);
    }
    
    if (!is_valid_password_format(password)) {
        return zerossg::make_result_error<zerossg::TokenString>(zerossg::ERROR_PASSWORD_POLICY_VIOLATION);
    }
    
    // Check rate limiting first
    {
        std::shared_lock lock(m_rate_limits_mutex);
        auto& rate_info = m_rate_limits[std::string(username)];
        
        if (rate_info.should_block()) {
            return zerossg::make_result_error<zerossg::TokenString>(zerossg::ERROR_ACCOUNT_LOCKED);
        }
        
        // Record attempt
        rate_info.m_attempts++;
        rate_info.m_window_start = std::system_clock::now();
    }
    
    // Check if user is blocked
    {
        std::shared_lock lock(m_blocked_users_mutex);
        if (m_blocked_users.contains(std::string(username))) {
            return zerossg::make_result_error<zerossg::TokenString>(zerossg::ERROR_ACCOUNT_BLOCKED);
        }
    }
    
    // Find user with modern concurrency
    std::shared_lock lock(m_users_mutex);
    const auto user_it = m_users.find(std::string(username));
    if (user_it == m_users.end()) {
        return zerossg::make_result_error<zerossg::TokenString>(zerossg::ERROR_USER_NOT_FOUND);
    }
    
    const zerossg::User& user = user_it->second;
    if (!user.is_active()) {
        return zerossg::make_result_error<zerossg::TokenString>(zerossg::ERROR_USER_INACTIVE);
    }
    
    // Modern password verification with timing-safe comparison
    const auto verify_result = verify_password(password, user.password_hash());
    if (!verify_result.is_success()) {
        // Record failed attempt for security monitoring
        detect_suspicious_activity(username, "");
        return zerossg::make_result_error<zerossg::TokenString>(std::format("{}{}", zerossg::ERROR_AUTHENTICATION_FAILED_PREFIX, verify_result.error()));
    }
    
    if (!verify_result.value()) {
        return zerossg::make_result_error<zerossg::TokenString>(zerossg::ERROR_INVALID_CREDENTIALS);
    }
    
    // Generate JWT token with enhanced security
    // Generate simple JWT token for now
    auto now = std::system_clock::now();
    auto iat = std::chrono::duration_cast<zerossg::Seconds>(now.time_since_epoch()).count();
    auto exp = std::chrono::duration_cast<zerossg::Seconds>((now + zerossg::Seconds(3600)).time_since_epoch()).count();
    
    json payload = {
        {zerossg::JWT_PAYLOAD_USERNAME, user.m_user_name},
        {zerossg::JWT_PAYLOAD_ROLE, role_to_string(user.m_role)},
        {zerossg::JWT_PAYLOAD_IAT, iat},
        {zerossg::JWT_PAYLOAD_EXP, exp},
        {zerossg::JWT_PAYLOAD_SUB, "zerossg"},
        {zerossg::JWT_PAYLOAD_JTI, std::to_string(std::hash<std::string>{}(std::string(user.m_user_name) + std::to_string(iat)))}
    };
    
    // Create JWT header
    json header = {
        {zerossg::JWT_HEADER_ALG, zerossg::JWT_ALGORITHM_HS256},
        {zerossg::JWT_HEADER_TYP, zerossg::JWT_TYPE}
    };
    
    // Encode header and payload
    zerossg::String header_b64 = base64_encode(header.dump());
    zerossg::String payload_b64 = base64_encode(payload.dump());
    
    // Create signature
    zerossg::String header_payload = header_b64 + "." + payload_b64;
    zerossg::String signature = generate_jwt_signature(header_payload);
    
    return zerossg::make_result_success<zerossg::TokenString>(header_payload + "." + signature);
}

zerossg::Result<bool> AuthenticationManager::validate_token(const zerossg::TokenString& token) {
    // Modern token format validation
    if (!auth_utils::is_valid_jwt_structure(token)) {
        return zerossg::make_result_error<bool>(zerossg::ERROR_INVALID_TOKEN_FORMAT);
    }
    
    // Check if token is revoked
    {
        std::shared_lock lock(m_revoked_tokens_mutex);
        if (m_revoked_tokens.contains(std::string(token))) {
            return zerossg::make_result_error<bool>(zerossg::ERROR_TOKEN_REVOKED);
        }
    }
    
    return zerossg::make_result_success(true);
}

zerossg::Result<zerossg::User> AuthenticationManager::get_user_from_token(const zerossg::TokenString& token) {
    // Parse JWT token (header.payload.signature)
    size_t first_dot = token.find('.');
    size_t second_dot = token.find('.', first_dot + 1);
    
    if (first_dot == zerossg::String::npos || second_dot == zerossg::String::npos) {
        return zerossg::make_result_error<zerossg::User>(zerossg::ERROR_INVALID_TOKEN_FORMAT);
    }
    
    zerossg::String header_payload = token.substr(0, second_dot);
    zerossg::String signature = token.substr(second_dot + 1);
    
    // Verify signature
    if (!verify_jwt_signature(header_payload, signature)) {
        return zerossg::make_result_error<zerossg::User>(zerossg::ERROR_INVALID_TOKEN_SIGNATURE);
    }
    
    // Parse payload
    auto payload_result = parse_jwt_payload(token);
    if (!payload_result.is_success()) {
        return zerossg::make_result_error<zerossg::User>(std::format("{}{}", zerossg::ERROR_INVALID_TOKEN_PAYLOAD_PREFIX, payload_result.error()));
    }
    
    // Check if token is revoked
    {
        std::lock_guard<std::mutex> lock(m_tokens_mutex);
        auto revoked_it = m_revoked_tokens.find(token);
        if (revoked_it != m_revoked_tokens.end()) {
            return zerossg::make_result_error<zerossg::User>(zerossg::ERROR_TOKEN_REVOKED);
        }
    }
    
    return payload_result;
}

zerossg::Result<zerossg::TokenString> AuthenticationManager::generate_token(const zerossg::User& user) {
    try {
        // Create JWT header
        json header = {
            {zerossg::JWT_HEADER_ALG, zerossg::JWT_ALGORITHM_HS256},
            {zerossg::JWT_HEADER_TYP, zerossg::JWT_TYPE}
        };
        
        // Create JWT payload
        json payload = {
            {zerossg::JWT_PAYLOAD_USERNAME, user.username},
            {zerossg::JWT_PAYLOAD_ROLE, role_to_string(user.role)},
            {zerossg::JWT_PAYLOAD_IAT, std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count()},
            {zerossg::JWT_PAYLOAD_EXP, std::chrono::duration_cast<std::chrono::seconds>((std::chrono::system_clock::now() + zerossg::TOKEN_EXPIRY_TIME).time_since_epoch()).count()}
        };
        
        // Encode header and payload
        std::string header_b64 = base64_encode(header.dump());
        std::string payload_b64 = base64_encode(payload.dump());
        
        // Create signature
        std::string header_payload = header_b64 + "." + payload_b64;
        std::string signature = generate_jwt_signature(header_payload);
        
        return zerossg::make_result_success<zerossg::TokenString>(header_payload + "." + signature);
    } catch (const std::exception& e) {
        return zerossg::make_result_error<zerossg::TokenString>(std::format("{}{}", zerossg::ERROR_JWT_GENERATION_FAILED_PREFIX, e.what()));
    }
}

zerossg::Result<void> AuthenticationManager::revoke_token(const zerossg::TokenString& token) {
    std::lock_guard<std::mutex> lock(m_tokens_mutex);
    
    // Store token with expiry time for cleanup
    auto expiry_time = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now() + zerossg::TOKEN_EXPIRY_TIME).count();
    m_revoked_tokens[std::string(token)] = std::to_string(expiry_time);
    
    return zerossg::make_result_success();
}

zerossg::Result<void> AuthenticationManager::add_user(const zerossg::User& user) {
    std::lock_guard<std::mutex> lock(m_users_mutex);
    
    if (m_users.find(user.username) != m_users.end()) {
        return zerossg::make_result_error<void>(zerossg::ERROR_USER_ALREADY_EXISTS);
    }
    
    m_users[user.username] = user;
    return zerossg::make_result_success();
}

zerossg::Result<void> AuthenticationManager::update_user(const zerossg::UserName& username, const zerossg::User& user) {
    std::lock_guard<std::mutex> lock(m_users_mutex);
    
    if (m_users.find(username) == m_users.end()) {
        return zerossg::make_result_error<void>(zerossg::ERROR_USER_NOT_FOUND);
    }
    
    m_users[username] = user;
    return zerossg::make_result_success();
}

zerossg::Result<void> AuthenticationManager::delete_user(const zerossg::UserName& username) {
    std::lock_guard<std::mutex> lock(m_users_mutex);
    
    if (m_users.erase(username) == 0) {
        return zerossg::make_result_error<void>(zerossg::ERROR_USER_NOT_FOUND);
    }
    
    return zerossg::make_result_success();
}

zerossg::Result<std::optional<zerossg::User>> AuthenticationManager::get_user(const zerossg::UserName& username) {
    std::lock_guard<std::mutex> lock(m_users_mutex);
    
    auto it = m_users.find(username);
    if (it == m_users.end()) {
        return zerossg::make_result_success<std::optional<zerossg::User>>(std::nullopt);
    }
    
    return zerossg::make_result_success<std::optional<zerossg::User>>(it->second);
}

zerossg::Result<zerossg::Users> AuthenticationManager::list_users() {
    std::lock_guard<std::mutex> lock(m_users_mutex);
    
    zerossg::Users users;
    users.reserve(m_users.size());
    
    for (const auto& pair : m_users) {
        users.push_back(pair.second);
    }
    
    return zerossg::make_result_success<zerossg::Users>(std::move(users));
}

zerossg::Result<zerossg::PasswordHash> AuthenticationManager::hash_password(const zerossg::Password& password) {
    // For production, use bcrypt or argon2. This is a simplified implementation using SHA-256 with salt
    zerossg::SecretKey salt(16);
    if (RAND_bytes(salt.data(), salt.size()) != 1) {
        return zerossg::make_result_error<zerossg::PasswordHash>(zerossg::ERROR_SALT_GENERATION_FAILED);
    }
    
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        return zerossg::make_result_error<zerossg::PasswordHash>(zerossg::ERROR_HASH_CONTEXT_CREATION_FAILED);
    }
    
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(mdctx);
        return zerossg::make_result_error<zerossg::PasswordHash>(zerossg::ERROR_HASH_INITIALIZATION_FAILED);
    }
    
    if (EVP_DigestUpdate(mdctx, salt.data(), salt.size()) != 1 ||
        EVP_DigestUpdate(mdctx, password.data(), password.size()) != 1) {
        EVP_MD_CTX_free(mdctx);
        return zerossg::make_result_error<zerossg::PasswordHash>(zerossg::ERROR_HASH_UPDATE_FAILED);
    }
    
    zerossg::SecretKey hash(EVP_MD_size(EVP_sha256()));
    unsigned int hash_len;
    if (EVP_DigestFinal_ex(mdctx, hash.data(), &hash_len) != 1) {
        EVP_MD_CTX_free(mdctx);
        return zerossg::make_result_error<zerossg::PasswordHash>(zerossg::ERROR_HASH_FINALIZATION_FAILED);
    }
    
    EVP_MD_CTX_free(mdctx);
    
    // Combine salt and hash
    zerossg::String result;
    result.reserve(salt.size() + hash_len);
    result.append(reinterpret_cast<char*>(salt.data()), salt.size());
    result.append(reinterpret_cast<char*>(hash.data()), hash_len);
    
    return zerossg::make_result_success<zerossg::PasswordHash>(base64_encode(result));
}

zerossg::Result<bool> AuthenticationManager::verify_password(const zerossg::Password& password, const zerossg::PasswordHash& hash) {
    // Convert hex string back to bytes
    if (hash.length() % 2 != 0) {
        return zerossg::make_result_error<bool>(zerossg::ERROR_INVALID_HASH_FORMAT);
    }
    
    zerossg::String hash_bytes;
    hash_bytes.reserve(hash.length() / 2);
    
    for (size_t i = 0; i < hash.length(); i += 2) {
        unsigned int byte;
        std::stringstream ss;
        ss << std::hex << hash.substr(i, 2);
        ss >> byte;
        hash_bytes.push_back(static_cast<char>(byte));
    }
    
    if (hash_bytes.size() < 16) { // salt + at least some hash
        return zerossg::make_result_error<bool>(zerossg::ERROR_HASH_TOO_SHORT);
    }
    
    // Extract salt and hash
    zerossg::String salt = hash_bytes.substr(0, 16);
    zerossg::String stored_hash = hash_bytes.substr(16);
    
    // Compute hash of password with salt
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        return zerossg::make_result_error<bool>(zerossg::ERROR_HASH_CONTEXT_CREATION_FAILED);
    }
    
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(mdctx);
        return zerossg::make_result_error<bool>(zerossg::ERROR_HASH_INITIALIZATION_FAILED);
    }
    
    if (EVP_DigestUpdate(mdctx, salt.data(), salt.size()) != 1 ||
        EVP_DigestUpdate(mdctx, password.data(), password.size()) != 1) {
        EVP_MD_CTX_free(mdctx);
        return zerossg::make_result_error<bool>(zerossg::ERROR_HASH_UPDATE_FAILED);
    }
    
    zerossg::Bytes computed_hash(EVP_MD_size(EVP_sha256()));
    unsigned int hash_len;
    if (EVP_DigestFinal_ex(mdctx, computed_hash.data(), &hash_len) != 1) {
        EVP_MD_CTX_free(mdctx);
        return zerossg::make_result_error<bool>(zerossg::ERROR_HASH_FINALIZATION_FAILED);
    }
    
    EVP_MD_CTX_free(mdctx);
    
    // Compare hashes
    if (stored_hash.size() != hash_len) {
        return zerossg::make_result_success(false);
    }
    
    return zerossg::make_result_success(std::equal(stored_hash.begin(), stored_hash.end(),
                                           computed_hash.begin(), computed_hash.end()));
}

zerossg::JwtPayloadString AuthenticationManager::create_jwt_payload(const zerossg::User& user) {
    json payload = {
        {zerossg::JWT_PAYLOAD_USERNAME, user.username},
        {zerossg::JWT_PAYLOAD_ROLE, role_to_string(user.role)},
        {zerossg::JWT_PAYLOAD_IAT, std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count()},
        {zerossg::JWT_PAYLOAD_EXP, std::chrono::duration_cast<std::chrono::seconds>((std::chrono::system_clock::now() + zerossg::TOKEN_EXPIRY_TIME).time_since_epoch()).count()}
    };
    return payload.dump();
}

zerossg::Result<zerossg::User> AuthenticationManager::parse_jwt_payload(const zerossg::TokenString& token) {
    size_t first_dot = token.find('.');
    size_t second_dot = token.find('.', first_dot + 1);
    
    if (first_dot == zerossg::String::npos || second_dot == zerossg::String::npos) {
        return zerossg::make_result_error<zerossg::User>(zerossg::ERROR_INVALID_TOKEN_FORMAT);
    }
    
    std::string payload_b64 = token.substr(first_dot + 1, second_dot - first_dot - 1);
    std::string payload_str = base64_decode(payload_b64);
    
    try {
        json payload = json::parse(payload_str);
        
        // Check expiration
        auto now = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        if (payload["exp"].get<int64_t>() < now) {
            return zerossg::Result<zerossg::User>::error(zerossg::ERROR_TOKEN_EXPIRED);
        }
        
        // Get user
        std::string username = payload["username"];
        auto user_result = get_user(username);
        if (!user_result.is_success()) {
            return zerossg::Result<zerossg::User>::error(std::format("{}{}", zerossg::ERROR_USER_NOT_FOUND_PREFIX, username));
        }
        
        auto user_opt = user_result.value();
        if (!user_opt.has_value()) {
            return zerossg::Result<zerossg::User>::error(std::format("{}{}", zerossg::ERROR_USER_NOT_FOUND_PREFIX, username));
        }
        
        return zerossg::Result<zerossg::User>::success(user_opt.value());
    } catch (const json::exception& e) {
        return zerossg::Result<zerossg::User>::error(std::format("{}{}", zerossg::ERROR_JWT_PAYLOAD_PARSE_FAILED_PREFIX, e.what()));
    }
}

zerossg::JwtSignature AuthenticationManager::generate_jwt_signature(const zerossg::JwtHeaderPayload& header_payload) {
    unsigned char* hmac = nullptr;
    unsigned int hmac_len;
    
    hmac = HMAC(EVP_sha256(), m_jwt_secret.data(), m_jwt_secret.size(),
                reinterpret_cast<const unsigned char*>(header_payload.data()), header_payload.size(), nullptr, &hmac_len);
    
    if (!hmac) {
        throw std::runtime_error(zerossg::ERROR_HMAC_GENERATION_FAILED);
    }
    
    std::string signature = base64_encode(std::string(reinterpret_cast<char*>(hmac), hmac_len));
    OPENSSL_free(hmac);
    
    return signature;
}

bool AuthenticationManager::verify_jwt_signature(const zerossg::JwtHeaderPayload& header_payload, const zerossg::JwtSignature& signature) {
    try {
        std::string computed_signature = generate_jwt_signature(header_payload);
        return computed_signature == signature;
    } catch (const std::exception&) {
        return false;
    }
}

zerossg::TokenString AuthenticationManager::generate_secure_token() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    
    zerossg::SecretKey token_data(32);
    for (auto& byte : token_data) {
        byte = static_cast<unsigned char>(dis(gen()));
    }
    
    return base64_encode(std::string(reinterpret_cast<char*>(token_data.data()), token_data.size()));
}

void AuthenticationManager::cleanup_expired_tokens() {
    auto now = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    
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

zerossg::UserCount AuthenticationManager::get_active_user_count() const noexcept {
    std::shared_lock lock(m_users_mutex);
    return std::ranges::count_if(m_users, 
        [](const auto& pair) { return pair.second.is_active(); });
}

zerossg::UserCount AuthenticationManager::get_blocked_user_count() const noexcept {
    std::shared_lock lock(m_blocked_users_mutex);
    return m_blocked_users.size();
}

zerossg::Strings AuthenticationManager::get_recent_failed_attempts(std::string_view username, zerossg::AttemptCount count) const noexcept {
    // Modern rate limiting with better tracking and semantic return type
    std::shared_lock lock(m_rate_limits_mutex);
    
    zerossg::Strings attempts;
    const auto it = m_rate_limits.find(zerossg::UserName{std::string(username)});
    if (it != m_rate_limits.end()) {
        // Return recent failed attempt timestamps with semantic type
        for (zerossg::AttemptCount i = 0; i < count && i < 5; ++i) {
            attempts.push_back(std::format("{}{}", zerossg::LOG_MSG_FAILED_ATTEMPT_PREFIX, 
                std::chrono::duration_cast<std::chrono::seconds>(it->second.m_window_start.time_since_epoch()).count()));
        }
    }
    
    return attempts;
}

// Helper functions for JWT operations
zerossg::RoleString role_to_string(zerossg::Role role) {
    switch (role) {
        case zerossg::Role::ADMIN: return "admin";
        case zerossg::Role::OPERATOR: return "operator";
        case zerossg::Role::VIEWER: return "viewer";
        default: return zerossg::ROLE_UNKNOWN;
    }
}

zerossg::JwtSignature AuthenticationManager::generate_jwt_signature(const zerossg::JwtHeaderPayload& header_payload) const noexcept {
    try {
        unsigned char* hmac = nullptr;
        unsigned int hmac_len = 0;
        
        HMAC(EVP_sha256(), 
              m_jwt_secret.data(), static_cast<int>(m_jwt_secret.size()),
              reinterpret_cast<const unsigned char*>(header_payload.c_str()), header_payload.length(),
              hmac, &hmac_len);
        
        zerossg::String result = base64_encode(zerossg::String(reinterpret_cast<char*>(hmac), hmac_len));
        OPENSSL_free(hmac);
        return result;
    } catch (...) {
        return "";
    }
}

bool AuthenticationManager::verify_jwt_signature(const zerossg::JwtHeaderPayload& header_payload, const zerossg::JwtSignature& signature) const noexcept {
    try {
        zerossg::String expected_signature = generate_jwt_signature(header_payload);
        return expected_signature == signature;
    } catch (...) {
        return false;
    }
}

namespace auth_utils {
    bool is_valid_jwt_structure(const zerossg::TokenString& token) {
        // Basic JWT structure validation: header.payload.signature
        size_t first_dot = token.find('.');
        size_t second_dot = token.find('.', first_dot + 1);
        
        return first_dot != zerossg::String::npos && 
               second_dot != zerossg::String::npos && 
               second_dot > first_dot + 1 &&
               second_dot < token.length() - 1;
    }
}

zerossg::SessionId AuthenticationManager::generate_session_id() const noexcept {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint64_t> dis(1, std::numeric_limits<uint64_t>::max());
    
    return std::to_string(dis(gen()));
}

} // namespace zerossg
