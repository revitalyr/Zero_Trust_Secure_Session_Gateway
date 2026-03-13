import zerossg.types;
import zerossg.std;
import zerossg.result;

namespace zerossg {

// Legacy functions for backward compatibility
// Note: These are deprecated in favor of constexpr versions

[[deprecated("Use constexpr role_to_string instead")]]
std::string role_to_string(Role role) {
    switch (role) {
        case Role::ADMIN: return zerossg::ROLE_ADMIN;
        case Role::OPERATOR: return zerossg::ROLE_OPERATOR;
        case Role::VIEWER: return zerossg::ROLE_VIEWER;
        default: return zerossg::ERROR_UNKNOWN_ROLE;
    }
}

[[deprecated("Use constexpr string_to_role instead")]]
Role string_to_role(const std::string& role_str) {
    if (role_str == zerossg::ROLE_ADMIN) return Role::ADMIN;
    if (role_str == zerossg::ROLE_OPERATOR) return Role::OPERATOR;
    if (role_str == zerossg::ROLE_VIEWER) return Role::VIEWER;
    return Role::VIEWER; // Default fallback
}

[[deprecated("Use constexpr security_event_type_to_string instead")]]
std::string security_event_type_to_string(SecurityEventType type) {
    switch (type) {
        case SecurityEventType::LOGIN_SUCCESS: return zerossg::EVENT_LOGIN_SUCCESS;
        case SecurityEventType::LOGIN_FAILURE: return zerossg::EVENT_LOGIN_FAILURE;
        case SecurityEventType::SESSION_START: return zerossg::EVENT_SESSION_START;
        case SecurityEventType::SESSION_TERMINATION: return zerossg::EVENT_SESSION_TERMINATION;
        case SecurityEventType::AUTHENTICATION_ERROR: return zerossg::EVENT_AUTHENTICATION_ERROR;
        case SecurityEventType::ACCESS_VIOLATION: return zerossg::EVENT_ACCESS_VIOLATION;
        case SecurityEventType::RATE_LIMIT_EXCEEDED: return zerossg::EVENT_RATE_LIMIT_EXCEEDED;
        case SecurityEventType::BRUTE_FORCE_DETECTED: return zerossg::EVENT_BRUTE_FORCE_DETECTED;
        default: return zerossg::ERROR_UNKNOWN_EVENT;
    }
}

// Modern utility functions using C++26 features

namespace utils {

// Advanced role validation with error handling
constexpr zerossg::Result<Role> validate_role(std::string_view role_str) noexcept {
    if (role_str.empty()) {
        return zerossg::make_result_error<Role>("Role string cannot be empty");
    }
    
    const auto role = string_to_role(role_str);
    return zerossg::make_result_success<Role>(role);
}

// Modern role comparison with three-way comparison
constexpr std::strong_ordering compare_roles(Role lhs, Role rhs) noexcept {
    const auto lhs_value = static_cast<std::underlying_type_t<Role>>(lhs);
    const auto rhs_value = static_cast<std::underlying_type_t<Role>>(rhs);
    
    if (lhs_value < rhs_value) return std::strong_ordering::less;
    if (lhs_value > rhs_value) return std::strong_ordering::greater;
    return std::strong_ordering::equal;
}

// Security event validation with modern error handling
constexpr zerossg::Result<SecurityEventType> validate_security_event(std::string_view event_str) noexcept {
    if (event_str.empty()) {
        return zerossg::make_result_error<SecurityEventType>("Event string cannot be empty");
    }
    
    // Use constexpr lookup table for validation
    constexpr std::array<std::string_view, 8> valid_events = {
        "login_success",
        "login_failure",
        "session_start",
        "session_termination",
        "authentication_error",
        "access_violation",
        "rate_limit_exceeded",
        "brute_force_detected"
    };
    
    if (const auto it = std::ranges::find(valid_events, event_str); 
        it != valid_events.end()) {
        const auto index = std::distance(valid_events.begin(), it);
        return zerossg::make_result_success<SecurityEventType>(
            static_cast<SecurityEventType>(index));
    }
    
    return zerossg::make_result_error<SecurityEventType>("Invalid security event type");
}

// Modern utility for role hierarchy checking
template<UserRole T>
constexpr bool is_admin_role() noexcept {
    return T::value == Role::ADMIN;
}

template<UserRole T>
constexpr bool is_operator_or_higher() noexcept {
    return static_cast<std::underlying_type_t<T>>(T::value) >= 
           static_cast<std::underlying_type_t<Role>>(Role::OPERATOR);
}

// Compile-time role set validation
template<UserRole... Roles>
constexpr bool all_roles_valid() noexcept {
    return (true && ... && (Roles::value <= static_cast<std::underlying_type_t<Role>>(Role::VIEWER)));
}

// Modern string utilities with constexpr support
constexpr bool is_valid_role_string(std::string_view role_str) noexcept {
    return role_str == "admin" || role_str == "operator" || role_str == "viewer";
}

constexpr bool is_valid_security_event_string(std::string_view event_str) noexcept {
    constexpr std::array valid_events = {
        "login_success",
        "login_failure", 
        "session_start",
        "session_termination",
        "authentication_error",
        "access_violation",
        "rate_limit_exceeded",
        "brute_force_detected"
    };
    
    return std::ranges::find(valid_events, event_str) != valid_events.end();
}

// Type-safe role enumeration with modern features
class RoleEnumerator {
public:
    constexpr RoleEnumerator() noexcept = default;
    
    [[nodiscard]] constexpr std::array<Role, 3> all_roles() const noexcept {
        return {Role::ADMIN, Role::OPERATOR, Role::VIEWER};
    }
    
    [[nodiscard]] constexpr size_t role_count() const noexcept {
        return 3;
    }
    
    template<UserRole T>
    [[nodiscard]] constexpr bool contains() const noexcept {
        constexpr auto roles = all_roles();
        return std::ranges::find(roles, T{}) != roles.end();
    }
};

// Modern security event utilities
class SecurityEventAnalyzer {
public:
    constexpr SecurityEventAnalyzer() noexcept = default;
    
    [[nodiscard]] constexpr bool is_authentication_event(SecurityEventType type) const noexcept {
        return type == SecurityEventType::LOGIN_SUCCESS || 
               type == SecurityEventType::LOGIN_FAILURE ||
               type == SecurityEventType::AUTHENTICATION_ERROR;
    }
    
    [[nodiscard]] constexpr bool is_session_event(SecurityEventType type) const noexcept {
        return type == SecurityEventType::SESSION_START || 
               type == SecurityEventType::SESSION_TERMINATION;
    }
    
    [[nodiscard]] constexpr bool is_security_violation(SecurityEventType type) const noexcept {
        return type == SecurityEventType::ACCESS_VIOLATION ||
               type == SecurityEventType::RATE_LIMIT_EXCEEDED ||
               type == SecurityEventType::BRUTE_FORCE_DETECTED;
    }
};

// Modern type-safe builders
class UserBuilder {
private:
    std::string m_username;
    std::string m_password_hash;
    Role m_role{Role::VIEWER};
    bool m_active{false};
    
public:
    constexpr UserBuilder() noexcept = default;
    
    constexpr UserBuilder& username(std::string uname) noexcept {
        m_username = std::move(uname);
        return *this;
    }
    
    constexpr UserBuilder& password_hash(std::string hash) noexcept {
        m_password_hash = std::move(hash);
        return *this;
    }
    
    template<UserRole T>
    constexpr UserBuilder& role() noexcept {
        m_role = T{};
        return *this;
    }
    
    constexpr UserBuilder& set_active(bool active) noexcept {
        m_active = active;
        return *this;
    }
    
    [[nodiscard]] constexpr User build() const noexcept {
        return User{m_username, m_password_hash, m_role};
    }
    
    [[nodiscard]] constexpr bool is_valid() const noexcept {
        return !m_username.empty() && !m_password_hash.empty();
    }
};

// Modern session utilities
class SessionValidator {
public:
    constexpr SessionValidator() noexcept = default;
    
    [[nodiscard]] static constexpr bool is_valid_session_id(std::string_view session_id) noexcept {
        return !session_id.empty() && session_id.size() >= 16;
    }
    
    [[nodiscard]] static constexpr bool is_valid_client_ip(std::string_view ip) noexcept {
        if (ip.empty()) return false;
        
        // Basic IPv4 validation
        size_t dot_count = 0;
        for (char c : ip) {
            if (c == '.') ++dot_count;
            if (!std::isdigit(c) && c != '.') return false;
        }
        
        return dot_count == 3 && dot_count < ip.size() - 1;
    }
    
    [[nodiscard]] static constexpr bool is_session_expired(const Session& session) noexcept {
        return session.is_expired();
    }
    
    [[nodiscard]] static constexpr auto time_until_expiry(const Session& session) noexcept {
        return session.time_until_expiry();
    }
};

} // namespace utils

} // namespace zerossg
