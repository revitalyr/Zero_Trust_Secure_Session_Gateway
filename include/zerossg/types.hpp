#pragma once

#include "common.hpp"
#include <boost/asio.hpp>
#include <array>
#include <span>

namespace zerossg {

// Modern enum class with explicit underlying type
enum class Role : uint8_t {
    ADMIN = 0,
    OPERATOR = 1,
    VIEWER = 2
};

// Modern constexpr functions for enum conversion
constexpr string_view role_to_string(Role role) noexcept {
    constexpr std::array role_names = {"admin", "operator", "viewer"};
    const auto index = static_cast<std::size_t>(role);
    return index < role_names.size() ? role_names[index] : string_view{};
}

constexpr Role string_to_role(string_view role_str) noexcept {
    if (role_str == "admin") return Role::ADMIN;
    if (role_str == "operator") return Role::OPERATOR;
    if (role_str == "viewer") return Role::VIEWER;
    return Role::VIEWER; // Default fallback
}

// Modern User struct with semantic member names
struct User {
    UserName m_user_name;
    PasswordHash m_password_hash;
    Role m_role;
    bool m_active;
    TimePoint m_created_at;
    TimePoint m_last_login;
    
    constexpr User() noexcept 
        : m_role(Role::VIEWER)
        , m_active(false) {}
    
    constexpr User(UserName username, PasswordHash password_hash, Role role) noexcept
        : m_user_name(std::move(username))
        , m_password_hash(std::move(password_hash))
        , m_role(role)
        , m_active(true)
        , m_created_at(system_clock::now()) {}
    
    // Modern accessor methods
    [[nodiscard]] constexpr const UserName& user_name() const noexcept { return m_user_name; }
    [[nodiscard]] constexpr const PasswordHash& password_hash() const noexcept { return m_password_hash; }
    [[nodiscard]] constexpr Role role() const noexcept { return m_role; }
    [[nodiscard]] constexpr bool is_active() const noexcept { return m_active; }
    [[nodiscard]] constexpr TimePoint created_at() const noexcept { return m_created_at; }
    [[nodiscard]] constexpr TimePoint last_login() const noexcept { return m_last_login; }
    
    void set_last_login(TimePoint time) noexcept { m_last_login = time; }
    void set_active(bool active) noexcept { m_active = active; }
};

// Modern Session struct with semantic member names
struct Session {
    SessionId m_session_id;
    UserName m_user_name;
    Role m_role;
    TimePoint m_created_at;
    TimePoint m_expires_at;
    ClientIp m_client_ip;
    ServiceName m_target_service;
    bool m_active;
    
    constexpr Session() noexcept 
        : m_role(Role::VIEWER)
        , m_active(false) {}
    
    constexpr Session(SessionId session_id, UserName username, Role role, 
                   ClientIp client_ip, ServiceName target_service) noexcept
        : m_session_id(std::move(session_id))
        , m_user_name(std::move(username))
        , m_role(role)
        , m_client_ip(std::move(client_ip))
        , m_target_service(std::move(target_service))
        , m_active(true)
        , m_created_at(system_clock::now())
        , m_expires_at(m_created_at + seconds(3600)) {}
    
    // Accessor methods with semantic return types
    [[nodiscard]] constexpr const SessionId& session_id() const noexcept { return m_session_id; }
    [[nodiscard]] constexpr const UserName& user_name() const noexcept { return m_user_name; }
    [[nodiscard]] constexpr Role role() const noexcept { return m_role; }
    [[nodiscard]] constexpr bool is_active() const noexcept { return m_active; }
    [[nodiscard]] constexpr TimePoint created_at() const noexcept { return m_created_at; }
    [[nodiscard]] constexpr TimePoint expires_at() const noexcept { return m_expires_at; }
    [[nodiscard]] constexpr const ClientIp& client_ip() const noexcept { return m_client_ip; }
    [[nodiscard]] constexpr const ServiceName& target_service() const noexcept { return m_target_service; }
    
    // Mutator methods
    void set_active(bool active) noexcept { m_active = active; }
    void set_expires_at(TimePoint expires) noexcept { m_expires_at = expires; }
    
    // Utility methods
    [[nodiscard]] bool is_expired() const noexcept {
        return system_clock::now() > m_expires_at;
    }
    
    [[nodiscard]] TimeoutDuration time_until_expiry() const noexcept {
        const auto now = system_clock::now();
        if (now >= m_expires_at) {
            return TimeoutDuration{0};
        }
        return std::chrono::duration_cast<TimeoutDuration>(m_expires_at - now);
    }
};

// Modern SecurityEventType with explicit underlying type
enum class SecurityEventType : uint8_t {
    LOGIN_SUCCESS = 0,
    LOGIN_FAILURE = 1,
    SESSION_START = 2,
    SESSION_TERMINATION = 3,
    AUTHENTICATION_ERROR = 4,
    ACCESS_VIOLATION = 5,
    RATE_LIMIT_EXCEEDED = 6,
    BRUTE_FORCE_DETECTED = 7
};

// Modern constexpr function for security event type conversion
constexpr string_view security_event_type_to_string(SecurityEventType type) noexcept {
    constexpr std::array event_names = {
        "login_success",
        "login_failure", 
        "session_start",
        "session_termination",
        "authentication_error",
        "access_violation",
        "rate_limit_exceeded",
        "brute_force_detected"
    };
    const auto index = static_cast<std::size_t>(type);
    return index < event_names.size() ? event_names[index] : string_view{};
}

// Modern SecurityEvent with better encapsulation
struct SecurityEvent {
    SecurityEventType m_type;
    system_clock::time_point m_timestamp;
    UserName m_username;
    ClientIp m_client_ip;
    std::string m_details;
    
    constexpr SecurityEvent(SecurityEventType type, UserName username, 
                        ClientIp client_ip, std::string details) noexcept
        : m_type(type)
        , m_timestamp(system_clock::now())
        , m_username(std::move(username))
        , m_client_ip(std::move(client_ip))
        , m_details(std::move(details)) {}
    
    // Accessors
    [[nodiscard]] constexpr SecurityEventType type() const noexcept { return m_type; }
    [[nodiscard]] constexpr system_clock::time_point timestamp() const noexcept { return m_timestamp; }
    [[nodiscard]] constexpr const UserName& username() const noexcept { return m_username; }
    [[nodiscard]] constexpr const ClientIp& client_ip() const noexcept { return m_client_ip; }
    [[nodiscard]] constexpr const std::string& details() const noexcept { return m_details; }
};

// Modern ConnectionInfo with better encapsulation
struct ConnectionInfo {
    TcpEndpoint m_remote_endpoint;
    TcpEndpoint m_local_endpoint;
    ClientIp m_client_ip;
    PortNo m_client_port;
    
    constexpr ConnectionInfo(const TcpEndpoint& remote,
                         const TcpEndpoint& local) noexcept
        : m_remote_endpoint(remote)
        , m_local_endpoint(local)
        , m_client_ip(remote.address().to_string())
        , m_client_port(remote.port()) {}
    
    // Accessors
    [[nodiscard]] constexpr const TcpEndpoint& remote_endpoint() const noexcept { 
        return m_remote_endpoint; 
    }
    [[nodiscard]] constexpr const TcpEndpoint& local_endpoint() const noexcept { 
        return m_local_endpoint; 
    }
    [[nodiscard]] constexpr const ClientIp& client_ip() const noexcept { return m_client_ip; }
    [[nodiscard]] constexpr PortNo client_port() const noexcept { return m_client_port; }
};

// Modern TargetService with better encapsulation and validation
struct TargetService {
    ServiceName m_name;
    HostAddress m_host;
    PortNo m_port;
    Roles<Role> m_allowed_roles;
    bool m_tls_enabled;
    
    constexpr TargetService() noexcept 
        : m_port(0)
        , m_tls_enabled(false) {}
    
    constexpr TargetService(ServiceName name, HostAddress host, PortNo port, 
                       Roles<Role> allowed_roles, bool tls_enabled) noexcept
        : m_name(std::move(name))
        , m_host(std::move(host))
        , m_port(port)
        , m_allowed_roles(std::move(allowed_roles))
        , m_tls_enabled(tls_enabled) {}
    
    // Accessors
    [[nodiscard]] constexpr const ServiceName& name() const noexcept { return m_name; }
    [[nodiscard]] constexpr const HostAddress& host() const noexcept { return m_host; }
    [[nodiscard]] constexpr PortNo port() const noexcept { return m_port; }
    [[nodiscard]] constexpr bool is_tls_enabled() const noexcept { return m_tls_enabled; }
    [[nodiscard]] constexpr const Roles<Role>& allowed_roles() const noexcept { return m_allowed_roles; }
    
    // Modern validation method
    [[nodiscard]] bool is_valid() const noexcept {
        return !m_name.empty() && !m_host.empty() && 
               m_port > 0 && m_port <= 65535 && !m_allowed_roles.empty();
    }
    
    // Modern role checking
    [[nodiscard]] bool is_role_allowed(Role role) const noexcept {
        return std::ranges::any_of(m_allowed_roles, 
            [role](Role allowed) { return allowed == role; });
    }
    
    // Utility methods
    [[nodiscard]] string get_address() const noexcept {
        return m_host + ":" + std::to_string(m_port);
    }
};

// Modern concepts for type checking
template<typename T>
concept UserRole = std::is_same_v<T, Role>;

template<typename T>
concept SecurityEvent = std::is_same_v<T, SecurityEventType>;

template<typename T>
concept ChronoTimePoint = requires {
    typename T::clock;
    typename T::duration;
    { T::clock::now() } -> std::same_as<T>;
};

// Modern utility functions
template<UserRole T>
constexpr string_view role_name() noexcept {
    return role_to_string(T{});
}

template<SecurityEvent T>
constexpr string_view event_name() noexcept {
    return security_event_type_to_string(T{});
}

// Modern span-based utilities
template<typename T>
constexpr bool contains_role(const vector<T>& roles, T role) noexcept {
    return std::ranges::any_of(roles, [role](const T& r) { return r == role; });
}

// Compile-time validation
template<typename T>
concept ValidTargetService = requires(T service) {
    { service.name() } -> std::convertible_to<string_view>;
    { service.host() } -> std::convertible_to<string_view>;
    { service.port() } -> std::convertible_to<uint16_t>;
    { service.is_valid() } -> std::convertible_to<bool>;
};

} // namespace zerossg
