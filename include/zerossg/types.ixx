module;

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <array>
#include <chrono>
#include <utility>
#include <algorithm>
#include <format>

export module zerossg.types;

export import zerossg.common;
export import zerossg.std;
export import zerossg.network;

export namespace zerossg {

// Basic type aliases
// Aliases like String, UserName, etc., are now in zerossg.common

// Import standard library types for clarity
// These are now imported via zerossg.std and aliased in zerossg.common

struct Session;
struct User;
struct TargetService;
struct SecurityEvent;
struct ConnectionInfo;


// Modern enum class with explicit underlying type
export enum class Role : uint8_t {
    ADMIN = 0,
    OPERATOR = 1,
    VIEWER = 2
};

// Modern constexpr functions for enum conversion
export constexpr StringView role_to_string(Role role) noexcept {
    switch (role) {
        case Role::ADMIN: return StringView{"admin"};
        case Role::OPERATOR: return StringView{"operator"};
        case Role::VIEWER: return StringView{"viewer"};
        default: return StringView{};
    }
}

export inline Role string_to_role(StringView role_str) noexcept {
    if (role_str == "admin") return Role::ADMIN;
    if (role_str == "operator") return Role::OPERATOR;
    if (role_str == "viewer") return Role::VIEWER;
    return Role::VIEWER; // Default fallback
}

// Modern User struct with semantic member names
export struct User {
    UserName m_user_name;
    PasswordHash m_password_hash;
    PasswordHash m_password_hash_confirm;
    Role m_role;
    TimePoint m_created_at;
    TimePoint m_last_login;
    bool m_active;
    
    User() noexcept 
        : m_role(Role::VIEWER)
        , m_active(false) {}
    
    User(UserName username, PasswordHash password_hash, Role role) noexcept
        : m_user_name(std::move(username))
        , m_password_hash(std::move(password_hash))
        , m_role(role)
        , m_active(true)
        , m_created_at(SystemClock::now()) {}
    
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
export struct Session {
    SessionId m_session_id;
    UserName m_user_name;
    Role m_role;
    TimePoint m_created_at;
    TimePoint m_expires_at;
    ClientIp m_client_ip;
    ServiceName m_target_service;
    bool m_active;
    
    Session() noexcept 
        : m_role(Role::VIEWER)
        , m_active(false) {}
    
    Session(SessionId session_id, UserName username, Role role,
                   ClientIp client_ip, ServiceName target_service,
                   TimePoint expires_at) noexcept
        : m_session_id(std::move(session_id))
        , m_user_name(std::move(username))
        , m_role(role)
        , m_client_ip(std::move(client_ip))
        , m_target_service(std::move(target_service))
        , m_active(true)
        , m_created_at(SystemClock::now())
        , m_expires_at(expires_at) {}
    
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
        return SystemClock::now() > m_expires_at;
    }
    
    [[nodiscard]] TimeoutDuration time_until_expiry() const noexcept {
        const auto now = SystemClock::now();
        if (now >= m_expires_at) {
            return TimeoutDuration{0};
        }
        return std::chrono::duration_cast<TimeoutDuration>(m_expires_at - now);
    }
};

// Modern SecurityEventType with explicit underlying type
export enum class SecurityEventType : uint8_t {
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
constexpr StringView security_event_type_to_string(SecurityEventType type) noexcept {
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
    const auto index = static_cast<size_t>(type);
    return index < event_names.size() ? event_names[index] : StringView{};
}

// Modern SecurityEvent with better encapsulation
export struct SecurityEvent {
    SecurityEventType m_type;
    TimePoint m_timestamp;
    UserName m_username;
    ClientIp m_client_ip;
    std::string m_details;
    
    SecurityEvent(SecurityEventType type, UserName username, 
                        ClientIp client_ip, std::string details) noexcept
        : m_type(type)
        , m_timestamp(SystemClock::now())
        , m_username(std::move(username))
        , m_client_ip(std::move(client_ip))
        , m_details(std::move(details)) {}
    
    // Accessors
    [[nodiscard]] constexpr SecurityEventType type() const noexcept { return m_type; }
    [[nodiscard]] constexpr TimePoint timestamp() const noexcept { return m_timestamp; }
    [[nodiscard]] constexpr const UserName& username() const noexcept { return m_username; }
    [[nodiscard]] constexpr const ClientIp& client_ip() const noexcept { return m_client_ip; }
    [[nodiscard]] constexpr const std::string& details() const noexcept { return m_details; }
};

// Modern ConnectionInfo with better encapsulation
export struct ConnectionInfo {
    TcpEndpoint m_remote_endpoint;
    TcpEndpoint m_local_endpoint;
    ClientIp m_client_ip;
    PortNo m_client_port;
    
    ConnectionInfo(const TcpEndpoint& remote,
                         const TcpEndpoint& local) noexcept
        : m_remote_endpoint(remote)
        , m_local_endpoint(local)
        , m_client_ip(remote.address().to_string())
        , m_client_port(remote.port()) {}
    
    // Accessors
    [[nodiscard]] const TcpEndpoint& remote_endpoint() const noexcept { 
        return m_remote_endpoint; 
    }
    [[nodiscard]] const TcpEndpoint& local_endpoint() const noexcept { 
        return m_local_endpoint; 
    }
    [[nodiscard]] const ClientIp& client_ip() const noexcept { return m_client_ip; }
    [[nodiscard]] PortNo client_port() const noexcept { return m_client_port; }
};

// Modern TargetService with better encapsulation and validation
export struct TargetService {
    ServiceName m_name;
    HostAddress m_host;
    PortNo m_port;
    Roles<Role> m_allowed_roles;
    bool m_tls_enabled;
    
    TargetService() noexcept 
        : m_port(0)
        , m_tls_enabled(false) {}
    
    TargetService(ServiceName name, HostAddress host, PortNo port, 
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
    [[nodiscard]] String get_address() const noexcept {
        return std::format("{}:{}", m_host, m_port);
    }
};

// Modern concepts for type checking
template<typename T>
concept UserRole = std::is_same_v<T, Role>;

template<typename T>
concept IsSecurityEventType = std::is_same_v<T, SecurityEventType>;

template<typename T>
concept ChronoTimePoint = requires {
    typename T::clock;
    typename T::duration;
    { T::clock::now() } -> std::same_as<T>;
};

// Modern utility functions
export template<UserRole T>
constexpr StringView role_name() noexcept {
    return role_to_string(T{});
}

export template<IsSecurityEventType T>
constexpr StringView event_name() noexcept {
    return security_event_type_to_string(T{});
}

// Modern span-based utilities
export template<typename T>
constexpr bool contains_role(const Vector<T>& roles, T role) noexcept {
    return std::ranges::any_of(roles, [role](const T& r) { return r == role; });
}

// Compile-time validation
export template<typename T>
concept ValidTargetService = requires(T service) {
    { service.name() } -> std::convertible_to<StringView>;
    { service.host() } -> std::convertible_to<StringView>;
    { service.port() } -> std::convertible_to<uint16_t>;
    { service.is_valid() } -> std::convertible_to<bool>;
};

// Additional type aliases for config
export using Users = Vector<User>;
export using Sessions = Vector<Session>;
export using TargetServices = Vector<TargetService>;
export using SecurityEvents = Vector<SecurityEvent>;
export using ConnectionInfos = Vector<ConnectionInfo>;
export using Permissions = Vector<Permission>;

// CLI aliases
export using CommandLineArgs = Vector<String>;
export using CommandName = String;
export using CommandDescription = String;
export using CommandUsage = String;
export using RawInputString = String;
export using TableData = Vector<Vector<String>>;
export using TableHeaders = Vector<String>;
export using SuccessString = String;
export using InfoString = String;
export using WarningString = String;

} // namespace zerossg
