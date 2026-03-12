export module zerossg.types;

export import zerossg.common;

export import <array>;
export import <span>;
export import <algorithm>;
export import <vector>;

export namespace zerossg {

// Modern enum class with explicit underlying type
export enum class Role : uint8_t {
    ADMIN = 0,
    OPERATOR = 1,
    VIEWER = 2
};

// Modern constexpr functions for enum conversion
export constexpr string_view role_to_string(Role role) noexcept {
    constexpr std::array role_names = {"admin", "operator", "viewer"};
    const auto index = static_cast<std::size_t>(role);
    return index < role_names.size() ? role_names[index] : string_view{};
}

export constexpr Role string_to_role(string_view role_str) noexcept {
    if (role_str == "admin") return Role::ADMIN;
    if (role_str == "operator") return Role::OPERATOR;
    if (role_str == "viewer") return Role::VIEWER;
    return Role::VIEWER; // Default fallback
}

// Modern User struct with semantic member names
export struct User {
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
    
    // Mutator methods
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
export constexpr string_view security_event_type_to_string(SecurityEventType type) noexcept {
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
export struct SecurityEvent {
    SecurityEventType m_type;
    system_clock::time_point m_timestamp;
    UserName m_username;
    ClientIp m_client_ip;
    String m_details;
    
    constexpr SecurityEvent(SecurityEventType type, UserName username, 
                        ClientIp client_ip, String details) noexcept
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
    [[nodiscard]] constexpr const String& details() const noexcept { return m_details; }
};

// Modern ConnectionInfo with better encapsulation
export struct ConnectionInfo {
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
export struct TargetService {
    ServiceName m_name;
    HostAddress m_host;
    PortNo m_port;
    Vector<Role> m_allowed_roles;
    bool m_tls_enabled;
    
    constexpr TargetService() noexcept 
        : m_port(0)
        , m_tls_enabled(false) {}
    
    constexpr TargetService(ServiceName name, HostAddress host, PortNo port, 
                       Vector<Role> allowed_roles, bool tls_enabled) noexcept
        : m_name(std::move(name))
        , m_host(std::move(host))
        , m_port(port)
        , m_allowed_roles(std::move(allowed_roles))
        , m_tls_enabled(tls_enabled) {}
    
    // Accessors
    [[nodiscard]] constexpr const ServiceName& name() const noexcept { return m_name; }
    [[nodiscard]] constexpr const HostAddress& host() const noexcept { return m_host; }
    [[nodiscard]] constexpr PortNo port() const noexcept { return m_port; }
    [[nodiscard]] constexpr const Vector<Role>& allowed_roles() const noexcept { return m_allowed_roles; }
    [[nodiscard]] constexpr bool tls_enabled() const noexcept { return m_tls_enabled; }
    
    // Validation methods
    [[nodiscard]] bool is_valid() const noexcept {
        return !m_name.empty() && m_port > 0 && m_port <= 65535;
    }
    
    [[nodiscard]] bool is_role_allowed(Role role) const noexcept {
        return std::ranges::find(m_allowed_roles, role) != m_allowed_roles.end();
    }
};

// Modern enum class for user status
export enum class UserStatus : uint8_t {
    ACTIVE = 0,
    INACTIVE = 1,
    BLOCKED = 2,
    SUSPENDED = 3
};

// Modern enum class for session status
export enum class SessionStatus : uint8_t {
    ACTIVE = 0,
    TERMINATED = 1,
    EXPIRED = 2,
    ERROR = 3
};

// Modern enum class for security event types
export enum class SecurityEventType : uint8_t {
    LOGIN_SUCCESS = 0,
    LOGIN_FAILURE = 1,
    SESSION_START = 2,
    SESSION_END = 3,
    ACCESS_DENIED = 4,
    RATE_LIMIT_EXCEEDED = 5,
    BRUTE_FORCE_DETECTED = 6,
    IP_BLOCKED = 7
};

// Modern enum class for connection states
export enum class ConnectionState : uint8_t {
    DISCONNECTED = 0,
    CONNECTING = 1,
    CONNECTED = 2,
    DISCONNECTING = 3,
    ERROR = 4
};

// User structure with modern C++26 features
export struct User {
    UserName username;
    PasswordHash password_hash;
    Role role{Role::VIEWER};
    UserStatus status{UserStatus::ACTIVE};
    std::chrono::system_clock::time_point created_at{std::chrono::system_clock::now()};
    std::chrono::system_clock::time_point last_login{};
    std::chrono::system_clock::time_point password_changed{std::chrono::system_clock::now()};
    bool is_active() const noexcept { return status == UserStatus::ACTIVE; }
    bool is_blocked() const noexcept { return status == UserStatus::BLOCKED; }
};

// Session structure with modern C++26 features
export struct Session {
    SessionId id;
    UserName username;
    ClientIp client_ip;
    ServiceName target_service;
    SessionStatus status{SessionStatus::ACTIVE};
    std::chrono::system_clock::time_point created_at{std::chrono::system_clock::now()};
    std::chrono::system_clock::time_point expires_at{};
    std::chrono::system_clock::time_point last_activity{std::chrono::system_clock::now()};
    bool is_expired() const noexcept { return std::chrono::system_clock::now() > expires_at; }
    bool is_active() const noexcept { return status == SessionStatus::ACTIVE && !is_expired(); }
};

// Target service structure with modern C++26 features
export struct TargetService {
    ServiceName name;
    HostAddress host;
    PortNo port;
    std::vector<Role> allowed_roles{Role::VIEWER};
    bool requires_tls{false};
    std::chrono::milliseconds timeout{30000};
    bool is_role_allowed(Role role) const noexcept {
        return std::ranges::find(allowed_roles, role) != allowed_roles.end();
    }
};

// Security event structure with modern C++26 features
export struct SecurityEvent {
    SecurityEventType type;
    UserName username{};
    ClientIp client_ip{};
    std::chrono::system_clock::time_point timestamp{std::chrono::system_clock::now()};
    std::string details;
    bool is_critical() const noexcept {
        return type == SecurityEventType::BRUTE_FORCE_DETECTED ||
               type == SecurityEventType::IP_BLOCKED;
    }
};

// Connection information structure with modern C++26 features
export struct ConnectionInfo {
    TcpEndpoint client_endpoint;
    TcpEndpoint server_endpoint;
    ConnectionState state{ConnectionState::DISCONNECTED};
    std::chrono::system_clock::time_point connected_at{};
    std::chrono::system_clock::time_point last_activity{std::chrono::system_clock::now()};
    std::size_t bytes_sent{0};
    std::size_t bytes_received{0};
    bool is_active() const noexcept { return state == ConnectionState::CONNECTED; }
    std::chrono::duration<double> uptime() const noexcept {
        if (state == ConnectionState::CONNECTED) {
            return std::chrono::system_clock::now() - connected_at;
        }
        return std::chrono::duration<double>{0};
    }
};

// Rate limiting structure with modern C++26 features
export struct RateLimitInfo {
    Count attempts{0};
    std::chrono::system_clock::time_point window_start{std::chrono::system_clock::now()};
    std::chrono::seconds window_duration{300}; // 5 minutes
    bool is_limit_exceeded(RateLimit max_attempts) const noexcept {
        return attempts >= max_attempts;
    }
    void reset_window() noexcept {
        attempts = 0;
        window_start = std::chrono::system_clock::now();
    }
    bool should_reset_window() const noexcept {
        return std::chrono::system_clock::now() > (window_start + window_duration);
    }
};

// Modern concepts for type checking
export template<typename T>
concept UserType = requires(T t) {
    { t.username } -> std::convertible_to<UserName>;
    { t.role } -> std::convertible_to<Role>;
    { t.status } -> std::convertible_to<UserStatus>;
    { t.is_active() } -> std::same_as<bool>;
};

export template<typename T>
concept SessionType = requires(T t) {
    { t.id } -> std::convertible_to<SessionId>;
    { t.username } -> std::convertible_to<UserName>;
    { t.status } -> std::convertible_to<SessionStatus>;
    { t.is_active() } -> std::same_as<bool>;
    { t.is_expired() } -> std::same_as<bool>;
};

export template<typename T>
concept ServiceType = requires(T t) {
    { t.name } -> std::convertible_to<ServiceName>;
    { t.host } -> std::convertible_to<HostAddress>;
    { t.port } -> std::convertible_to<PortNo>;
    { t.is_role_allowed(Role{}) } -> std::same_as<bool>;
};

// Modern utility functions with concepts
export template<UserType T>
constexpr bool is_user_admin(const T& user) noexcept {
    return user.role == Role::ADMIN;
}

export template<SessionType T>
constexpr bool is_session_valid(const T& session) noexcept {
    return session.is_active() && !session.is_expired();
}

export template<ServiceType T>
constexpr bool can_user_access_service(const UserType auto& user, const T& service) noexcept {
    return service.is_role_allowed(user.role);
}

} // namespace zerossg
