export module zerossg.types;

export import zerossg.common;

export import <array>;
export import <span>;

export namespace zerossg {

// Forward declarations for types used in interfaces
export struct User;
export struct Session;
export struct TargetService;
export struct SecurityEvent;
export struct ConnectionInfo;

// Modern enum class with explicit underlying type
export enum class Role : uint8_t {
    ADMIN = 0,
    OPERATOR = 1,
    VIEWER = 2
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
