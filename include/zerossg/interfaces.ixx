export module zerossg.interfaces;

// C++23 module imports
export import zerossg.types;
export import <memory>;

export namespace zerossg {

// Forward declarations
export class AuthenticationManager;
export class AuthorizationManager;
export class SessionManager;
export class SecurityManager;
export class Logger;

// Interface for authentication
export class IAuthenticator {
public:
    virtual ~IAuthenticator() = default;
    virtual Result<String> authenticate(const UserName& username, const PasswordHash& password) = 0;
    virtual Result<bool> validate_token(const TokenString& token) = 0;
    virtual Result<User> get_user_from_token(const TokenString& token) = 0;
    virtual Result<TokenString> generate_token(const User& user) = 0;
    virtual Result<void> revoke_token(const TokenString& token) = 0;
};

// Interface for authorization
export class IAuthorizer {
public:
    virtual ~IAuthorizer() = default;
    virtual Result<bool> can_access_service(const User& user, const ServiceName& service_name) = 0;
    virtual Result<bool> has_permission(const User& user, const String& permission) = 0;
    virtual Result<Strings> get_allowed_services(const User& user) = 0;
};

// Interface for session management
export class ISessionManager {
public:
    virtual ~ISessionManager() = default;
    virtual Result<SessionId> create_session(const User& user, const ClientIp& client_ip, const ServiceName& target_service) = 0;
    virtual Result<Session> get_session(const SessionId& session_id) = 0;
    virtual Result<void> update_session(const SessionId& session_id, const Session& session) = 0;
    virtual Result<void> terminate_session(const SessionId& session_id) = 0;
    virtual Result<Sessions> get_active_sessions() = 0;
    virtual Result<void> cleanup_expired_sessions() = 0;
};

// Interface for security controls
export class ISecurityManager {
public:
    virtual ~ISecurityManager() = default;
    virtual Result<bool> check_rate_limit(const ClientIp& client_ip) = 0;
    virtual Result<bool> detect_brute_force(const ClientIp& client_ip) = 0;
    virtual void record_failed_attempt(const ClientIp& client_ip) = 0;
    virtual void record_successful_login(const ClientIp& client_ip) = 0;
    virtual Result<void> block_ip(const ClientIp& client_ip, Milliseconds duration) = 0;
    virtual bool is_ip_blocked(const ClientIp& client_ip) = 0;
};

// Interface for logging
export class ILogger {
public:
    virtual ~ILogger() = default;
    virtual void log_session_event(const SessionId& session_id, const String& event_type, const String& details) = 0;
    virtual void log_error(const String& component, const ErrorMessage& error) = 0;
    virtual void log_info(const String& component, const String& message) = 0;
    virtual void log_debug(const String& component, const String& message) = 0;
    virtual void log_security_event(const SecurityEvent& event) = 0;
};

// Interface for configuration
export class IConfigManager {
public:
    virtual ~IConfigManager() = default;
    virtual Result<void> load_config(const ConfigFileName& config_file) = 0;
    virtual String get_string(const String& key, const String& default_value = "") = 0;
    virtual int get_int(const String& key, int default_value = 0) = 0;
    virtual bool get_bool(const String& key, bool default_value = false) = 0;
    virtual Strings get_string_array(const String& key) = 0;
    virtual Result<TargetService> get_target_service(const ServiceName& service_name) = 0;
    virtual Result<TargetServices> get_all_target_services() = 0;
};

// Interface for TLS handling
export class ITlsHandler {
public:
    virtual ~ITlsHandler() = default;
    virtual Result<void> initialize(const FileName& cert_file, const FileName& key_file) = 0;
    virtual SslContext& get_context() = 0;
    virtual Result<bool> verify_certificate(const String& cert_data) = 0;
};

// Interface for proxy functionality
export class IProxy {
public:
    virtual ~IProxy() = default;
    virtual Result<void> start_proxy(const SessionId& session_id, const ConnectionInfo& client_conn, 
                                   const TargetService& target) = 0;
    virtual Result<void> stop_proxy(const SessionId& session_id) = 0;
    virtual bool is_proxy_active(const SessionId& session_id) = 0;
};

// Interface for CLI
export class ICLI {
public:
    virtual ~ICLI() = default;
    virtual Result<void> start_interactive_mode() = 0;
    virtual Result<void> execute_command(const std::string& command) = 0;
    virtual void show_status() = 0;
    virtual void show_sessions() = 0;
    virtual void show_users() = 0;
    virtual void export_audit_logs(const FileName& output_file) = 0;
    virtual void show_help() = 0;
    virtual void show_version() = 0;
};

} // namespace zerossg
