#pragma once

#include "common.hpp"
#include "types.hpp"
#include <boost/asio.hpp>

namespace zerossg {

// Forward declarations
class AuthenticationManager;
class AuthorizationManager;
class SessionManager;
class SecurityManager;
class Logger;

// Interface for authentication
class IAuthenticator {
public:
    virtual ~IAuthenticator() = default;
    virtual Result<std::string> authenticate(const UserName& username, const PasswordHash& password) = 0;
    virtual Result<bool> validate_token(const TokenString& token) = 0;
    virtual Result<User> get_user_from_token(const TokenString& token) = 0;
    virtual Result<TokenString> generate_token(const User& user) = 0;
    virtual Result<void> revoke_token(const TokenString& token) = 0;
};

// Interface for authorization
class IAuthorizer {
public:
    virtual ~IAuthorizer() = default;
    virtual Result<bool> can_access_service(const User& user, const ServiceName& service_name) = 0;
    virtual Result<bool> has_permission(const User& user, const std::string& permission) = 0;
    virtual Result<Strings> get_allowed_services(const User& user) = 0;
};

// Interface for session management
class ISessionManager {
public:
    virtual ~ISessionManager() = default;
    virtual Result<SessionId> create_session(const User& user, const ClientIp& client_ip, const ServiceName& target_service) = 0;
    virtual Result<Session> get_session(const SessionId& session_id) = 0;
    virtual Result<void> update_session(const SessionId& session_id, const Session& session) = 0;
    virtual Result<void> terminate_session(const SessionId& session_id) = 0;
    virtual Result<std::vector<Session>> get_active_sessions() = 0;
    virtual Result<void> cleanup_expired_sessions() = 0;
};

// Interface for security controls
class ISecurityManager {
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
class ILogger {
public:
    virtual ~ILogger() = default;
    virtual void log_security_event(const SecurityEvent& event) = 0;
    virtual void log_session_event(const SessionId& session_id, const std::string& event_type, const std::string& details) = 0;
    virtual void log_error(const std::string& component, const ErrorMessage& error) = 0;
    virtual void log_info(const std::string& component, const std::string& message) = 0;
    virtual void log_debug(const std::string& component, const std::string& message) = 0;
};

// Interface for configuration
class IConfigManager {
public:
    virtual ~IConfigManager() = default;
    virtual Result<void> load_config(const ConfigFileName& config_file) = 0;
    virtual std::string get_string(const std::string& key, const std::string& default_value = "") = 0;
    virtual int get_int(const std::string& key, int default_value = 0) = 0;
    virtual bool get_bool(const std::string& key, bool default_value = false) = 0;
    virtual Strings get_string_array(const std::string& key) = 0;
    virtual Result<TargetService> get_target_service(const ServiceName& service_name) = 0;
    virtual Result<std::vector<TargetService>> get_all_target_services() = 0;
};

// Interface for TLS handling
class ITlsHandler {
public:
    virtual ~ITlsHandler() = default;
    virtual Result<void> initialize(const FileName& cert_file, const FileName& key_file) = 0;
    virtual boost::asio::ssl::context& get_context() = 0;
    virtual Result<bool> verify_certificate(const std::string& cert_data) = 0;
};

// Interface for proxy functionality
class IProxy {
public:
    virtual ~IProxy() = default;
    virtual Result<void> start_proxy(const SessionId& session_id, const ConnectionInfo& client_conn, 
                                   const TargetService& target) = 0;
    virtual Result<void> stop_proxy(const SessionId& session_id) = 0;
    virtual bool is_proxy_active(const SessionId& session_id) = 0;
};

// Interface for CLI
class ICLI {
public:
    virtual ~ICLI() = default;
    virtual Result<int> run(int argc, char* argv[]) = 0;
    virtual void show_help() = 0;
    virtual void show_active_sessions() = 0;
    virtual void export_audit_logs(const FileName& output_file) = 0;
};

} // namespace zerossg
