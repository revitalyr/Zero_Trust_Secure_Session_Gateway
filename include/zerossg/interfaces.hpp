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
    virtual Result<string> authenticate(const string& username, const string& password) = 0;
    virtual Result<bool> validate_token(const string& token) = 0;
    virtual Result<User> get_user_from_token(const string& token) = 0;
    virtual Result<string> generate_token(const User& user) = 0;
    virtual Result<void> revoke_token(const string& token) = 0;
};

// Interface for authorization
class IAuthorizer {
public:
    virtual ~IAuthorizer() = default;
    virtual Result<bool> can_access_service(const User& user, const string& service_name) = 0;
    virtual Result<bool> has_permission(const User& user, const string& permission) = 0;
    virtual Result<vector<string>> get_allowed_services(const User& user) = 0;
};

// Interface for session management
class ISessionManager {
public:
    virtual ~ISessionManager() = default;
    virtual Result<string> create_session(const User& user, const string& client_ip, const string& target_service) = 0;
    virtual Result<Session> get_session(const string& session_id) = 0;
    virtual Result<void> update_session(const string& session_id, const Session& session) = 0;
    virtual Result<void> terminate_session(const string& session_id) = 0;
    virtual Result<vector<Session>> get_active_sessions() = 0;
    virtual Result<void> cleanup_expired_sessions() = 0;
};

// Interface for security controls
class ISecurityManager {
public:
    virtual ~ISecurityManager() = default;
    virtual Result<bool> check_rate_limit(const string& client_ip) = 0;
    virtual Result<bool> detect_brute_force(const string& client_ip) = 0;
    virtual void record_failed_attempt(const string& client_ip) = 0;
    virtual void record_successful_login(const string& client_ip) = 0;
    virtual Result<void> block_ip(const string& client_ip, milliseconds duration) = 0;
    virtual bool is_ip_blocked(const string& client_ip) = 0;
};

// Interface for logging
class ILogger {
public:
    virtual ~ILogger() = default;
    virtual void log_security_event(const SecurityEvent& event) = 0;
    virtual void log_session_event(const string& session_id, const string& event_type, const string& details) = 0;
    virtual void log_error(const string& component, const string& error) = 0;
    virtual void log_info(const string& component, const string& message) = 0;
    virtual void log_debug(const string& component, const string& message) = 0;
};

// Interface for configuration
class IConfigManager {
public:
    virtual ~IConfigManager() = default;
    virtual Result<void> load_config(const string& config_file) = 0;
    virtual string get_string(const string& key, const string& default_value = "") = 0;
    virtual int get_int(const string& key, int default_value = 0) = 0;
    virtual bool get_bool(const string& key, bool default_value = false) = 0;
    virtual vector<string> get_string_array(const string& key) = 0;
    virtual Result<TargetService> get_target_service(const string& service_name) = 0;
    virtual Result<vector<TargetService>> get_all_target_services() = 0;
};

// Interface for TLS handling
class ITlsHandler {
public:
    virtual ~ITlsHandler() = default;
    virtual Result<void> initialize(const string& cert_file, const string& key_file) = 0;
    virtual boost::asio::ssl::context& get_context() = 0;
    virtual Result<bool> verify_certificate(const string& cert_data) = 0;
};

// Interface for proxy functionality
class IProxy {
public:
    virtual ~IProxy() = default;
    virtual Result<void> start_proxy(const string& session_id, const ConnectionInfo& client_conn, 
                                   const TargetService& target) = 0;
    virtual Result<void> stop_proxy(const string& session_id) = 0;
    virtual bool is_proxy_active(const string& session_id) = 0;
};

// Interface for CLI
class ICLI {
public:
    virtual ~ICLI() = default;
    virtual Result<int> run(int argc, char* argv[]) = 0;
    virtual void show_help() = 0;
    virtual void show_active_sessions() = 0;
    virtual void export_audit_logs(const string& output_file) = 0;
};

} // namespace zerossg
