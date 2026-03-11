#pragma once

#include "common.hpp"
#include <boost/asio.hpp>

namespace zerossg {

// User roles
enum class Role {
    ADMIN,
    OPERATOR,
    VIEWER
};

// Convert role to string
string role_to_string(Role role);
Role string_to_role(const string& role_str);

// User information
struct User {
    string username;
    string password_hash;
    Role role;
    bool active;
    system_clock::time_point created_at;
    system_clock::time_point last_login;
    
    User() : active(false) {}
    
    User(string uname, string pwhash, Role r)
        : username(std::move(uname))
        , password_hash(std::move(pwhash))
        , role(r)
        , active(true)
        , created_at(system_clock::now())
    {}
};

// Session information
struct Session {
    string session_id;
    string username;
    Role role;
    system_clock::time_point created_at;
    system_clock::time_point expires_at;
    string client_ip;
    string target_service;
    bool active;
    
    Session() : active(false) {}
    
    Session(string sid, string uname, Role r, string client_ip_str, string target)
        : session_id(std::move(sid))
        , username(std::move(uname))
        , role(r)
        , client_ip(std::move(client_ip_str))
        , target_service(std::move(target))
        , active(true)
        , created_at(system_clock::now())
        , expires_at(created_at + seconds(3600)) // 1 hour default
    {}
};

// Security event types
enum class SecurityEventType {
    LOGIN_SUCCESS,
    LOGIN_FAILURE,
    SESSION_START,
    SESSION_TERMINATION,
    AUTHENTICATION_ERROR,
    ACCESS_VIOLATION,
    RATE_LIMIT_EXCEEDED,
    BRUTE_FORCE_DETECTED
};

string security_event_type_to_string(SecurityEventType type);

// Security event
struct SecurityEvent {
    SecurityEventType type;
    system_clock::time_point timestamp;
    string username;
    string client_ip;
    string details;
    
    SecurityEvent(SecurityEventType t, string uname, string ip, string det)
        : type(t)
        , timestamp(system_clock::now())
        , username(std::move(uname))
        , client_ip(std::move(ip))
        , details(std::move(det))
    {}
};

// Network connection information
struct ConnectionInfo {
    boost::asio::ip::tcp::endpoint remote_endpoint;
    boost::asio::ip::tcp::endpoint local_endpoint;
    string client_ip;
    uint16_t client_port;
    
    ConnectionInfo(const boost::asio::ip::tcp::endpoint& remote, 
                   const boost::asio::ip::tcp::endpoint& local)
        : remote_endpoint(remote)
        , local_endpoint(local)
        , client_ip(remote.address().to_string())
        , client_port(remote.port())
    {}
};

// Target service configuration
struct TargetService {
    string name;
    string host;
    uint16_t port;
    vector<Role> allowed_roles;
    bool tls_enabled;
    
    TargetService() : port(0), tls_enabled(false) {}
    
    TargetService(string n, string h, uint16_t p, vector<Role> roles, bool tls)
        : name(std::move(n))
        , host(std::move(h))
        , port(p)
        , allowed_roles(std::move(roles))
        , tls_enabled(tls)
    {}
};

} // namespace zerossg
