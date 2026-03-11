#include "zerossg/types.hpp"
#include <stdexcept>

namespace zerossg {

string role_to_string(Role role) {
    switch (role) {
        case Role::ADMIN: return "admin";
        case Role::OPERATOR: return "operator";
        case Role::VIEWER: return "viewer";
        default: throw std::invalid_argument("Invalid role value");
    }
}

Role string_to_role(const string& role_str) {
    if (role_str == "admin") return Role::ADMIN;
    if (role_str == "operator") return Role::OPERATOR;
    if (role_str == "viewer") return Role::VIEWER;
    throw std::invalid_argument("Invalid role string: " + role_str);
}

string security_event_type_to_string(SecurityEventType type) {
    switch (type) {
        case SecurityEventType::LOGIN_SUCCESS: return "login_success";
        case SecurityEventType::LOGIN_FAILURE: return "login_failure";
        case SecurityEventType::SESSION_START: return "session_start";
        case SecurityEventType::SESSION_TERMINATION: return "session_termination";
        case SecurityEventType::AUTHENTICATION_ERROR: return "authentication_error";
        case SecurityEventType::ACCESS_VIOLATION: return "access_violation";
        case SecurityEventType::RATE_LIMIT_EXCEEDED: return "rate_limit_exceeded";
        case SecurityEventType::BRUTE_FORCE_DETECTED: return "brute_force_detected";
        default: throw std::invalid_argument("Invalid security event type");
    }
}

} // namespace zerossg
