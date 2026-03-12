#pragma once

// Project headers
#include "zerossg/interfaces.hpp"

// C++ Standard Library headers
#include <mutex>
#include <random>
#include <unordered_map>

namespace zerossg {

class SessionManager : public ISessionManager {
public:
    SessionManager();
    ~SessionManager() override = default;
    
    // ISessionManager interface
    Result<string> create_session(const User& user, const string& client_ip, const string& target_service) override;
    Result<Session> get_session(const string& session_id) override;
    Result<void> update_session(const string& session_id, const Session& session) override;
    Result<void> terminate_session(const string& session_id) override;
    Result<vector<Session>> get_active_sessions() override;
    Result<void> cleanup_expired_sessions() override;
    
    // Session statistics
    size_t get_active_session_count() const;
    size_t get_total_session_count() const;
    
    // Session lifecycle management
    Result<void> extend_session(const string& session_id, seconds additional_time);
    Result<bool> is_session_valid(const string& session_id);
    
    // Session filtering
    Result<vector<Session>> get_sessions_by_user(const string& username);
    Result<vector<Session>> get_sessions_by_service(const string& service_name);
    Result<vector<Session>> get_sessions_by_ip(const string& client_ip);
    
private:
    // Session storage
    unordered_map<string, Session> m_sessions;
    mutable std::mutex m_sessions_mutex;
    
    // Statistics
    std::atomic<size_t> m_total_sessions{0};
    
    // Session ID generation
    std::random_device m_random_device;
    std::mt19937 m_random_generator;
    
    // Configuration
    static constexpr seconds DEFAULT_SESSION_TIMEOUT{3600}; // 1 hour
    static constexpr size_t SESSION_ID_SIZE = 32;
    static constexpr size_t MAX_SESSIONS_PER_USER = 5;
    
    // Helper methods
    string generate_session_id();
    bool is_user_at_session_limit(const string& username);
    void cleanup_expired_sessions_internal();
    string format_session_duration(const system_clock::time_point& start, const system_clock::time_point& end);
};

} // namespace zerossg
