module;

#include <atomic>
#include <chrono>
#include <mutex>
#include <random>
#include <string>

export module zerossg.session.session_manager;

// C++23 module imports
import zerossg.interfaces;
import zerossg.types;
import zerossg.constants;

namespace zerossg {

// Import needed types
using zerossg::User;
using zerossg::SessionId;
using zerossg::ClientIp;
using zerossg::ServiceName;

export class SessionManager : public ISessionManager {
public:
    SessionManager();
    ~SessionManager() override = default;
    
    // ISessionManager interface
    Result<SessionId> create_session(const User& user, const ClientIp& client_ip, const ServiceName& target_service) override;
    Result<Session> get_session(const SessionId& session_id) override;
    Result<void> update_session(const SessionId& session_id, const Session& session) override;
    Result<void> terminate_session(const SessionId& session_id) override;
    Result<Sessions> get_active_sessions() override;
    Result<void> cleanup_expired_sessions() override;
    
    // Session statistics
    size_t get_active_session_count() const;
    size_t get_total_session_count() const;
    
    // Session lifecycle management
    Result<void> extend_session(const SessionId& session_id, Seconds additional_time);
    Result<bool> is_session_valid(const SessionId& session_id);
    
    // Session filtering
    Result<Vector<Session>> get_sessions_by_user(const UserName& username);
    Result<Vector<Session>> get_sessions_by_service(const ServiceName& service_name);
    Result<Vector<Session>> get_sessions_by_ip(const ClientIp& client_ip);
    
private:
    // Session storage
    UnorderedMap<SessionId, Session> m_sessions;
    mutable std::mutex m_sessions_mutex;
    
    // Statistics
    std::atomic<size_t> m_total_sessions{0};
    
    // Session ID generation
    std::random_device m_random_device;
    std::mt19937 m_random_generator;
    
    // Helper methods
    SessionId generate_session_id();
    void cleanup_expired_sessions_internal();
    
    // Configuration
    static constexpr Seconds DEFAULT_SESSION_TIMEOUT{3600}; // 1 hour
    static constexpr size_t SESSION_ID_SIZE = 32;
    static constexpr size_t MAX_SESSIONS_PER_USER = 5;
    
    // Helper methods
    bool is_user_at_session_limit(const UserName& username);
    String format_session_duration(const std::chrono::system_clock::time_point& start, const std::chrono::system_clock::time_point& end);
};

} // namespace zerossg
