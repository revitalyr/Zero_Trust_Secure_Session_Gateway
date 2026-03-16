module;
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
module zerossg.session.session_manager;

// C++23 module imports
import zerossg.constants;
import zerossg.types;

// Standard library imports
import zerossg.std;

namespace zerossg {

SessionManager::SessionManager() : m_random_generator(m_random_device()) {
}

zerossg::Result<zerossg::SessionId> SessionManager::create_session(const zerossg::User& user, const zerossg::ClientIp& client_ip, const zerossg::ServiceName& target_service) {
    LockGuard<std::mutex> lock(m_sessions_mutex);
    
    // Check if user has reached session limit
    if (is_user_at_session_limit(user.user_name())) {
        return make_result_error<SessionId>(std::format("{}{}", zerossg::ERROR_MAXIMUM_SESSION_LIMIT, user.user_name()));
    }
    
    // Generate unique session ID
    SessionId session_id = generate_session_id();
    
    // Check for collision (very unlikely, but handle it)
    while (m_sessions.find(session_id) != m_sessions.end()) {
        session_id = generate_session_id();
    }
    
    // Create session
    zerossg::Session session(session_id, user.user_name(), user.role(), client_ip, target_service);
    session.m_expires_at = std::chrono::system_clock::now() + zerossg::DEFAULT_SESSION_TIMEOUT;
    
    // Store session
    m_sessions[session_id] = session;
    m_total_sessions.fetch_add(1);
    
    return make_result_success(session_id);
}

zerossg::Result<zerossg::Session> SessionManager::get_session(const zerossg::SessionId& session_id) {
    LockGuard<std::mutex> lock(m_sessions_mutex);
    
    auto it = m_sessions.find(session_id);
    if (it == m_sessions.end()) {
        return make_result_error<Session>(std::format("{}{}", zerossg::ERROR_SESSION_NOT_FOUND_PREFIX, session_id));
    }
    
    const zerossg::Session& session = it->second;
    
    // Check if session has expired
    if (session.is_expired()) {
        // Remove expired session
        m_sessions.erase(it);
        return make_result_error<Session>(std::format("{}{}", zerossg::ERROR_SESSION_EXPIRED_PREFIX, session_id));
    }
    
    return make_result_success(session);
}

zerossg::Result<void> SessionManager::update_session(const zerossg::SessionId& session_id, const zerossg::Session& session) {
    LockGuard<std::mutex> lock(m_sessions_mutex);
    
    auto it = m_sessions.find(session_id);
    if (it == m_sessions.end()) {
        return make_result_error(std::format("{}{}", zerossg::ERROR_SESSION_NOT_FOUND_PREFIX, session_id));
    }
    
    m_sessions[session_id] = session;
    return make_result_success();
}

zerossg::Result<void> SessionManager::terminate_session(const zerossg::SessionId& session_id) {
    LockGuard<std::mutex> lock(m_sessions_mutex);
    
    if (m_sessions.erase(session_id) == 0) {
        return make_result_error(std::format("{}{}", zerossg::ERROR_SESSION_NOT_FOUND_PREFIX, session_id));
    }
    
    return make_result_success();
}

zerossg::Result<zerossg::Sessions> SessionManager::get_active_sessions() {
    LockGuard<std::mutex> lock(m_sessions_mutex);
    
    cleanup_expired_sessions_internal();
    
    zerossg::Sessions active_sessions;
    active_sessions.reserve(m_sessions.size());
    
    for (const auto& pair : m_sessions) {
        if (pair.second.is_active() && !pair.second.is_expired()) {
            active_sessions.push_back(pair.second);
        }
    }
    
    return make_result_success(std::move(active_sessions));
}

zerossg::Result<void> SessionManager::cleanup_expired_sessions() {
    LockGuard<std::mutex> lock(m_sessions_mutex);
    cleanup_expired_sessions_internal();
    return make_result_success();
}

size_t SessionManager::get_active_session_count() const {
    LockGuard<std::mutex> lock(m_sessions_mutex);
    
    size_t active_count = 0;
    auto now = std::chrono::system_clock::now();
    
    for (const auto& pair : m_sessions) {
        if (pair.second.is_active() && now <= pair.second.expires_at()) {
            active_count++;
        }
    }
    
    return active_count;
}

size_t SessionManager::get_total_session_count() const {
    return m_total_sessions.load();
}

zerossg::Result<void> SessionManager::extend_session(const zerossg::SessionId& session_id, Seconds additional_time) {
    LockGuard<std::mutex> lock(m_sessions_mutex);
    
    auto it = m_sessions.find(session_id);
    if (it == m_sessions.end()) {
        return make_result_error(std::format("{}{}", zerossg::ERROR_SESSION_NOT_FOUND_PREFIX, session_id));
    }
    
    zerossg::Session& session = it->second;
    
    // Check if session is still active
    if (!session.is_active() || session.is_expired()) {
        return make_result_error(std::format("{}{}", zerossg::ERROR_SESSION_NOT_ACTIVE_PREFIX, session_id));
    }
    
    // Extend session
    session.set_expires_at(session.expires_at() + additional_time);
    
    return make_result_success();
}

zerossg::Result<bool> SessionManager::is_session_valid(const zerossg::SessionId& session_id) {
    auto session_result = get_session(session_id);
    return session_result.has_value() ? make_result_success(true) : make_result_error<bool>(session_result.error());
}

zerossg::Result<zerossg::Sessions> SessionManager::get_sessions_by_user(const zerossg::UserName& username) {
    LockGuard<std::mutex> lock(m_sessions_mutex);
    
    cleanup_expired_sessions_internal();
    
    zerossg::Sessions user_sessions;
    
    for (const auto& pair : m_sessions) {
        if (pair.second.user_name() == username && pair.second.is_active()) {
            user_sessions.push_back(pair.second);
        }
    }
    
    return make_result_success(std::move(user_sessions));
}

zerossg::Result<zerossg::Sessions> SessionManager::get_sessions_by_service(const zerossg::ServiceName& service_name) {
    LockGuard<std::mutex> lock(m_sessions_mutex);
    
    cleanup_expired_sessions_internal();
    
    zerossg::Sessions service_sessions;
    
    for (const auto& pair : m_sessions) {
        if (pair.second.target_service() == service_name && pair.second.is_active()) {
            service_sessions.push_back(pair.second);
        }
    }
    
    return make_result_success(std::move(service_sessions));
}

zerossg::Result<zerossg::Sessions> SessionManager::get_sessions_by_ip(const zerossg::ClientIp& client_ip) {
    LockGuard<std::mutex> lock(m_sessions_mutex);
    
    cleanup_expired_sessions_internal();
    
    zerossg::Sessions ip_sessions;
    
    for (const auto& pair : m_sessions) {
        if (pair.second.client_ip() == client_ip && pair.second.is_active()) {
            ip_sessions.push_back(pair.second);
        }
    }
    
    return make_result_success(std::move(ip_sessions));
}

zerossg::SessionId SessionManager::generate_session_id() {
    std::uniform_int_distribution<> dis(0, 255);
    
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    
    for (size_t i = 0; i < zerossg::SESSION_ID_SIZE; ++i) {
        ss << std::setw(2) << dis(m_random_generator);
    }
    
    return ss.str();
}

bool SessionManager::is_user_at_session_limit(const zerossg::UserName& username) {
    size_t user_session_count = 0;
    auto now = std::chrono::system_clock::now();
    
    for (const auto& pair : m_sessions) {
        if (pair.second.user_name() == username && 
            pair.second.is_active() && 
            now <= pair.second.expires_at()) {
            user_session_count++;
            
            if (user_session_count >= zerossg::MAX_SESSIONS_PER_USER) {
                return true;
            }
        }
    }
    
    return false;
}

void SessionManager::cleanup_expired_sessions_internal() {
    auto now = std::chrono::system_clock::now();
    auto it = m_sessions.begin();
    
    while (it != m_sessions.end()) {
        if (now > it->second.expires_at()) {
            it = m_sessions.erase(it);
        } else {
            ++it;
        }
    }
}

zerossg::DurationString SessionManager::format_session_duration(const std::chrono::system_clock::time_point& start, 
                                                                const std::chrono::system_clock::time_point& end) {
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(end - start);
    
    if (duration.count() < 60) {
        return std::format("{}s", duration.count());
    } else if (duration.count() < 3600) {
        auto minutes = duration.count() / 60;
        auto seconds = duration.count() % 60;
        return std::format("{}m {}s", minutes, seconds);
    } else {
        auto hours = duration.count() / 3600;
        auto minutes = (duration.count() % 3600) / 60;
        return std::format("{}h {}m", hours, minutes);
    }
}

} // namespace zerossg
