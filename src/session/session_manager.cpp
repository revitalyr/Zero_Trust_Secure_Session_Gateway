// C++23 module imports
import zerossg.session.session_manager;
import zerossg.constants;

// Standard library imports
import zerossg.std;

namespace zerossg {
    // Import std utilities
    using std::lock_guard;
    using std::mutex;
    using std::string;
    using std::chrono::system_clock;
    using std::chrono::seconds;
    using std::make_shared;
    using std::move;
    using std::remove_if;
    
    // Import constants for string literals
using zerossg::ERROR_MAXIMUM_SESSION_LIMIT;
using zerossg::ERROR_SESSION_NOT_FOUND_PREFIX;
using zerossg::ERROR_SESSION_EXPIRED_PREFIX;
using zerossg::ERROR_SESSION_NOT_ACTIVE_PREFIX;
using zerossg::TIME_FORMAT_SECONDS_SUFFIX;
using zerossg::TIME_FORMAT_MINUTES_SUFFIX;
using zerossg::TIME_FORMAT_HOURS_SUFFIX;

SessionManager::SessionManager() : m_random_generator(m_random_device()) {
}

Result<SessionId> SessionManager::create_session(const User& user, const ClientIp& client_ip, const ServiceName& target_service) {
    std::lock_guard<std::mutex> lock(m_sessions_mutex);
    
    // Check if user has reached session limit
    if (is_user_at_session_limit(user.m_user_name)) {
        return Result<SessionId>::error(ERROR_MAXIMUM_SESSION_LIMIT + std::string(user.m_user_name));
    }
    
    // Generate unique session ID
    SessionId session_id = generate_session_id();
    
    // Check for collision (very unlikely, but handle it)
    while (m_sessions.find(session_id) != m_sessions.end()) {
        session_id = generate_session_id();
    }
    
    // Create session
    Session session(session_id, user.m_user_name, user.m_role, client_ip, target_service);
    session.m_expires_at = std::chrono::system_clock::now() + DEFAULT_SESSION_TIMEOUT;
    
    // Store session
    m_sessions[session_id] = session;
    m_total_sessions.fetch_add(1);
    
    return Result<SessionId>::success(session_id);
}

Result<Session> SessionManager::get_session(const SessionId& session_id) {
    std::lock_guard<std::mutex> lock(m_sessions_mutex);
    
    auto it = m_sessions.find(session_id);
    if (it == m_sessions.end()) {
        return Result<Session>::error(ERROR_SESSION_NOT_FOUND_PREFIX + session_id);
    }
    
    const Session& session = it->second;
    
    // Check if session has expired
    if (std::chrono::system_clock::now() > session.m_expires_at) {
        // Remove expired session
        m_sessions.erase(it);
        return Result<Session>::error(ERROR_SESSION_EXPIRED_PREFIX + session_id);
    }
    
    return Result<Session>::success(session);
}

Result<void> SessionManager::update_session(const SessionId& session_id, const Session& session) {
    std::lock_guard<std::mutex> lock(m_sessions_mutex);
    
    auto it = m_sessions.find(session_id);
    if (it == m_sessions.end()) {
        return Result<void>::error(ERROR_SESSION_NOT_FOUND_PREFIX + session_id);
    }
    
    m_sessions[session_id] = session;
    return Result<void>::success();
}

Result<void> SessionManager::terminate_session(const string& session_id) {
    std::lock_guard<std::mutex> lock(m_sessions_mutex);
    
    if (m_sessions.erase(session_id) == 0) {
        return Result<void>::error(ERROR_SESSION_NOT_FOUND_PREFIX + session_id);
    }
    
    return Result<void>::success();
}

Result<vector<Session>> SessionManager::get_active_sessions() {
    std::lock_guard<std::mutex> lock(m_sessions_mutex);
    
    cleanup_expired_sessions_internal();
    
    vector<Session> active_sessions;
    active_sessions.reserve(m_sessions.size());
    
    for (const auto& pair : m_sessions) {
        if (pair.second.active && system_clock::now() <= pair.second.expires_at) {
            active_sessions.push_back(pair.second);
        }
    }
    
    return Result<vector<Session>>::success(std::move(active_sessions));
}

Result<void> SessionManager::cleanup_expired_sessions() {
    std::lock_guard<std::mutex> lock(m_sessions_mutex);
    cleanup_expired_sessions_internal();
    return Result<void>::success();
}

size_t SessionManager::get_active_session_count() const {
    std::lock_guard<std::mutex> lock(m_sessions_mutex);
    
    size_t active_count = 0;
    auto now = system_clock::now();
    
    for (const auto& pair : m_sessions) {
        if (pair.second.active && now <= pair.second.expires_at) {
            active_count++;
        }
    }
    
    return active_count;
}

size_t SessionManager::get_total_session_count() const {
    return m_total_sessions.load();
}

Result<void> SessionManager::extend_session(const string& session_id, seconds additional_time) {
    std::lock_guard<std::mutex> lock(m_sessions_mutex);
    
    auto it = m_sessions.find(session_id);
    if (it == m_sessions.end()) {
        return Result<void>::error(ERROR_SESSION_NOT_FOUND_PREFIX + session_id);
    }
    
    Session& session = it->second;
    
    // Check if session is still active
    if (!session.active || system_clock::now() > session.expires_at) {
        return Result<void>::error(ERROR_SESSION_NOT_ACTIVE_PREFIX + session_id);
    }
    
    // Extend session
    session.expires_at += additional_time;
    
    return Result<void>::success();
}

Result<bool> SessionManager::is_session_valid(const string& session_id) {
    auto session_result = get_session(session_id);
    return session_result.is_success() ? Result<bool>::success(true) : Result<bool>::error(session_result.error());
}

Result<vector<Session>> SessionManager::get_sessions_by_user(const string& username) {
    std::lock_guard<std::mutex> lock(m_sessions_mutex);
    
    cleanup_expired_sessions_internal();
    
    vector<Session> user_sessions;
    
    for (const auto& pair : m_sessions) {
        if (pair.second.username == username && pair.second.active) {
            user_sessions.push_back(pair.second);
        }
    }
    
    return Result<vector<Session>>::success(std::move(user_sessions));
}

Result<vector<Session>> SessionManager::get_sessions_by_service(const string& service_name) {
    std::lock_guard<std::mutex> lock(m_sessions_mutex);
    
    cleanup_expired_sessions_internal();
    
    vector<Session> service_sessions;
    
    for (const auto& pair : m_sessions) {
        if (pair.second.target_service == service_name && pair.second.active) {
            service_sessions.push_back(pair.second);
        }
    }
    
    return Result<vector<Session>>::success(std::move(service_sessions));
}

Result<vector<Session>> SessionManager::get_sessions_by_ip(const string& client_ip) {
    std::lock_guard<std::mutex> lock(m_sessions_mutex);
    
    cleanup_expired_sessions_internal();
    
    vector<Session> ip_sessions;
    
    for (const auto& pair : m_sessions) {
        if (pair.second.client_ip == client_ip && pair.second.active) {
            ip_sessions.push_back(pair.second);
        }
    }
    
    return Result<vector<Session>>::success(std::move(ip_sessions));
}

string SessionManager::generate_session_id() {
    std::uniform_int_distribution<> dis(0, 255);
    
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    
    for (size_t i = 0; i < SESSION_ID_SIZE; ++i) {
        ss << std::setw(2) << dis(m_random_generator);
    }
    
    return ss.str();
}

bool SessionManager::is_user_at_session_limit(const string& username) {
    size_t user_session_count = 0;
    auto now = system_clock::now();
    
    for (const auto& pair : m_sessions) {
        if (pair.second.username == username && 
            pair.second.active && 
            now <= pair.second.expires_at) {
            user_session_count++;
            
            if (user_session_count >= MAX_SESSIONS_PER_USER) {
                return true;
            }
        }
    }
    
    return false;
}

void SessionManager::cleanup_expired_sessions_internal() {
    auto now = system_clock::now();
    auto it = m_sessions.begin();
    
    while (it != m_sessions.end()) {
        if (now > it->second.expires_at) {
            it = m_sessions.erase(it);
        } else {
            ++it;
        }
    }
}

string SessionManager::format_session_duration(const system_clock::time_point& start, 
                                               const system_clock::time_point& end) {
    auto duration = std::chrono::duration_cast<seconds>(end - start);
    
    if (duration.count() < 60) {
        return std::to_string(duration.count()) + TIME_FORMAT_SECONDS_SUFFIX;
    } else if (duration.count() < 3600) {
        auto minutes = duration.count() / 60;
        auto seconds = duration.count() % 60;
        return std::to_string(minutes) + TIME_FORMAT_MINUTES_SUFFIX + std::to_string(seconds) + TIME_FORMAT_SECONDS_SUFFIX;
    } else {
        auto hours = duration.count() / 3600;
        auto minutes = (duration.count() % 3600) / 60;
        return std::to_string(hours) + TIME_FORMAT_HOURS_SUFFIX + std::to_string(minutes) + TIME_FORMAT_MINUTES_SUFFIX;
    }
}

} // namespace zerossg
