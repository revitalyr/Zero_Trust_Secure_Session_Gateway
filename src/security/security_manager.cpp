module;
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

module zerossg.security.security_manager;

// Project headers
import zerossg.interfaces;
import zerossg.logging.logger;
import zerossg.std; // Includes <format>

namespace zerossg {

SecurityManager::SecurityManager() {
    m_logger = Logger::get("SecurityManager");
    // Start background cleanup thread
    m_cleanup_thread = std::thread(&SecurityManager::cleanup_worker, this);
}

SecurityManager::~SecurityManager() {
    m_running.store(false);
    if (m_cleanup_thread.joinable()) {
        m_cleanup_thread.join();
    }
}

Result<bool> SecurityManager::check_rate_limit(const string& client_ip) {
    LockGuard<std::mutex> lock(m_rate_limits_mutex);
    
    auto now = SystemClock::now();
    auto& info = m_rate_limits[client_ip];
    
    // Check if IP is currently blocked
    if (info.blocked && info.block_until.has_value() && now < info.block_until.value()) {
        record_security_event("rate_limit_blocked", std::format("IP {} blocked for exceeding rate limit", client_ip));
        return make_result_error<bool>("IP is currently blocked due to rate limiting");
    }
    
    // Reset window if needed
    if (now - info.window_start >= m_rate_limit_window) {
        info.request_count = 0;
        info.window_start = now;
        info.blocked = false;
        info.block_until.reset();
    }
    
    // Check rate limit
    if (info.request_count >= m_rate_limit_max_requests) {
        info.blocked = true;
        info.block_until = now + m_default_block_duration;
        
        record_security_event("rate_limit_exceeded", 
            std::format("IP {} exceeded rate limit: {} requests in {} seconds", 
                client_ip, info.request_count, m_rate_limit_window.count()));
        
        return make_result_error<bool>("Rate limit exceeded");
    }
    
    info.request_count++;
    return make_result_success(true);
}

Result<bool> SecurityManager::detect_brute_force(const zerossg::String& client_ip) {
    LockGuard<std::mutex> lock(m_brute_force_mutex);
    
    auto now = SystemClock::now();
    auto& info = m_brute_force_data[client_ip];
    
    // Check if brute force is already detected
    if (info.detected) {
        return make_result_success(true);
    }
    
    // Clean old attempts outside the window
    if (now - info.first_attempt > m_brute_force_window) {
        info.failed_attempts = 0;
        info.first_attempt = now;
    }
    
    // Check if threshold is exceeded
    if (info.failed_attempts >= m_brute_force_threshold) {
        info.detected = true;
        info.detection_time = now;
        
        m_total_brute_force_detections.fetch_add(1);
        
        record_security_event("brute_force_detected", 
            std::format("Brute force attack detected from IP {}: {} failed attempts in {} seconds",
                client_ip, info.failed_attempts, m_brute_force_window.count()));
        
        // Auto-block the IP
        block_ip(client_ip, m_default_block_duration);
        
        return make_result_success(true);
    }
    
    return make_result_success(false);
}

void SecurityManager::record_failed_attempt(const string& client_ip) {
    {
        LockGuard<std::mutex> lock(m_brute_force_mutex);
        auto& info = m_brute_force_data[client_ip];
        
        auto now = SystemClock::now();
        if (info.failed_attempts == 0) {
            info.first_attempt = now;
        }
        info.last_attempt = now;
        info.failed_attempts++;
    }
    
    m_total_failed_attempts.fetch_add(1);
    record_security_event("failed_attempt", std::format("Failed authentication attempt from IP {}", client_ip));
}

void SecurityManager::record_successful_login(const string& client_ip) {
    {
        LockGuard<std::mutex> lock(m_brute_force_mutex);
        // Reset failed attempts on successful login
        auto it = m_brute_force_data.find(client_ip);
        if (it != m_brute_force_data.end()) {
            it->second.failed_attempts = 0;
            it->second.detected = false;
        }
    }
    
    m_total_successful_logins.fetch_add(1);
    record_security_event("successful_login", std::format("Successful authentication from IP {}", client_ip));
}

Result<void> SecurityManager::block_ip(const string& client_ip, milliseconds duration) {
    LockGuard<std::mutex> lock(m_blocked_ips_mutex);
    
    auto block_until = SystemClock::now() + duration;
    m_blocked_ips[client_ip] = block_until;
    
    record_security_event("ip_blocked", 
        std::format("IP {} blocked for {} milliseconds", client_ip, duration.count()));
    
    return make_result_success();
}

bool SecurityManager::is_ip_blocked(const string& client_ip) {
    LockGuard<std::mutex> lock(m_blocked_ips_mutex);
    
    auto it = m_blocked_ips.find(client_ip);
    if (it == m_blocked_ips.end()) {
        return false;
    }
    
    // Check if block has expired
    if (SystemClock::now() > it->second) {
        m_blocked_ips.erase(it);
        return false;
    }
    
    return true;
}

size_t SecurityManager::get_blocked_ip_count() const {
    LockGuard<std::mutex> lock(m_blocked_ips_mutex);
    
    auto now = SystemClock::now();
    size_t count = 0;
    
    for (const auto& pair : m_blocked_ips) {
        if (now <= pair.second) {
            count++;
        }
    }
    
    return count;
}

size_t SecurityManager::get_brute_force_attempts() const {
    return m_total_failed_attempts.load();
}

vector<string> SecurityManager::get_blocked_ips() const {
    LockGuard<std::mutex> lock(m_blocked_ips_mutex);
    
    auto now = SystemClock::now();
    vector<string> blocked_ips;
    
    for (const auto& pair : m_blocked_ips) {
        if (now <= pair.second) {
            blocked_ips.push_back(pair.first);
        }
    }
    
    return blocked_ips;
}

void SecurityManager::cleanup_expired_data() {
    cleanup_rate_limits();
    cleanup_brute_force_data();
    cleanup_blocked_ips();
    cleanup_security_events();
}

void SecurityManager::cleanup_worker() {
    while (m_running.load()) {
        try {
            std::this_thread::sleep_for(std::chrono::minutes(5));
            cleanup_expired_data();
        } catch (const std::exception& e) {
            m_logger->error(std::format("Security cleanup worker error: {}", e.what()));
        }
    }
}

void SecurityManager::cleanup_rate_limits() {
    LockGuard<std::mutex> lock(m_rate_limits_mutex);
    
    auto now = SystemClock::now();
    auto it = m_rate_limits.begin();
    
    while (it != m_rate_limits.end()) {
        auto& info = it->second;
        
        // Remove expired blocks
        if (info.blocked && info.block_until.has_value() && now >= info.block_until.value()) {
            info.blocked = false;
            info.request_count = 0;
            info.window_start = now;
            info.block_until.reset();
        }
        
        // Remove entries that haven't been used recently
        if (now - info.window_start > m_rate_limit_window * 2 && info.request_count == 0) {
            it = m_rate_limits.erase(it);
        } else {
            ++it;
        }
    }
}

void SecurityManager::cleanup_brute_force_data() {
    LockGuard<std::mutex> lock(m_brute_force_mutex);
    
    auto now = SystemClock::now();
    auto it = m_brute_force_data.begin();
    
    while (it != m_brute_force_data.end()) {
        auto& info = it->second;
        
        // Remove old entries
        if (now - info.last_attempt > m_brute_force_window * 2) {
            it = m_brute_force_data.erase(it);
        } else {
            ++it;
        }
    }
}

void SecurityManager::cleanup_blocked_ips() {
    LockGuard<std::mutex> lock(m_blocked_ips_mutex);
    
    auto now = SystemClock::now();
    auto it = m_blocked_ips.begin();
    
    while (it != m_blocked_ips.end()) {
        if (now > it->second) {
            it = m_blocked_ips.erase(it);
        } else {
            ++it;
        }
    }
}

void SecurityManager::cleanup_security_events() {
    LockGuard<std::mutex> lock(m_events_mutex);
    
    // Keep only recent events
    while (m_security_events.size() > MAX_SECURITY_EVENTS) {
        m_security_events.pop();
    }
}

void SecurityManager::record_security_event(const string& event_type, const string& details) {
    LockGuard<std::mutex> lock(m_events_mutex);
    
    m_security_events.emplace(event_type, details);
    
    m_logger->warn(std::format("[SECURITY] {}: {}", event_type, details));
}

} // namespace zerossg
