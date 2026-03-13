// Project headers
import zerossg.interfaces;
import zerossg.logging.logger;
#include <algorithm>
#include <iostream>

namespace zerossg {

SecurityManager::SecurityManager() {
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
    std::lock_guard<std::mutex> lock(m_rate_limits_mutex);
    
    auto now = system_clock::now();
    auto& info = m_rate_limits[client_ip];
    
    // Check if IP is currently blocked
    if (info.blocked && now < info.block_until) {
        record_security_event("rate_limit_blocked", "IP " + client_ip + " blocked for exceeding rate limit");
        return Result<bool>::success(false);
    }
    
    // Reset window if needed
    if (now - info.window_start >= m_rate_limit_window) {
        info.request_count = 0;
        info.window_start = now;
        info.blocked = false;
    }
    
    // Check rate limit
    if (info.request_count >= m_rate_limit_max_requests) {
        info.blocked = true;
        info.block_until = now + m_default_block_duration;
        
        record_security_event("rate_limit_exceeded", 
            "IP " + client_ip + " exceeded rate limit: " + 
            std::to_string(info.request_count) + " requests in " +
            std::to_string(m_rate_limit_window.count()) + " seconds");
        
        return Result<bool>::success(false);
    }
    
    info.request_count++;
    return Result<bool>::success(true);
}

Result<bool> SecurityManager::detect_brute_force(const zerossg::String& client_ip) {
    std::lock_guard<std::mutex> lock(m_brute_force_mutex);
    
    auto now = system_clock::now();
    auto& info = m_brute_force_data[client_ip];
    
    // Check if brute force is already detected
    if (info.detected) {
        return Result<bool>::success(true);
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
            "Brute force attack detected from IP " + client_ip + ": " +
            std::to_string(info.failed_attempts) + " failed attempts in " +
            std::to_string(m_brute_force_window.count()) + " seconds");
        
        // Auto-block the IP
        block_ip(client_ip, m_default_block_duration);
        
        return Result<bool>::success(true);
    }
    
    return Result<bool>::success(false);
}

void SecurityManager::record_failed_attempt(const string& client_ip) {
    {
        std::lock_guard<std::mutex> lock(m_brute_force_mutex);
        auto& info = m_brute_force_data[client_ip];
        
        auto now = system_clock::now();
        if (info.failed_attempts == 0) {
            info.first_attempt = now;
        }
        info.last_attempt = now;
        info.failed_attempts++;
    }
    
    m_total_failed_attempts.fetch_add(1);
    record_security_event("failed_attempt", "Failed authentication attempt from IP " + client_ip);
}

void SecurityManager::record_successful_login(const string& client_ip) {
    {
        std::lock_guard<std::mutex> lock(m_brute_force_mutex);
        // Reset failed attempts on successful login
        auto it = m_brute_force_data.find(client_ip);
        if (it != m_brute_force_data.end()) {
            it->second.failed_attempts = 0;
            it->second.detected = false;
        }
    }
    
    m_total_successful_logins.fetch_add(1);
    record_security_event("successful_login", "Successful authentication from IP " + client_ip);
}

Result<void> SecurityManager::block_ip(const string& client_ip, milliseconds duration) {
    std::lock_guard<std::mutex> lock(m_blocked_ips_mutex);
    
    auto block_until = system_clock::now() + duration;
    m_blocked_ips[client_ip] = block_until;
    
    record_security_event("ip_blocked", 
        "IP " + client_ip + " blocked for " + std::to_string(duration.count()) + " milliseconds");
    
    return Result<void>::success();
}

bool SecurityManager::is_ip_blocked(const string& client_ip) {
    std::lock_guard<std::mutex> lock(m_blocked_ips_mutex);
    
    auto it = m_blocked_ips.find(client_ip);
    if (it == m_blocked_ips.end()) {
        return false;
    }
    
    // Check if block has expired
    if (system_clock::now() > it->second) {
        m_blocked_ips.erase(it);
        return false;
    }
    
    return true;
}

size_t SecurityManager::get_blocked_ip_count() const {
    std::lock_guard<std::mutex> lock(m_blocked_ips_mutex);
    
    auto now = system_clock::now();
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
    std::lock_guard<std::mutex> lock(m_blocked_ips_mutex);
    
    auto now = system_clock::now();
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
            std::cerr << "Security cleanup worker error: " << e.what() << std::endl;
        }
    }
}

void SecurityManager::cleanup_rate_limits() {
    std::lock_guard<std::mutex> lock(m_rate_limits_mutex);
    
    auto now = system_clock::now();
    auto it = m_rate_limits.begin();
    
    while (it != m_rate_limits.end()) {
        auto& info = it->second;
        
        // Remove expired blocks
        if (info.blocked && now >= info.block_until) {
            info.blocked = false;
            info.request_count = 0;
            info.window_start = now;
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
    std::lock_guard<std::mutex> lock(m_brute_force_mutex);
    
    auto now = system_clock::now();
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
    std::lock_guard<std::mutex> lock(m_blocked_ips_mutex);
    
    auto now = system_clock::now();
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
    std::lock_guard<std::mutex> lock(m_events_mutex);
    
    // Keep only recent events
    while (m_security_events.size() > MAX_SECURITY_EVENTS) {
        m_security_events.pop();
    }
}

void SecurityManager::record_security_event(const string& event_type, const string& details) {
    std::lock_guard<std::mutex> lock(m_events_mutex);
    
    m_security_events.emplace(event_type, details);
    
    // Log to console (in production, use proper logging)
    auto now = system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    
    std::cout << "[SECURITY] " << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S")
              << " - " << event_type << ": " << details << std::endl;
}

bool SecurityManager::is_rate_limited(const string& client_ip, RateLimitInfo& info) {
    auto now = system_clock::now();
    
    // Check if currently blocked
    if (info.blocked && now < info.block_until) {
        return true;
    }
    
    // Reset window if needed
    if (now - info.window_start >= m_rate_limit_window) {
        info.request_count = 0;
        info.window_start = now;
        info.blocked = false;
    }
    
    // Check rate limit
    if (info.request_count >= m_rate_limit_max_requests) {
        info.blocked = true;
        info.block_until = now + m_default_block_duration;
        return true;
    }
    
    info.request_count++;
    return false;
}

bool SecurityManager::is_brute_force_detected(const string& client_ip, BruteForceInfo& info) {
    auto now = system_clock::now();
    
    // Clean old attempts outside the window
    if (now - info.first_attempt > m_brute_force_window) {
        info.failed_attempts = 0;
        info.first_attempt = now;
    }
    
    // Check if threshold is exceeded
    if (info.failed_attempts >= m_brute_force_threshold) {
        info.detected = true;
        info.detection_time = now;
        return true;
    }
    
    return false;
}

} // namespace zerossg
