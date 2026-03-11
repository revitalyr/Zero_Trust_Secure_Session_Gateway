#pragma once

#include "zerossg/interfaces.hpp"
#include <unordered_map>
#include <mutex>
#include <chrono>
#include <queue>
#include <thread>
#include <atomic>

namespace zerossg {

struct SecurityEventRecord {
    system_clock::time_point timestamp;
    string event_type;
    string details;
    
    SecurityEventRecord(const string& type, const string& det)
        : timestamp(system_clock::now())
        , event_type(type)
        , details(det)
    {}
};

struct RateLimitInfo {
    size_t request_count{0};
    system_clock::time_point window_start{system_clock::now()};
    bool blocked{false};
    system_clock::time_point block_until{system_clock::time_point{}};
};

struct BruteForceInfo {
    size_t failed_attempts{0};
    system_clock::time_point first_attempt{system_clock::now()};
    system_clock::time_point last_attempt{system_clock::now()};
    bool detected{false};
    system_clock::time_point detection_time{system_clock::time_point{}};
};

class SecurityManager : public ISecurityManager {
public:
    SecurityManager();
    ~SecurityManager() override;
    
    // ISecurityManager interface
    Result<bool> check_rate_limit(const string& client_ip) override;
    Result<bool> detect_brute_force(const string& client_ip) override;
    void record_failed_attempt(const string& client_ip) override;
    void record_successful_login(const string& client_ip) override;
    Result<void> block_ip(const string& client_ip, milliseconds duration) override;
    bool is_ip_blocked(const string& client_ip) override;
    
    // Security statistics
    size_t get_blocked_ip_count() const;
    size_t get_brute_force_attempts() const;
    vector<string> get_blocked_ips() const;
    
    // Configuration
    void set_rate_limit_window(seconds window) { m_rate_limit_window = window; }
    void set_rate_limit_max_requests(size_t max_requests) { m_rate_limit_max_requests = max_requests; }
    void set_brute_force_threshold(size_t threshold) { m_brute_force_threshold = threshold; }
    void set_brute_force_window(seconds window) { m_brute_force_window = window; }
    void set_default_block_duration(milliseconds duration) { m_default_block_duration = duration; }
    
    // Cleanup and maintenance
    void cleanup_expired_data();
    
private:
    // Rate limiting
    unordered_map<string, RateLimitInfo> m_rate_limits;
    mutable std::mutex m_rate_limits_mutex;
    
    // Brute force detection
    unordered_map<string, BruteForceInfo> m_brute_force_data;
    mutable std::mutex m_brute_force_mutex;
    
    // IP blocking
    unordered_map<string, system_clock::time_point> m_blocked_ips;
    mutable std::mutex m_blocked_ips_mutex;
    
    // Security events
    std::queue<SecurityEventRecord> m_security_events;
    mutable std::mutex m_events_mutex;
    static constexpr size_t MAX_SECURITY_EVENTS = 10000;
    
    // Statistics
    std::atomic<size_t> m_total_failed_attempts{0};
    std::atomic<size_t> m_total_successful_logins{0};
    std::atomic<size_t> m_total_brute_force_detections{0};
    
    // Configuration
    seconds m_rate_limit_window{300}; // 5 minutes
    size_t m_rate_limit_max_requests{100}; // 100 requests per window
    size_t m_brute_force_threshold{5}; // 5 failed attempts
    seconds m_brute_force_window{900}; // 15 minutes
    milliseconds m_default_block_duration{3600000}; // 1 hour
    
    // Background cleanup thread
    std::thread m_cleanup_thread;
    std::atomic<bool> m_running{true};
    
    // Helper methods
    void cleanup_worker();
    void cleanup_rate_limits();
    void cleanup_brute_force_data();
    void cleanup_blocked_ips();
    void cleanup_security_events();
    
    void record_security_event(const string& event_type, const string& details);
    bool is_rate_limited(const string& client_ip, RateLimitInfo& info);
    bool is_brute_force_detected(const string& client_ip, BruteForceInfo& info);
};

} // namespace zerossg
