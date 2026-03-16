export module zerossg.security.security_manager;

export import zerossg.interfaces;
export import zerossg.std;

export namespace zerossg {

export class SecurityManager : public ISecurityManager {
public:
    SecurityManager();
    ~SecurityManager();

    Result<bool> check_rate_limit(const ClientIp& client_ip) override;
    Result<bool> detect_brute_force(const ClientIp& client_ip) override;
    void record_failed_attempt(const ClientIp& client_ip) override;
    void record_successful_login(const ClientIp& client_ip) override;
    Result<void> block_ip(const ClientIp& client_ip, Milliseconds duration) override;
    bool is_ip_blocked(const ClientIp& client_ip) override;

    // Additional methods for monitoring
    size_t get_blocked_ip_count() const;
    size_t get_brute_force_attempts() const;
    std::vector<String> get_blocked_ips() const;

private:
    struct RateLimitInfo {
        size_t request_count = 0;
        TimePoint window_start = SystemClock::now();
        TimePoint block_until = TimePoint::max();
        bool blocked = false;
    };

    struct BruteForceInfo {
        size_t failed_attempts = 0;
        TimePoint first_attempt = SystemClock::now();
        TimePoint last_attempt = SystemClock::now();
        TimePoint detection_time = TimePoint::max();
        bool detected = false;
    };

    struct SecurityEvent {
        String event_type;
        String details;
        TimePoint timestamp = SystemClock::now();
    };

    void cleanup_expired_data();
    void cleanup_worker();
    void cleanup_rate_limits();
    void cleanup_brute_force_data();
    void cleanup_blocked_ips();
    void cleanup_security_events();
    void record_security_event(const String& event_type, const String& details);

    bool is_rate_limited(const String& client_ip, RateLimitInfo& info);
    bool is_brute_force_detected(const String& client_ip, BruteForceInfo& info);

    mutable std::mutex m_rate_limits_mutex;
    mutable std::mutex m_brute_force_mutex;
    mutable std::mutex m_blocked_ips_mutex;
    mutable std::mutex m_events_mutex;

    std::unordered_map<String, RateLimitInfo> m_rate_limits;
    std::unordered_map<String, BruteForceInfo> m_brute_force_data;
    std::unordered_map<String, TimePoint> m_blocked_ips;
    std::queue<SecurityEvent> m_security_events;

    std::atomic<size_t> m_total_failed_attempts{0};
    std::atomic<size_t> m_total_successful_logins{0};
    std::atomic<size_t> m_total_brute_force_detections{0};

    std::thread m_cleanup_thread;
    std::atomic<bool> m_running{true};

    // Configuration
    static constexpr size_t m_rate_limit_max_requests = 100;
    static constexpr std::chrono::seconds m_rate_limit_window{300}; // 5 minutes
    static constexpr size_t m_brute_force_threshold = 5;
    static constexpr std::chrono::seconds m_brute_force_window{900}; // 15 minutes
    static constexpr std::chrono::milliseconds m_default_block_duration{3600000}; // 1 hour
    static constexpr size_t MAX_SECURITY_EVENTS = 10000;
};

} // namespace zerossg
