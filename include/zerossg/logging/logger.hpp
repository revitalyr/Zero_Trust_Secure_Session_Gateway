#pragma once

// C++23 module imports
import zerossg.common;
import zerossg.interfaces;
import zerossg.constants;

// Third-party library imports
import <spdlog/spdlog.h>;
import <spdlog/sinks/stdout_color_sinks.h>;
import <spdlog/sinks/rotating_file_sink.h>;
import <spdlog/sinks/daily_file_sink.h>;

// Standard library imports
import zerossg.std;

namespace zerossg {

// Import semantic aliases for type visibility
using zerossg::String;
using zerossg::SessionId;
using zerossg::UserName;
using zerossg::ClientIp;
using zerossg::FileName;
using zerossg::SecurityEvent;

// Import standard library types for clarity
using std::mutex;
using std::string;
using std::lock_guard;
using std::pair;
using std::unordered_map;
using std::vector;

// Import zerossg SharedPtr
using zerossg::SharedPtr;

// Import SecurityEvent type
using zerossg::SecurityEvent;

// Import spdlog types for module compatibility
using spdlog::logger;
using spdlog::level::level_enum;

enum class LogLevel {
    TRACE = 0,
    DEBUG = 1,
    INFO = 2,
    WARN = 3,
    ERROR = 4,
    CRITICAL = 5
};

// Modern Logger class with structured logging support
class Logger {
public:
    explicit Logger(String name = "zerossg");
    ~Logger();
    
    // Core logging methods with semantic types
    void trace(const String& message);
    void debug(const String& message);
    void info(const String& message);
    void warn(const String& message);
    void error(const String& message);
    void critical(const String& message);
    
    // Structured logging with semantic types
    void log_user_action(const UserName& username, const String& action, const ClientIp& client_ip = "");
    void log_session_start(const SessionId& session_id, const UserName& username, const ClientIp& client_ip);
    void log_session_end(const SessionId& session_id, const String& reason = "");
    void log_session_termination(const SessionId& session_id, const String& reason = "");
    void log_access_denied(const UserName& username, const ClientIp& client_ip, const String& resource, const String& reason = "");
    void log_security_violation(const ClientIp& client_ip, const String& violation_type, const String& details = "");
    
    // Performance logging
    void log_performance_metric(const String& operation, double duration_ms, const String& unit = "ms");
    void log_connection_stats(size_t active_connections, size_t total_connections);
    void log_throughput(size_t bytes_transferred, const String& direction = "total");
    
    // Static factory methods
    static SharedPtr<Logger> create(const String& name = "zerossg");
    static SharedPtr<Logger> create_with_file_output(const String& name, const FileName& log_file);
    static SharedPtr<Logger> create_security_logger();
    static SharedPtr<Logger> create_audit_logger();
    
private:
    SharedPtr<spdlog::logger> m_logger;
    mutable mutex m_mutex;
    
    // Helper methods
    spdlog::level::level_enum convert_log_level(LogLevel level) const;
    String format_timestamp() const;
    String format_security_event(const SecurityEvent& event) const;
    
    // Field formatting for structured logging
    String format_fields(const vector<pair<String, String>>& fields) const;
    
    // Initialize default sinks
    void initialize_default_sinks();
};

// Global logger instance management
class LoggerManager {
public:
    static LoggerManager& instance();
    
    SharedPtr<Logger> get_logger(const String& name = "default");
    void set_default_level(LogLevel level);
    void add_file_sink(const FileName& filename, size_t max_size = 1048576, size_t max_files = 3);
    void add_console_sink();
    
private:
    LoggerManager() = default;
    ~LoggerManager() = default;
    
    unordered_map<String, SharedPtr<Logger>> m_loggers;
    mutable mutex m_mutex;
    LogLevel m_default_level = LogLevel::INFO;
};

// Convenience functions for global logging
inline void log_info(const String& message) {
    LoggerManager::instance().get_logger()->info(message);
}

inline void log_error(const String& message) {
    LoggerManager::instance().get_logger()->error(message);
}

inline void log_debug(const String& message) {
    LoggerManager::instance().get_logger()->debug(message);
}

inline void log_warn(const String& message) {
    LoggerManager::instance().get_logger()->warn(message);
}

} // namespace zerossg
