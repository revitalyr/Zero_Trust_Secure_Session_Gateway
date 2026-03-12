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
using zerossg::Vector;
using zerossg::SessionId;
using zerossg::UserName;
using zerossg::ClientIp;
using zerossg::FileName;
using zerossg::SecurityEvent;

// Import standard library types for clarity
using std::shared_ptr;
using std::mutex;
using std::string;
using std::lock_guard;

// Import spdlog types for module compatibility
// Using spdlog::logger and spdlog::level::level_enum directly

// Import standard library types for module compatibility
using std::shared_ptr;
using std::pair;
using std::mutex;
using std::unordered_map;

// Import additional types from common module
using zerossg::shared_ptr;

enum class LogLevel {
    TRACE = 0,
    DEBUG = 1,
    INFO = 2,
    WARN = 3,
    ERROR = 4,
    CRITICAL = 5
};

class Logger : public ILogger {
public:
    Logger();
    explicit Logger(const String& name);
    ~Logger() = default;
    
    // ILogger interface
    void log_security_event(const SecurityEvent& event);
    void log_session_event(const SessionId& session_id, const String& event_type, const String& details);
    void log_error(const String& component, const ErrorMessage& error);
    void log_info(const String& component, const String& message);
    void log_debug(const String& component, const String& message);
    
    // Configuration
    void set_level(LogLevel level);
    void set_pattern(const String& pattern);
    void add_file_sink(const FileName& filename, size_t max_file_size = 1024 * 1024 * 5, size_t max_files = 3);
    void add_daily_file_sink(const FileName& filename, int hour = 0, int minute = 0);
    void enable_console_output(bool enable = true);
    
    // Structured logging helpers
    template<typename... Args>
    void log_structured(LogLevel level, const String& component, const String& message, Args&&... args);
    
    void log_with_fields(LogLevel level, const String& component, const String& message,
                         const Vector<std::pair<String, String>>& fields);
    
    // Audit logging
    void log_authentication_attempt(const UserName& username, const ClientIp& client_ip, bool success, const String& reason = "");
    void log_session_creation(const SessionId& session_id, const UserName& username, const ClientIp& client_ip, const ServiceName& target_service);
    void log_session_termination(const SessionId& session_id, const String& reason = "");
    void log_access_denied(const UserName& username, const ClientIp& client_ip, const String& resource, const String& reason = "");
    void log_security_violation(const ClientIp& client_ip, const String& violation_type, const String& details = "");
    
    // Performance logging
    void log_performance_metric(const String& operation, double duration_ms, const String& unit = "ms");
    void log_connection_stats(size_t active_connections, size_t total_connections);
    void log_throughput(size_t bytes_transferred, const String& direction = "total");
    
    // Static factory methods
    static shared_ptr<Logger> create(const String& name = "zerossg");
    static shared_ptr<Logger> create_with_file_output(const String& name, const FileName& log_file);
    static shared_ptr<Logger> create_security_logger();
    static shared_ptr<Logger> create_audit_logger();
    
private:
    shared_ptr<spdlog::logger> m_logger;
    mutable mutex m_mutex;
    
    // Helper methods
    spdlog::level::level_enum convert_log_level(LogLevel level) const;
    String format_timestamp() const;
    String format_security_event(const SecurityEvent& event) const;
    
    // Field formatting for structured logging
    String format_fields(const Vector<pair<String, String>>& fields) const;
    
    // Initialize default sinks
    void initialize_default_sinks();
};

// Global logger instance management
class LoggerManager {
public:
    static LoggerManager& instance();
    
    shared_ptr<Logger> get_logger(const String& name = "default");
    void set_global_logger(shared_ptr<Logger> logger);
    
    // Convenience methods for global logging
    void info(const String& message);
    void error(const String& message);
    void warn(const String& message);
    void debug(const String& message);
    
private:
    LoggerManager() = default;
    unordered_map<String, shared_ptr<Logger>> m_loggers;
    shared_ptr<Logger> m_global_logger;
    mutable mutex m_mutex;
};

// Convenience macros for logging
#define LOG_INFO(component, message) \
    zerossg::LoggerManager::instance().get_logger()->log_info(component, message)

#define LOG_ERROR(component, message) \
    zerossg::LoggerManager::instance().get_logger()->log_error(component, message)

#define LOG_DEBUG(component, message) \
    zerossg::LoggerManager::instance().get_logger()->log_debug(component, message)

#define LOG_SECURITY_EVENT(event) \
    zerossg::LoggerManager::instance().get_logger()->log_security_event(event)

#define LOG_SESSION_EVENT(session_id, event_type, details) \
    zerossg::LoggerManager::instance().get_logger()->log_session_event(session_id, event_type, details)

} // namespace zerossg
