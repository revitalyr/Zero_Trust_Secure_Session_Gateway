#pragma once

#include "zerossg/interfaces.hpp"
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/daily_file_sink.h>
#include <memory>
#include <mutex>
#include <string>

namespace zerossg {

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
    explicit Logger(const string& name);
    ~Logger() override = default;
    
    // ILogger interface
    void log_security_event(const SecurityEvent& event) override;
    void log_session_event(const string& session_id, const string& event_type, const string& details) override;
    void log_error(const string& component, const string& error) override;
    void log_info(const string& component, const string& message) override;
    void log_debug(const string& component, const string& message) override;
    
    // Configuration
    void set_level(LogLevel level);
    void set_pattern(const string& pattern);
    void add_file_sink(const string& filename, size_t max_file_size = 1024 * 1024 * 5, size_t max_files = 3);
    void add_daily_file_sink(const string& filename, int hour = 0, int minute = 0);
    void enable_console_output(bool enable = true);
    
    // Structured logging helpers
    template<typename... Args>
    void log_structured(LogLevel level, const string& component, const string& message, Args&&... args);
    
    void log_with_fields(LogLevel level, const string& component, const string& message,
                         const std::vector<std::pair<string, string>>& fields);
    
    // Audit logging
    void log_authentication_attempt(const string& username, const string& client_ip, bool success, const string& reason = "");
    void log_session_creation(const string& session_id, const string& username, const string& client_ip, const string& target_service);
    void log_session_termination(const string& session_id, const string& reason = "");
    void log_access_denied(const string& username, const string& client_ip, const string& resource, const string& reason = "");
    void log_security_violation(const string& client_ip, const string& violation_type, const string& details = "");
    
    // Performance logging
    void log_performance_metric(const string& operation, double duration_ms, const string& unit = "ms");
    void log_connection_stats(size_t active_connections, size_t total_connections);
    void log_throughput(size_t bytes_transferred, const string& direction = "total");
    
    // Static factory methods
    static std::shared_ptr<Logger> create(const string& name = "zerossg");
    static std::shared_ptr<Logger> create_with_file_output(const string& name, const string& log_file);
    static std::shared_ptr<Logger> create_security_logger();
    static std::shared_ptr<Logger> create_audit_logger();
    
private:
    std::shared_ptr<spdlog::logger> m_logger;
    mutable std::mutex m_mutex;
    
    // Helper methods
    spdlog::level::level_enum convert_log_level(LogLevel level) const;
    string format_timestamp() const;
    string format_security_event(const SecurityEvent& event) const;
    
    // Field formatting for structured logging
    string format_fields(const std::vector<std::pair<string, string>>& fields) const;
    
    // Initialize default sinks
    void initialize_default_sinks();
};

// Global logger instance management
class LoggerManager {
public:
    static LoggerManager& instance();
    
    std::shared_ptr<Logger> get_logger(const string& name = "default");
    void set_global_logger(std::shared_ptr<Logger> logger);
    
    // Convenience methods for global logging
    void info(const string& message);
    void error(const string& message);
    void warn(const string& message);
    void debug(const string& message);
    
private:
    LoggerManager() = default;
    std::unordered_map<string, std::shared_ptr<Logger>> m_loggers;
    std::shared_ptr<Logger> m_global_logger;
    mutable std::mutex m_mutex;
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
