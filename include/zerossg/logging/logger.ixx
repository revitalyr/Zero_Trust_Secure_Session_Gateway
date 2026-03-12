export module zerossg.logging.logger;

// C++23 module imports
import zerossg.common;
import zerossg.interfaces;

// Third-party library imports
export import <spdlog/spdlog.h>;
export import <spdlog/sinks/stdout_color_sinks.h>;
export import <spdlog/sinks/rotating_file_sink.h>;
export import <spdlog/sinks/daily_file_sink.h>;

// Standard library imports
export import <memory>;
export import <mutex>;
export import <chrono>;

export namespace zerossg {

export enum class LogLevel {
    TRACE = 0,
    DEBUG = 1,
    INFO = 2,
    WARN = 3,
    ERROR = 4,
    CRITICAL = 5
};

// Forward declarations
export class Logger;
export class LoggerManager;

export class Logger {
public:
    Logger(const String& name, LogLevel level = LogLevel::INFO);
    ~Logger();
    
    // Modern logging methods with semantic types
    void log_session_event(const SessionId& session_id, const String& event_type, const String& details);
    void log_error(const String& component, const ErrorMessage& error);
    void log_info(const String& component, const String& message);
    void log_debug(const String& component, const String& message);
    void log_security_event(const SecurityEvent& event);
    
    // Configuration methods
    void set_level(LogLevel level);
    LogLevel get_level() const noexcept;
    
    // Formatting options
    void format_timestamp(bool enable) noexcept;
    void format_security_event(bool enable) noexcept;
    void format_fields(const String& format) noexcept;

private:
    String m_name;
    LogLevel m_level;
    std::shared_ptr<spdlog::logger> m_logger;
    bool m_format_timestamp{true};
    bool m_format_security_event{true};
    String m_format_fields{"default"};
};

export class LoggerManager {
public:
    static LoggerManager& instance();
    
    // Modern logger management with semantic types
    Result<void> create_logger(const String& name, LogLevel level = LogLevel::INFO);
    Result<void> remove_logger(const String& name);
    Optional<Logger&> get_logger(const String& name);
    
    // Global configuration
    void set_global_level(LogLevel level);
    void set_output_file(const FileName& filename);
    void set_max_file_size(size_t size_bytes);
    void set_max_files(size_t count);
    
    // Flush all loggers
    void flush_all();
    
    // Statistics
    UserCount get_logger_count() const noexcept;
    Strings get_logger_names() const;

private:
    LoggerManager() = default;
    ~LoggerManager() = default;
    
    UnorderedMap<String, std::unique_ptr<Logger>> m_loggers;
    mutable std::mutex m_loggers_mutex;
    LogLevel m_global_level{LogLevel::INFO};
    FileName m_output_file{"zerossg.log"};
    size_t m_max_file_size{10 * 1024 * 1024}; // 10MB
    size_t m_max_files{5};
};

// Convenience macros for logging
export #define LOG_TRACE(logger, message) logger.log_debug(logger.m_name, message)
export #define LOG_DEBUG(logger, message) logger.log_debug(logger.m_name, message)
export #define LOG_INFO(logger, message) logger.log_info(logger.m_name, message)
export #define LOG_WARN(logger, message) logger.log_error(logger.m_name, message)
export #define LOG_ERROR(logger, message) logger.log_error(logger.m_name, message)
export #define LOG_CRITICAL(logger, message) logger.log_error(logger.m_name, message)

// Global logger access
export #define LOG_SESSION_EVENT(session_id, event_type, details) \
    zerossg::LoggerManager::instance().get_logger("session")->log_session_event(session_id, event_type, details)
export #define LOG_SECURITY_EVENT(event) \
    zerossg::LoggerManager::instance().get_logger("security")->log_security_event(event)

} // namespace zerossg
