module;

// Third-party library imports
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/daily_file_sink.h>

// Standard library imports
#include <memory>
#include <mutex>
#include <chrono>
#include <source_location> // Добавлено
#include <format>          // Добавлено для удобства форматирования
#undef ERROR

export module zerossg.logging.logger;

// C++23 module imports
import zerossg.interfaces;
import zerossg.std;

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
    void log_security_event(const SecurityEvent& event);

    // Generic log method with source location and formatting support
    template<typename... Args>
    void log(LogLevel level, const std::source_location& loc, std::format_string<Args...> fmt, Args&&... args) {
        if (level < m_level) return;
        log_impl(level, loc, std::format(fmt, std::forward<Args>(args)...));
    }

    // Helper methods for specific levels using source_location
    template<typename... Args>
    void trace(std::format_string<Args...> fmt, Args&&... args, const std::source_location& loc = std::source_location::current()) {
        log(LogLevel::TRACE, loc, fmt, std::forward<Args>(args)...);
    }

    template<typename... Args>
    void debug(std::format_string<Args...> fmt, Args&&... args, const std::source_location& loc = std::source_location::current()) {
        log(LogLevel::DEBUG, loc, fmt, std::forward<Args>(args)...);
    }

    template<typename... Args>
    void info(std::format_string<Args...> fmt, Args&&... args, const std::source_location& loc = std::source_location::current()) {
        log(LogLevel::INFO, loc, fmt, std::forward<Args>(args)...);
    }

    template<typename... Args>
    void warn(std::format_string<Args...> fmt, Args&&... args, const std::source_location& loc = std::source_location::current()) {
        log(LogLevel::WARN, loc, fmt, std::forward<Args>(args)...);
    }

    template<typename... Args>
    void error(std::format_string<Args...> fmt, Args&&... args, const std::source_location& loc = std::source_location::current()) {
        log(LogLevel::ERROR, loc, fmt, std::forward<Args>(args)...);
    }

    template<typename... Args>
    void critical(std::format_string<Args...> fmt, Args&&... args, const std::source_location& loc = std::source_location::current()) {
        log(LogLevel::CRITICAL, loc, fmt, std::forward<Args>(args)...);
    }

    // Legacy support (to be deprecated or refactored)
    void log_error(const String& component, const ErrorMessage& error, const std::source_location& loc = std::source_location::current());
    void log_info(const String& component, const String& message, const std::source_location& loc = std::source_location::current());
    void log_debug(const String& component, const String& message, const std::source_location& loc = std::source_location::current());
    
    // Additional logging methods used in implementation
    void log_with_fields(LogLevel level, const String& component, const String& message, const std::vector<std::pair<String, String>>& fields);
    void log_authentication_attempt(const String& username, const String& client_ip, bool success, const String& reason);
    void log_session_creation(const String& session_id, const String& username, const String& client_ip, const String& target_service);
    void log_session_termination(const String& session_id, const String& reason);
    void log_access_denied(const String& username, const String& client_ip, const String& resource, const String& reason);
    void log_security_violation(const String& client_ip, const String& violation_type, const String& details);
    void log_performance_metric(const String& operation, double duration_ms, const String& unit);
    void log_connection_stats(size_t active_connections, size_t total_connections);
    void log_throughput(size_t bytes_transferred, const String& direction);

    // Sink management
    void add_file_sink(const String& filename, size_t max_file_size, size_t max_files);
    void add_daily_file_sink(const String& filename, int hour, int minute);
    void enable_console_output(bool enable);
    
    // Static helpers
    static spdlog::level::level_enum convert_log_level(LogLevel level);
    static String format_fields(const std::vector<std::pair<String, String>>& fields);

    // Configuration methods
    void set_level(LogLevel level);
    LogLevel get_level() const noexcept;
    
    // Formatting options
    void format_timestamp(bool enable) noexcept;
    void format_security_event(bool enable) noexcept;
    void set_pattern(const String& pattern);

private:
    void log_impl(LogLevel level, const std::source_location& loc, const String& message);
    void initialize_default_sinks();

    String m_name;
    LogLevel m_level;
    std::shared_ptr<spdlog::logger> m_logger;
    bool m_format_timestamp{true};
    bool m_format_security_event{true};
    String m_format_fields{"default"};
    std::mutex m_mutex;
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

} // namespace zerossg
