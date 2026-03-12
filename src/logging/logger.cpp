// C++23 module imports
import zerossg.interfaces;
import zerossg.constants;
#include <spdlog/async.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <chrono>;
#include <iomanip>;
#include <sstream>;
#include <memory>
#include <vector>
#include <mutex>
#include <algorithm>

namespace zerossg {
    // Import std utilities
    using std::lock_guard;
    using std::mutex;
    using std::string;
    using std::make_shared;
    using std::dynamic_pointer_cast;
    using std::vector;
    using std::pair;
    using std::remove_if;
    using LogLevel = zerossg::LogLevel;

namespace zerossg {

Logger::Logger() {
    initialize_default_sinks();
}

Logger::Logger(const string& name) {
    initialize_default_sinks();
    m_logger->set_name(name);
}

void Logger::log_security_event(const SecurityEvent& event) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    string formatted_event = format_security_event(event);
    m_logger->info("SECURITY_EVENT: {}", formatted_event);
}

void Logger::log_session_event(const string& session_id, const string& event_type, const string& details) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    m_logger->info("SESSION_EVENT: session_id={}, event_type={}, details={}", 
                   session_id, event_type, details);
}

void Logger::log_error(const string& component, const string& error) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_logger->error("ERROR [{}]: {}", component, error);
}

void Logger::log_info(const string& component, const string& message) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_logger->info("INFO [{}]: {}", component, message);
}

void Logger::log_debug(const string& component, const string& message) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_logger->debug("DEBUG [{}]: {}", component, message);
}

void Logger::set_level(LogLevel level) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_logger->set_level(convert_log_level(level));
}

void Logger::set_pattern(const string& pattern) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_logger->set_pattern(pattern);
}

void Logger::add_file_sink(const string& filename, size_t max_file_size, size_t max_files) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(filename, max_file_size, max_files);
    m_logger->sinks().push_back(file_sink);
}

void Logger::add_daily_file_sink(const string& filename, int hour, int minute) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto daily_sink = std::make_shared<spdlog::sinks::daily_file_sink_mt>(filename, hour, minute);
    m_logger->sinks().push_back(daily_sink);
}

void Logger::enable_console_output(bool enable) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (enable) {
        // Check if console sink already exists
        bool has_console_sink = false;
        for (const auto& sink : m_logger->sinks()) {
            if (std::dynamic_pointer_cast<spdlog::sinks::stdout_color_sink_mt>(sink)) {
                has_console_sink = true;
                break;
            }
        }
        
        if (!has_console_sink) {
            auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
            m_logger->sinks().insert(m_logger->sinks().begin(), console_sink);
        }
    } else {
        // Remove console sinks
        auto& sinks = m_logger->sinks();
        sinks.erase(std::remove_if(sinks.begin(), sinks.end(),
            [](const std::shared_ptr<spdlog::sinks::sink>& sink) {
                return std::dynamic_pointer_cast<spdlog::sinks::stdout_color_sink_mt>(sink) != nullptr;
            }), sinks.end());
    }
}

void Logger::log_with_fields(LogLevel level, const string& component, const string& message,
                            const std::vector<std::pair<string, string>>& fields) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    string fields_str = format_fields(fields);
    string full_message = message;
    if (!fields_str.empty()) {
        full_message += " | " + fields_str;
    }
    
    m_logger->log(convert_log_level(level), "[{}] {}", component, full_message);
}

void Logger::log_authentication_attempt(const string& username, const string& client_ip, bool success, const string& reason) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    vector<std::pair<string, string>> fields = {
        {"username", username},
        {"client_ip", client_ip},
        {"success", success ? "true" : "false"},
        {"timestamp", format_timestamp()}
    };
    
    if (!reason.empty()) {
        fields.emplace_back("reason", reason);
    }
    
    string fields_str = format_fields(fields);
    m_logger->info("AUTHENTICATION_ATTEMPT: {}", fields_str);
}

void Logger::log_session_creation(const string& session_id, const string& username, 
                                 const string& client_ip, const string& target_service) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    vector<std::pair<string, string>> fields = {
        {"session_id", session_id},
        {"username", username},
        {"client_ip", client_ip},
        {"target_service", target_service},
        {"timestamp", format_timestamp()}
    };
    
    string fields_str = format_fields(fields);
    m_logger->info("SESSION_CREATION: {}", fields_str);
}

void Logger::log_session_termination(const string& session_id, const string& reason) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    vector<std::pair<string, string>> fields = {
        {"session_id", session_id},
        {"timestamp", format_timestamp()}
    };
    
    if (!reason.empty()) {
        fields.emplace_back("reason", reason);
    }
    
    string fields_str = format_fields(fields);
    m_logger->info("SESSION_TERMINATION: {}", fields_str);
}

void Logger::log_access_denied(const string& username, const string& client_ip, 
                              const string& resource, const string& reason) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    vector<std::pair<string, string>> fields = {
        {"username", username},
        {"client_ip", client_ip},
        {"resource", resource},
        {"timestamp", format_timestamp()}
    };
    
    if (!reason.empty()) {
        fields.emplace_back("reason", reason);
    }
    
    string fields_str = format_fields(fields);
    m_logger->warn("ACCESS_DENIED: {}", fields_str);
}

void Logger::log_security_violation(const string& client_ip, const string& violation_type, const string& details) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    vector<std::pair<string, string>> fields = {
        {"client_ip", client_ip},
        {"violation_type", violation_type},
        {"timestamp", format_timestamp()}
    };
    
    if (!details.empty()) {
        fields.emplace_back("details", details);
    }
    
    string fields_str = format_fields(fields);
    m_logger->error("SECURITY_VIOLATION: {}", fields_str);
}

void Logger::log_performance_metric(const string& operation, double duration_ms, const string& unit) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    vector<std::pair<string, string>> fields = {
        {"operation", operation},
        {"duration", std::to_string(duration_ms) + " " + unit},
        {"timestamp", format_timestamp()}
    };
    
    string fields_str = format_fields(fields);
    m_logger->info("PERFORMANCE_METRIC: {}", fields_str);
}

void Logger::log_connection_stats(size_t active_connections, size_t total_connections) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    vector<std::pair<string, string>> fields = {
        {"active_connections", std::to_string(active_connections)},
        {"total_connections", std::to_string(total_connections)},
        {"timestamp", format_timestamp()}
    };
    
    string fields_str = format_fields(fields);
    m_logger->info("CONNECTION_STATS: {}", fields_str);
}

void Logger::log_throughput(size_t bytes_transferred, const string& direction) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    vector<std::pair<string, string>> fields = {
        {"bytes_transferred", std::to_string(bytes_transferred)},
        {"direction", direction},
        {"timestamp", format_timestamp()}
    };
    
    string fields_str = format_fields(fields);
    m_logger->info("THROUGHPUT: {}", fields_str);
}

std::shared_ptr<Logger> Logger::create(const string& name) {
    auto logger = std::make_shared<Logger>(name);
    return logger;
}

std::shared_ptr<Logger> Logger::create_with_file_output(const string& name, const string& log_file) {
    auto logger = std::make_shared<Logger>(name);
    logger->add_file_sink(log_file);
    return logger;
}

std::shared_ptr<Logger> Logger::create_security_logger() {
    auto logger = create("security");
    logger->add_file_sink("logs/security.log");
    logger->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] [SECURITY] %v");
    return logger;
}

std::shared_ptr<Logger> Logger::create_audit_logger() {
    auto logger = create("audit");
    logger->add_file_sink("logs/audit.log");
    logger->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] [AUDIT] %v");
    return logger;
}

spdlog::level::level_enum Logger::convert_log_level(LogLevel level) const {
    switch (level) {
        case LogLevel::TRACE: return spdlog::level::trace;
        case LogLevel::DEBUG: return spdlog::level::debug;
        case LogLevel::INFO: return spdlog::level::info;
        case LogLevel::WARN: return spdlog::level::warn;
        case LogLevel::ERROR: return spdlog::level::err;
        case LogLevel::CRITICAL: return spdlog::level::critical;
        default: return spdlog::level::info;
    }
}

string Logger::format_timestamp() const {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
    
    std::stringstream ss;
    ss << std::put_time(std::gmtime(&time_t), "%Y-%m-%dT%H:%M:%S");
    ss << '.' << std::setfill('0') << std::setw(3) << ms.count() << 'Z';
    
    return ss.str();
}

string Logger::format_security_event(const SecurityEvent& event) const {
    vector<std::pair<string, string>> fields = {
        {"type", security_event_type_to_string(event.type)},
        {"username", event.username},
        {"client_ip", event.client_ip},
        {"details", event.details},
        {"timestamp", format_timestamp()}
    };
    
    return format_fields(fields);
}

string Logger::format_fields(const std::vector<std::pair<string, string>>& fields) const {
    if (fields.empty()) {
        return "";
    }
    
    std::stringstream ss;
    for (size_t i = 0; i < fields.size(); ++i) {
        ss << fields[i].first << "=" << fields[i].second;
        if (i < fields.size() - 1) {
            ss << ", ";
        }
    }
    
    return ss.str();
}

void Logger::initialize_default_sinks() {
    std::vector<spdlog::sink_ptr> sinks;
    
    // Console sink
    auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
    sinks.push_back(console_sink);
    
    // Create logger with sinks
    m_logger = std::make_shared<spdlog::logger>("zerossg", sinks.begin(), sinks.end());
    
    // Set default pattern and level
    m_logger->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] %v");
    m_logger->set_level(spdlog::level::info);
    
    // Register with spdlog
    spdlog::register_logger(m_logger);
}

// LoggerManager implementation
LoggerManager& LoggerManager::instance() {
    static LoggerManager instance;
    return instance;
}

std::shared_ptr<Logger> LoggerManager::get_logger(const string& name) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto it = m_loggers.find(name);
    if (it != m_loggers.end()) {
        return it->second;
    }
    
    auto logger = Logger::create(name);
    m_loggers[name] = logger;
    
    if (!m_global_logger) {
        m_global_logger = logger;
    }
    
    return logger;
}

void LoggerManager::set_global_logger(std::shared_ptr<Logger> logger) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_global_logger = logger;
}

void LoggerManager::info(const string& message) {
    auto logger = get_logger();
    logger->log_info("global", message);
}

void LoggerManager::error(const string& message) {
    auto logger = get_logger();
    logger->log_error("global", message);
}

void LoggerManager::warn(const string& message) {
    auto logger = get_logger();
    logger->log_info("global", message); // Using info level for warnings
}

void LoggerManager::debug(const string& message) {
    auto logger = get_logger();
    logger->log_debug("global", message);
}

} // namespace zerossg
