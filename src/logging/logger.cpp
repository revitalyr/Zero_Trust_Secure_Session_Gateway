module;

#include <filesystem>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include <spdlog/async.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/daily_file_sink.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <chrono>
#include <iomanip>

#undef ERROR // Fix collision with Windows ERROR macro
module zerossg.logging.logger;

import zerossg.interfaces;
import zerossg.constants;
import zerossg.std;

// Logger class implementation
namespace zerossg {

Logger::Logger(const String& name, LogLevel level) : m_mutex(), m_logger(nullptr) {
    initialize_default_sinks();
    // m_logger->set_name(name); // spdlog::logger does not have set_name
    set_level(level);
}

// Private helper methods
void Logger::initialize_default_sinks() {
    // Create default file sink
    auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>("logs/zerossg.log", 1024*1024, 3);
    file_sink->set_level(spdlog::level::info);
    
    m_logger = std::make_shared<spdlog::logger>("zerossg", file_sink);
    m_logger->set_level(spdlog::level::info);
    m_logger->flush_on(spdlog::level::info);
}

String Logger::format_fields(const std::vector<std::pair<String, String>>& fields) {
    std::stringstream ss;
    for (const auto& field : fields) {
        ss << field.first << "=" << field.second;
        if (&field != &fields.back()) {
            ss << ", ";
        }
    }
    return ss.str();
}

spdlog::level::level_enum Logger::convert_log_level(LogLevel level) {
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

void Logger::log_security_event(const String& event_type, const String& details) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    String formatted_event = format_fields({
        {"event_type", event_type},
        {"details", details}
    });
    
    m_logger->info("SECURITY_EVENT: {}", formatted_event);
}

void Logger::log_session_event(const String& session_id, const String& event_type, const String& details) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    m_logger->info("SESSION_EVENT: session_id={}, event_type={}, details={}", 
                   session_id, event_type, details);
}

void Logger::log_error(const String& component, const String& error, const std::source_location& loc) {
    // Redirect legacy calls to new implementation
    log_impl(LogLevel::ERROR, loc, std::format("[{}]: {}", component, error));
}

void Logger::log_info(const String& component, const String& message, const std::source_location& loc) {
    log_impl(LogLevel::INFO, loc, std::format("[{}]: {}", component, message));
}

void Logger::log_debug(const String& component, const String& message, const std::source_location& loc) {
    log_impl(LogLevel::DEBUG, loc, std::format("[{}]: {}", component, message));
}

void Logger::log_impl(LogLevel level, const std::source_location& loc, const String& message) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Extract filename from path
    std::filesystem::path path(loc.file_name());
    String filename = path.filename().string();
    
    // Format with source location info
    String detailed_msg = std::format("[{}:{}] {}", filename, loc.line(), message);

    m_logger->log(convert_log_level(level), "{}", detailed_msg);
}

void zerossg::Logger::set_level(zerossg::LogLevel level) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_logger->set_level(zerossg::Logger::convert_log_level(level));
}

void zerossg::Logger::set_pattern(const zerossg::String& pattern) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_logger->set_pattern(pattern);
}

void zerossg::Logger::add_file_sink(const zerossg::String& filename, size_t max_file_size, size_t max_files) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(filename, max_file_size, max_files);
    m_logger->sinks().push_back(file_sink);
}

void zerossg::Logger::add_daily_file_sink(const zerossg::String& filename, int hour, int minute) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto daily_sink = std::make_shared<spdlog::sinks::daily_file_sink_mt>(filename, hour, minute, false, static_cast<uint16_t>(5));
    m_logger->sinks().push_back(daily_sink);
}

void zerossg::Logger::enable_console_output(bool enable) {
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
        m_logger->sinks().erase(
            std::remove_if(m_logger->sinks().begin(), m_logger->sinks().end(),
                [](const std::shared_ptr<spdlog::sinks::sink>& sink) -> bool {
                    return std::dynamic_pointer_cast<spdlog::sinks::stdout_color_sink_mt>(sink) != nullptr;
                }),
            m_logger->sinks().end());
    }
}

void zerossg::Logger::log_with_fields(zerossg::LogLevel level, const zerossg::String& component, const zerossg::String& message,
                            const std::vector<std::pair<zerossg::String, zerossg::String>>& fields) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    zerossg::String fields_str = zerossg::Logger::format_fields(fields);
    zerossg::String full_message = message;
    if (!fields_str.empty()) {
        full_message += " | " + fields_str;
    }
    
    m_logger->log(zerossg::Logger::convert_log_level(level), "[{}] {}", component, full_message);
}

void zerossg::Logger::log_authentication_attempt(const zerossg::String& username, const zerossg::String& client_ip, bool success, const zerossg::String& reason) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    zerossg::String status = success ? "SUCCESS" : "FAILED";
    zerossg::String event_type = "AUTH_ATTEMPT";
    
    zerossg::Logger::log_security_event(event_type, "username=" + username + ", client_ip=" + client_ip + ", status=" + status + ", reason=" + reason);
}

void zerossg::Logger::log_session_creation(const zerossg::String& session_id, const zerossg::String& username, 
                                 const zerossg::String& client_ip, const zerossg::String& target_service) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    std::vector<std::pair<zerossg::String, zerossg::String>> fields = {
        {"session_id", session_id},
        {"username", username},
        {"client_ip", client_ip},
        {"target_service", target_service}
    };
    
    zerossg::String fields_str = zerossg::Logger::format_fields(fields);
    m_logger->info("SESSION_CREATION: {}", fields_str);
}

void zerossg::Logger::log_session_termination(const zerossg::String& session_id, const zerossg::String& reason) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    std::vector<std::pair<zerossg::String, zerossg::String>> fields = {
        {"session_id", session_id},
        {"reason", reason}
    };
    
    zerossg::String fields_str = zerossg::Logger::format_fields(fields);
    m_logger->info("SESSION_TERMINATION: {}", fields_str);
}

void zerossg::Logger::log_access_denied(const zerossg::String& username, const zerossg::String& client_ip, 
                              const zerossg::String& resource, const zerossg::String& reason) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    std::vector<std::pair<zerossg::String, zerossg::String>> fields = {
        {"username", username},
        {"client_ip", client_ip},
        {"resource", resource}
    };
    
    if (!reason.empty()) {
        fields.emplace_back("reason", reason);
    }
    
    zerossg::String fields_str = zerossg::Logger::format_fields(fields);
    m_logger->warn("ACCESS_DENIED: {}", fields_str);
}

void zerossg::Logger::log_security_violation(const zerossg::String& client_ip, const zerossg::String& violation_type, const zerossg::String& details) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    std::vector<std::pair<zerossg::String, zerossg::String>> fields = {
        {"client_ip", client_ip},
        {"violation_type", violation_type}
    };
    
    if (!details.empty()) {
        fields.emplace_back("details", details);
    }
    
    zerossg::String fields_str = zerossg::Logger::format_fields(fields);
    m_logger->error("SECURITY_VIOLATION: {}", fields_str);
}

void zerossg::Logger::log_performance_metric(const zerossg::String& operation, double duration_ms, const zerossg::String& unit) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    std::vector<std::pair<zerossg::String, zerossg::String>> fields = {
        {"operation", operation},
        {"duration", std::to_string(duration_ms) + " " + unit}
    };
    
    zerossg::String fields_str = zerossg::Logger::format_fields(fields);
    m_logger->info("PERFORMANCE_METRIC: {}", fields_str);
}

void zerossg::Logger::log_connection_stats(size_t active_connections, size_t total_connections) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    std::vector<std::pair<zerossg::String, zerossg::String>> fields = {
        {"active_connections", std::to_string(active_connections)},
        {"total_connections", std::to_string(total_connections)}
    };
    
    zerossg::String fields_str = zerossg::Logger::format_fields(fields);
    m_logger->info("CONNECTION_STATS: {}", fields_str);
}

void zerossg::Logger::log_throughput(size_t bytes_transferred, const zerossg::String& direction) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    std::vector<std::pair<zerossg::String, zerossg::String>> fields = {
        {"bytes_transferred", std::to_string(bytes_transferred)},
        {"direction", direction}
    };
    
    zerossg::String fields_str = zerossg::Logger::format_fields(fields);
    m_logger->info("THROUGHPUT: {}", fields_str);
}

} // namespace zerossg
