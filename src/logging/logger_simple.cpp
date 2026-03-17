// Simple logger implementation without spdlog dependencies
module;

#include <iostream>
#include <fstream>
#include <string>
#include <chrono>
#include <iomanip>
#include <sstream>

module zerossg.logging.logger;

namespace zerossg {

// Simple Logger implementation
Logger::Logger(const String& name) : m_name(name) {
    std::cout << "Logger '" << m_name << "' initialized (simple mode)\n";
}

Logger::~Logger() {
    std::cout << "Logger '" << m_name << "' destroyed\n";
}

void Logger::info(const String& message) {
    log("INFO", message);
}

void Logger::warn(const String& message) {
    log("WARN", message);
}

void Logger::error(const String& message) {
    log("ERROR", message);
}

void Logger::debug(const String& message) {
    log("DEBUG", message);
}

void Logger::set_level(LogLevel level) {
    m_level = level;
}

void Logger::set_pattern(const String& pattern) {
    m_pattern = pattern;
}

void Logger::add_file_sink(const String& filename) {
    m_filename = filename;
    std::cout << "File sink added: " << filename << "\n";
}

void Logger::log(const String& level, const String& message) {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    
    std::ostringstream oss;
    oss << "[" << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S") << "]"
         << " [" << level << "]"
         << " [" << m_name << "]"
         << " " << message;
    
    String log_line = oss.str();
    
    // Output to console
    std::cout << log_line << "\n";
    
    // Output to file if configured
    if (!m_filename.empty()) {
        std::ofstream file(m_filename, std::ios::app);
        if (file.is_open()) {
            file << log_line << "\n";
        }
    }
}

// Factory function
std::unique_ptr<Logger> create_logger(const String& name) {
    return std::make_unique<Logger>(name);
}

} // namespace zerossg
