module;

#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

module zerossg.logging.logger;

import <vector>;
import <memory>;
import <string>;

namespace zerossg {

class Logger::Impl {
public:
    std::shared_ptr<spdlog::logger> spd_logger;
};

Logger::Logger(const std::string& name) : pimpl(std::make_unique<Impl>()) {
    pimpl->spd_logger = spdlog::get(name);
    if (!pimpl->spd_logger) {
        // If get fails, it means init hasn't been called or the name is new.
        // spdlog::get returns nullptr for unregistered loggers.
        // We'll rely on a default logger if it exists.
        pimpl->spd_logger = spdlog::default_logger();
    }
}

void Logger::init(const std::string& level, const std::string& file_path, bool enable_console) {
    std::vector<spdlog::sink_ptr> sinks;
    if (enable_console) {
        sinks.push_back(std::make_shared<spdlog::sinks::stdout_color_sink_mt>());
    }
    if (!file_path.empty()) {
        // 5MB per file, 3 rotated files
        sinks.push_back(std::make_shared<spdlog::sinks::rotating_file_sink_mt>(file_path, 1024 * 1024 * 5, 3));
    }

    auto logger = std::make_shared<spdlog::logger>("zerossg", begin(sinks), end(sinks));
    spdlog::register_logger(logger);
    spdlog::set_default_logger(logger);

    spdlog::set_level(spdlog::level::from_str(level));
    spdlog::flush_on(spdlog::level::info);
}

std::shared_ptr<Logger> Logger::get(const std::string& name) {
    // Use a private constructor with std::make_shared
    return std::shared_ptr<Logger>(new Logger(name));
}

void Logger::trace(const std::string& msg) { pimpl->spd_logger->trace(msg); }
void Logger::debug(const std::string& msg) { pimpl->spd_logger->debug(msg); }
void Logger::info(const std::string& msg) { pimpl->spd_logger->info(msg); }
void Logger::warn(const std::string& msg) { pimpl->spd_logger->warn(msg); }
void Logger::error(const std::string& msg) { pimpl->spd_logger->error(msg); }
void Logger::critical(const std::string& msg) { pimpl->spd_logger->critical(msg); }

}