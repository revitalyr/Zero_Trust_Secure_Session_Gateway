// Logger tests
module;

#include <iostream>
#include <fstream>
#include <filesystem>

#define BOOST_UT_DISABLE_MODULE
#include <boost/ut.hpp>

import zerossg.logging.logger;
import zerossg.constants;

namespace zerossg::tests {

using namespace boost::ut;

// Test logger creation and basic functionality
suite logger_tests = [] {
    "logger_creation"_test = [] {
        Logger logger("test_logger", LogLevel::INFO);
        expect(true) << "Logger created successfully";
    };

    "logger_initialization"_test = [] {
        std::string test_log_file = "test_logger.log";
        
        // Remove test log file if it exists
        std::filesystem::remove(test_log_file);
        
        {
            Logger logger("test_logger", LogLevel::INFO, test_log_file);
            logger.info("Test message");
        }
        
        expect(std::filesystem::exists(test_log_file)) << "Log file should be created";
        
        // Clean up
        std::filesystem::remove(test_log_file);
    };

    "logger_log_levels"_test = [] {
        std::string test_log_file = "test_logger_levels.log";
        std::filesystem::remove(test_log_file);
        
        {
            Logger logger("test_logger", LogLevel::DEBUG, test_log_file);
            logger.debug("Debug message");
            logger.info("Info message");
            logger.warning("Warning message");
            logger.error("Error message");
        }
        
        expect(std::filesystem::exists(test_log_file)) << "Log file should be created";
        
        // Clean up
        std::filesystem::remove(test_log_file);
    };

    "logger_default_file"_test = [] {
        Logger logger("default_logger", LogLevel::INFO);
        expect(true) << "Logger with default file created successfully";
    };
};

} // namespace zerossg::tests
