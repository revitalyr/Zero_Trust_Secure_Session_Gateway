#include "zerossg/network/gateway_server.hpp"
#include "zerossg/cli/cli_interface.hpp"
#include "zerossg/config/config_manager.hpp"
#include "zerossg/logging/logger.hpp"
#include <iostream>
#include <memory>
#include <csignal>

using namespace zerossg;

// Global server instance for signal handling
std::unique_ptr<GatewayServer> g_server;
std::atomic<bool> g_shutdown_requested{false};

// Signal handler for graceful shutdown
void signal_handler(int signal) {
    std::cout << "\nReceived signal " << signal << ", shutting down gracefully..." << std::endl;
    g_shutdown_requested.store(true);
    
    if (g_server && g_server->is_running()) {
        auto stop_result = g_server->stop();
        if (!stop_result.is_success()) {
            std::cerr << "Error stopping server: " << stop_result.error() << std::endl;
        }
    }
}

// Setup signal handlers
void setup_signal_handlers() {
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);
    
#ifndef _WIN32
    std::signal(SIGQUIT, signal_handler);
    std::signal(SIGHUP, SIG_IGN); // Ignore SIGHUP for daemon mode
#endif
}

// Print application banner
void print_banner() {
    std::cout << R"(
 _____ _   _ _   _    _    _   _  ____ _____ ____  
| ____| \ | | | | |  / \  | \ | |/ ___| ____|  _ \ 
|  _| |  \| | |_| | / _ \ |  \| | |   |  _| | | | |
| |___| |\  |  _  |/ ___ \| |\  | |___| |___| |_| |
|_____|_| \_|_| |_/_/   \_\_| \_|\____|_____|____/ 

Secure Session Gateway - Zero Trust Architecture
================================================
)" << std::endl;
}

// Print usage information
void print_usage(const char* program_name) {
    std::cout << "Usage: " << program_name << " [command] [options]" << std::endl;
    std::cout << std::endl;
    std::cout << "Commands:" << std::endl;
    std::cout << "  start [config-file]     Start the gateway server" << std::endl;
    std::cout << "  stop                    Stop the gateway server" << std::endl;
    std::cout << "  status                  Show server status" << std::endl;
    std::cout << "  interactive             Enter interactive CLI mode" << std::endl;
    std::cout << "  help                    Show this help message" << std::endl;
    std::cout << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  --config <file>         Configuration file path (default: config.json)" << std::endl;
    std::cout << "  --log-level <level>     Log level: trace, debug, info, warn, error, critical" << std::endl;
    std::cout << "  --daemon                Run as daemon (Unix only)" << std::endl;
    std::cout << "  --version               Show version information" << std::endl;
    std::cout << std::endl;
    std::cout << "Examples:" << std::endl;
    std::cout << "  " << program_name << " start config.json" << std::endl;
    std::cout << "  " << program_name << " interactive" << std::endl;
    std::cout << "  " << program_name << " --config production.json start" << std::endl;
}

// Parse command line arguments
struct CommandLineArgs {
    string command;
    string config_file{"config.json"};
    string log_level{"info"};
    bool daemon_mode{false};
    bool show_version{false};
    bool show_help{false};
    std::vector<string> command_args;
};

CommandLineArgs parse_command_line(int argc, char* argv[]) {
    CommandLineArgs args;
    
    for (int i = 1; i < argc; ++i) {
        string arg = argv[i];
        
        if (arg == "--help" || arg == "-h") {
            args.show_help = true;
            return args;
        } else if (arg == "--version" || arg == "-v") {
            args.show_version = true;
            return args;
        } else if (arg == "--config" || arg == "-c") {
            if (i + 1 < argc) {
                args.config_file = argv[++i];
            }
        } else if (arg == "--log-level" || arg == "-l") {
            if (i + 1 < argc) {
                args.log_level = argv[++i];
            }
        } else if (arg == "--daemon" || arg == "-d") {
            args.daemon_mode = true;
        } else if (arg.starts_with("--")) {
            std::cerr << "Unknown option: " << arg << std::endl;
            args.show_help = true;
            return args;
        } else if (args.command.empty()) {
            args.command = arg;
        } else {
            args.command_args.push_back(arg);
        }
    }
    
    return args;
}

// Run the server
int run_server(const CommandLineArgs& args) {
    try {
        // Initialize logging
        auto logger = Logger::create("zerossg");
        logger->set_level(LogLevel::INFO);
        logger->add_file_sink("logs/zerossg.log");
        
        LOG_INFO("main", "Starting Zero Trust Secure Session Gateway");
        
        // Load configuration
        auto config_manager = std::make_unique<ConfigManager>();
        auto config_result = config_manager->load_config(args.config_file);
        if (!config_result.is_success()) {
            std::cerr << "Failed to load configuration: " << config_result.error() << std::endl;
            return 1;
        }
        
        // Create and initialize server
        g_server = std::make_unique<GatewayServer>();
        auto init_result = g_server->initialize(args.config_file);
        if (!init_result.is_success()) {
            std::cerr << "Failed to initialize server: " << init_result.error() << std::endl;
            return 1;
        }
        
        // Setup signal handlers
        setup_signal_handlers();
        
        // Start server
        auto start_result = g_server->start();
        if (!start_result.is_success()) {
            std::cerr << "Failed to start server: " << start_result.error() << std::endl;
            return 1;
        }
        
        LOG_INFO("main", "Server started successfully");
        std::cout << "Server is running. Press Ctrl+C to stop." << std::endl;
        
        // Wait for shutdown signal
        while (g_server->is_running() && !g_shutdown_requested.load()) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        
        LOG_INFO("main", "Server shutting down");
        
        // Cleanup
        if (g_server) {
            g_server->stop();
            g_server.reset();
        }
        
        LOG_INFO("main", "Server stopped successfully");
        
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Server error: " << e.what() << std::endl;
        return 1;
    }
}

// Run CLI interface
int run_cli(const CommandLineArgs& args) {
    try {
        auto cli = std::make_unique<CLIInterface>();
        cli->set_config_file(args.config_file);
        
        if (args.command == "interactive") {
            print_banner();
            cli->run_interactive_mode();
            return 0;
        } else {
            // Convert command args to argc/argv format
            std::vector<string> all_args = {args.command};
            all_args.insert(all_args.end(), args.command_args.begin(), args.command_args.end());
            
            std::vector<char*> argv;
            for (auto& arg : all_args) {
                argv.push_back(const_cast<char*>(arg.c_str()));
            }
            
            auto result = cli->run(static_cast<int>(argv.size()), argv.data());
            return result.is_success() ? result.value() : 1;
        }
    } catch (const std::exception& e) {
        std::cerr << "CLI error: " << e.what() << std::endl;
        return 1;
    }
}

// Daemon mode (Unix only)
#ifndef _WIN32
int run_daemon(const CommandLineArgs& args) {
    pid_t pid = fork();
    
    if (pid < 0) {
        std::cerr << "Failed to fork daemon process" << std::endl;
        return 1;
    }
    
    if (pid > 0) {
        // Parent process exits
        std::cout << "Daemon started with PID: " << pid << std::endl;
        return 0;
    }
    
    // Child process continues as daemon
    umask(0);
    
    pid_t sid = setsid();
    if (sid < 0) {
        std::cerr << "Failed to create session ID" << std::endl;
        return 1;
    }
    
    // Change working directory
    if (chdir("/") < 0) {
        std::cerr << "Failed to change working directory" << std::endl;
        return 1;
    }
    
    // Close standard file descriptors
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    
    // Run server in daemon mode
    return run_server(args);
}
#endif

int main(int argc, char* argv[]) {
    // Parse command line arguments
    auto args = parse_command_line(argc, argv);
    
    // Handle help and version
    if (args.show_help) {
        print_usage(argv[0]);
        return 0;
    }
    
    if (args.show_version) {
        std::cout << "Zero Trust Secure Session Gateway v1.0.0" << std::endl;
        std::cout << "Built with modern C++20 and enterprise-grade security features" << std::endl;
        return 0;
    }
    
    // Handle daemon mode
    if (args.daemon_mode) {
#ifndef _WIN32
        return run_daemon(args);
#else
        std::cerr << "Daemon mode is not supported on Windows" << std::endl;
        return 1;
#endif
    }
    
    // Default command is 'start' if none provided
    if (args.command.empty()) {
        args.command = "start";
    }
    
    // Route to appropriate handler
    if (args.command == "start") {
        // Insert config file as first argument if provided
        if (!args.config_file.empty() && args.config_file != "config.json") {
            args.command_args.insert(args.command_args.begin(), args.config_file);
        }
        return run_server(args);
    } else {
        return run_cli(args);
    }
}
