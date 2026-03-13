#include <memory>
#include <csignal>

import zerossg.network.gateway_server;
import zerossg.cli.cli_interface;
import zerossg.config.config_manager;
import zerossg.logging.logger;
import zerossg.common;

import zerossg.std;

// Global server instance for signal handling
std::unique_ptr<zerossg::GatewayServer> g_server;
std::atomic<bool> g_shutdown_requested{false};

// Signal handler for graceful shutdown
void signal_handler(int signal) {
    zerossg::Logger::get("main")->info(std::format("Signal {} received, shutting down gracefully...", signal));
    g_shutdown_requested.store(true);
    
    if (g_server && g_server->is_running()) {
        auto stop_result = g_server->stop();
        if (!stop_result.is_success()) {
            zerossg::Logger::get("main")->error(std::format("Error stopping server: {}", stop_result.error()));
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
    zerossg::Logger::get("main")->info(R"(
 _____ _   _ _   _    _    _   _  ____ _____ ____  
| ____| \ | | | | |  / \  | \ | |/ ___| ____|  _ \ 
|  _| |  \| | |_| | / _ \ |  \| | |   |  _| | | | |
| |___| |\  |  _  |/ ___ \| |\  | |___| |___| |_| | 
|_____|_| \_|_| |_/_/   \_\_| \_|\____|_____|____/ 
        _____      _   _   _   _  ____ _____ 
       |  __ \    / \ | | | | | | |/ ___| ____|
       | |__) |  / _ \| | | | | | | |   |  _|  
       |  _  /  / ___ \ |_| | |_| | |___| |___ 
       |_| \_\/_/   \_\___/ \___/ \____|_____|
    
    Zero Trust Secure Session Gateway v1.0.0
    Modern C++20 implementation with enterprise-grade security
)");
}

// Print usage information
void print_usage(const char* program_name) {
    std::string usage = std::format(R"(
Usage: )" + zerossg::String(program_name) + R"( [command] [options]

Commands:
  start [config-file]     Start the gateway server
  stop                    Stop the gateway server
  status                  Show server status
  interactive             Enter interactive CLI mode
  help                    Show this help message

Options:
  --config <file>         Configuration file path (default: config.json)
  --log-level <level>     Log level: trace, debug, info, warn, error, critical
  --daemon                Run as daemon (Unix only)
  --version               Show version information

Examples:
  )" + String(program_name) + R"( start config.json
  )" + String(program_name) + R"( interactive
  )" + String(program_name) + R"( --config production.json start))");
    
    zerossg::Logger::get("main")->info(usage);
}

// Parse command line arguments
struct CommandLineArgs {
    String command;
    String config_file{"config.json"};
    String log_level{"info"};
    bool daemon_mode{false};
    bool show_version{false};
    bool show_help{false};
    std::vector<zerossg::String> command_args;
};

CommandLineArgs parse_command_line(int argc, char* argv[]) {
    CommandLineArgs args;
    
    for (int i = 1; i < argc; ++i) {
        zerossg::String arg = argv[i];
        
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
            zerossg::Logger::get("main")->error(std::format("Unknown option: {}", arg));
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
        zerossg::Logger::init(args.log_level, "logs/zerossg.log");
        auto logger = zerossg::Logger::get("main");
        
        logger->info("Starting Zero Trust Secure Session Gateway");
        
        // Load configuration
        auto config_manager = std::make_unique<ConfigManager>();
        auto config_result = config_manager->load_config(args.config_file);
        if (!config_result.is_success()) {
            logger->critical(std::format("Failed to load configuration: {}", config_result.error()));
            return 1;
        }
        
        // Create and initialize server
        g_server = std::make_unique<GatewayServer>();
        auto init_result = g_server->initialize(args.config_file);
        if (!init_result.is_success()) {
            logger->critical(std::format("Failed to initialize server: {}", init_result.error()));
            return 1;
        }
        
        // Setup signal handlers
        setup_signal_handlers();
        
        // Start server
        auto start_result = g_server->start();
        if (!start_result.is_success()) {
            logger->critical(std::format("Failed to start server: {}", start_result.error()));
            return 1;
        }
        
        logger->info("Server started successfully");
        logger->info("Server is running. Press Ctrl+C to stop.");
        
        // Wait for shutdown signal
        while (g_server->is_running() && !g_shutdown_requested.load()) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        
        logger->info("Server shutting down");
        
        // Cleanup
        if (g_server) {
            g_server->stop();
            g_server.reset();
        }
        logger->info("Server stopped successfully");
        
        return 0;
    } catch (const std::exception& e) {
        zerossg::Logger::get("main")->critical(std::format("Server error: {}", e.what()));
        return 1;
    }
}

// Run CLI interface
int run_cli(const CommandLineArgs& args) {
    try {
        zerossg::Logger::init(args.log_level, "", true); // Console only for CLI
        auto cli = std::make_unique<CLIInterface>();
        cli->set_config_file(args.config_file);
        
        if (args.command == "interactive") {
            print_banner();
            cli->run_interactive_mode();
            return 0;
        } else {
            // Convert command args to argc/argv format
            std::vector<zerossg::String> all_args = {args.command};
            all_args.insert(all_args.end(), args.command_args.begin(), args.command_args.end());
            
            std::vector<char*> argv;
            for (auto& arg : all_args) {
                argv.push_back(const_cast<char*>(arg.c_str()));
            }
            
            auto result = cli->run(static_cast<int>(argv.size()), argv.data());
            return result.is_success() ? result.value() : 1;
        }
    } catch (const std::exception& e) {
        zerossg::Logger::get("main")->error(std::format("CLI error: {}", e.what()));
        return 1;
    }
}

// Daemon mode (Unix only)
#ifndef _WIN32
int run_daemon(const CommandLineArgs& args) {
    pid_t pid = fork();
    
    if (pid < 0) {
        zerossg::Logger::get("main")->critical("Failed to fork daemon process");
        return 1;
    }
    
    if (pid > 0) {
        // Parent process exits
        zerossg::Logger::get("main")->info(std::format("Daemon started with PID: {}", pid));
        return 0;
    }
    
    // Child process continues as daemon
    umask(0);
    
    pid_t sid = setsid();
    if (sid < 0) {
        zerossg::Logger::get("main")->critical("Failed to create session ID");
        return 1;
    }
    
    // Change working directory
    if (chdir("/") < 0) {
        zerossg::Logger::get("main")->critical("Failed to change working directory");
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
    // Initial logging to console until config is parsed
    zerossg::Logger::init("info", "", true);

    auto args = parse_command_line(argc, argv);
    
    // Handle help and version
    if (args.show_help) {
        print_usage(argv[0]);
        return 0;
    }
    
    if (args.show_version) {
        zerossg::Logger::get("main")->info("Zero Trust Secure Session Gateway v1.0.0");
        zerossg::Logger::get("main")->info("Built with modern C++20 and enterprise-grade security features");
        return 0;
    }
    
    // Handle daemon mode
    if (args.daemon_mode) {
#ifndef _WIN32
        return run_daemon(args);
#else
        zerossg::Logger::get("main")->error("Daemon mode is not supported on Windows");
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
        if (!args.config_file.empty() && args.config_file != zerossg::String("config.json")) {
            args.command_args.insert(args.command_args.begin(), args.config_file);
        }
        return run_server(args);
    } else {
        return run_cli(args);
    }
}
