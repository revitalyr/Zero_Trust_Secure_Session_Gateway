// Zero Trust Secure Session Gateway - Main Entry Point
// C++23 modules implementation

// Add Boost includes to provide context for ADL in non-module code
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

// Standard library includes for signal handling
#include <csignal>
#include <cstdlib>
#include <iostream>

// C++23 module imports
import zerossg.cli.cli_interface;
import zerossg.config.config_manager;
import zerossg.logging.logger;
import zerossg.network.gateway_server;
import zerossg.auth.authenticator;
import zerossg.session.session_manager;
import zerossg.security.security_manager;
import zerossg.rbac.authorizer;
import zerossg.tls.tls_handler;
import zerossg.proxy.proxy_manager;

namespace zerossg {

// Global server instance for signal handling
static std::unique_ptr<GatewayServer> g_server = nullptr;
static std::unique_ptr<CLIInterface> g_cli = nullptr;

// Signal handler for graceful shutdown
void signal_handler(int signal) {
    std::cout << "\nReceived signal " << signal << ", shutting down gracefully..." << std::endl;
    
    if (g_server && g_server->is_running()) {
        auto stop_result = g_server->stop();
        if (!stop_result.has_value()) {
            std::cerr << "Error stopping server: " << stop_result.error() << std::endl;
        }
    }
    
    std::exit(0);
}

// Setup signal handlers
void setup_signal_handlers() {
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);
    
#ifdef SIGQUIT
    std::signal(SIGQUIT, signal_handler);
#endif
}

} // namespace zerossg

int main(int argc, char* argv[]) {
    try {
        // Setup signal handlers for graceful shutdown
        zerossg::setup_signal_handlers();
        
        // Initialize logging system
        auto logger = zerossg::Logger::get("main");
        logger->info("Starting Zero Trust Secure Session Gateway");
        
        // Create CLI interface
        zerossg::g_cli = std::make_unique<zerossg::CLIInterface>();
        
        // Parse and execute command
        auto result = zerossg::g_cli->run(argc, argv);
        
        if (!result.has_value()) {
            std::cerr << "CLI execution failed: " << result.error() << std::endl;
            return 1;
        }
        
        logger->info("Zero Trust Secure Session Gateway completed successfully");
        return result.value();
        
    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 1;
    } catch (...) {
        std::cerr << "Unknown fatal error occurred" << std::endl;
        return 1;
    }
}
