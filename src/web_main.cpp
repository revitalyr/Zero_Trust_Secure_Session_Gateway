module;

#include <iostream>
#include <thread>
#include <chrono>

module zerossg.web_main;

import zerossg.web.web_server;
import zerossg.constants;

namespace zerossg {

class WebApp {
public:
    WebApp() = default;
    
    int run(int argc, char* argv[]) {
        std::cout << "Zero Trust Secure Session Gateway - Web Interface\n";
        std::cout << "================================================\n\n";
        
        // Parse command line arguments for port
        int port = DEFAULT_WEB_PORT;
        if (argc > 1) {
            try {
                port = std::stoi(argv[1]);
                if (port < PortNoMin || port > PortNoMax) {
                    std::cerr << "Error: Port must be between " << PortNoMin << " and " << PortNoMax << "\n";
                    return EXIT_FAILURE;
                }
            } catch (const std::exception& e) {
                std::cerr << "Error: Invalid port number\n";
                std::cerr << "Usage: " << argv[0] << " [port]\n";
                return EXIT_FAILURE;
            }
        }
        
        // Create web server
        auto server = create_web_server();
        
        // Check if port is available
        if (!WebServer::is_port_available(port)) {
            std::cerr << "Error: Port " << port << " is already in use!\n";
            std::cerr << "Please stop the other service or use a different port.\n";
            std::cerr << "Usage: " << argv[0] << " [port]\n";
            return EXIT_FAILURE;
        }
        
        // Start server
        auto result = server->start(DEFAULT_LOCALHOST, port);
        if (!result) {
            std::cerr << "Failed to start web server: " << result.error() << "\n";
            return EXIT_FAILURE;
        }
        
        std::cout << "\nWeb interface is running!\n";
        std::cout << "Open http://" << DEFAULT_LOCALHOST << ":" << port << " in your browser\n\n";
        std::cout << "Press Ctrl+C to stop the server\n\n";
        
        // Keep server running
        while (server->is_running()) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        
        return EXIT_SUCCESS;
    }
};

} // namespace zerossg

int main(int argc, char* argv[]) {
    try {
        zerossg::WebApp app;
        return app.run(argc, argv);
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return EXIT_FAILURE;
    } catch (...) {
        std::cerr << "Unknown error occurred\n";
        return EXIT_FAILURE;
    }
}
