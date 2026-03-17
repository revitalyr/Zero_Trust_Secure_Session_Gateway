// Web interface main entry point
module;

#include <iostream>
#include <thread>
#include <chrono>

module zerossg.web.web_server;

namespace zerossg {

class WebApp {
public:
    WebApp() = default;
    
    int run(int argc, char* argv[]) {
        std::cout << "Zero Trust Secure Session Gateway - Web Interface\n";
        std::cout << "================================================\n\n";
        
        // Create web server
        auto server = create_web_server();
        
        // Start server
        auto result = server->start("localhost", 8080);
        if (!result) {
            std::cerr << "Failed to start web server: " << result.error() << "\n";
            return 1;
        }
        
        std::cout << "\nWeb interface is running!\n";
        std::cout << "Open http://localhost:8080 in your browser\n\n";
        std::cout << "Press Ctrl+C to stop the server\n\n";
        
        // Keep server running
        while (server->is_running()) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        
        return 0;
    }
};

} // namespace zerossg

int main(int argc, char* argv[]) {
    try {
        zerossg::WebApp app;
        return app.run(argc, argv);
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    } catch (...) {
        std::cerr << "Unknown error occurred\n";
        return 1;
    }
}
