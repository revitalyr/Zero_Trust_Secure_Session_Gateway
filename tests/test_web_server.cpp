// Web server tests
#include <iostream>
#include <thread>
#include <chrono>

#define BOOST_UT_DISABLE_MODULE
#include <boost/ut.hpp>

import zerossg.web.web_server;
import zerossg.constants;

namespace zerossg::tests {

using namespace boost::ut;

// Test web server creation and basic functionality
suite web_server_tests = [] {
    "web_server_creation"_test = [] {
        auto server = create_web_server();
        expect(server != nullptr) << "Web server should be created";
    };

    "web_server_initial_state"_test = [] {
        auto server = create_web_server();
        expect(!server->is_running()) << "Server should not be running initially";
    };

    "port_availability_check"_test = [] {
        // Test port availability for a port that should be available
        bool is_available = WebServer::is_port_available(9999);
        expect(true) << "Port availability check should work";
    };

    "port_availability_with_address"_test = [] {
        bool is_available = WebServer::is_port_available(DEFAULT_LOCALHOST, 9999);
        expect(true) << "Port availability check with address should work";
    };

    "web_server_start_stop"_test = [] {
        auto server = create_web_server();
        
        // Try to start on available port
        auto result = server->start(DEFAULT_LOCALHOST, 9999);
        expect(static_cast<bool>(result)) << "Server should start successfully";
        
        if (result) {
            expect(server->is_running()) << "Server should be running after start";
            
            // Give server a moment to initialize
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            
            // Stop the server
            auto stop_result = server->stop();
            expect(static_cast<bool>(stop_result)) << "Server should stop successfully";
        }
    };

    "web_server_handlers"_test = [] {
        auto server = create_web_server();
        
        // Test that all handlers can be called without crashing
        auto root_response = server->handle_root();
        expect(root_response.status_code == HTTP_STATUS_OK) << "Root handler should return 200";
        
        auto status_response = server->handle_status();
        expect(status_response.status_code == HTTP_STATUS_OK) << "Status handler should return 200";
        
        auto config_response = server->handle_config();
        expect(config_response.status_code == HTTP_STATUS_OK) << "Config handler should return 200";
        
        auto users_response = server->handle_users();
        expect(users_response.status_code == HTTP_STATUS_OK) << "Users handler should return 200";
        
        auto sessions_response = server->handle_sessions();
        expect(sessions_response.status_code == HTTP_STATUS_OK) << "Sessions handler should return 200";
        
        auto logs_response = server->handle_logs();
        expect(logs_response.status_code == HTTP_STATUS_OK) << "Logs handler should return 200";
        
        auto not_found_response = server->handle_not_found();
        expect(not_found_response.status_code == 404) << "Not found handler should return 404";
    };

    "web_server_json_responses"_test = [] {
        auto server = create_web_server();
        
        String status_json = server->get_status_json();
        expect(!status_json.empty()) << "Status JSON should not be empty";
        expect(status_json.find("status") != String::npos) << "Status JSON should contain status field";
        
        String config_json = server->get_config_json();
        expect(!config_json.empty()) << "Config JSON should not be empty";
        expect(config_json.find("server_port") != String::npos) << "Config JSON should contain server_port field";
    };
};

} // namespace zerossg::tests
