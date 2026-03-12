// Example demonstrating C++23 modules usage
// This file shows how the project will use modules once compiler support is available

#ifdef __cpp_modules
// C++23 modules usage (future)
import zerossg.common;
import zerossg.constants;
import zerossg.types;
import zerossg.interfaces;
#else
// Traditional header usage (current)
#include "zerossg/common.hpp"
#include "zerossg/constants.hpp"
#include "zerossg/types.hpp"
#include "zerossg/interfaces.hpp"
#endif

#include <iostream>

using namespace zerossg;

int main() {
    std::cout << "Zero Trust Secure Session Gateway" << std::endl;
    std::cout << "Version: " << APPLICATION_VERSION << std::endl;
    
    // Example of using semantic types
    UserName username = "admin";
    PasswordHash password_hash = "hashed_password";
    ClientIp client_ip = "192.168.1.100";
    ServiceName service_name = "ssh";
    
    std::cout << "User: " << username << std::endl;
    std::cout << "Client IP: " << client_ip << std::endl;
    std::cout << "Target Service: " << service_name << std::endl;
    
    // Example of using Result type
    Result<User> user_result = make_result_success(User{
        .username = username,
        .password_hash = password_hash,
        .role = Role::ADMIN,
        .status = UserStatus::ACTIVE
    });
    
    if (user_result) {
        const User& user = user_result.value();
        std::cout << "User created successfully with role: ";
        switch (user.role) {
            case Role::ADMIN: std::cout << "ADMIN"; break;
            case Role::OPERATOR: std::cout << "OPERATOR"; break;
            case Role::VIEWER: std::cout << "VIEWER"; break;
        }
        std::cout << std::endl;
    } else {
        std::cout << "Error: " << user_result.error() << std::endl;
    }
    
    // Example of using time types
    Hours session_timeout = DEFAULT_SESSION_TIMEOUT;
    Milliseconds block_duration = DEFAULT_BLOCK_DURATION;
    
    std::cout << "Session timeout: " << session_timeout.count() << " hours" << std::endl;
    std::cout << "Block duration: " << block_duration.count() << " milliseconds" << std::endl;
    
    // Example of using collection types
    Strings allowed_services = {"ssh", "web", "database"};
    std::cout << "Allowed services: ";
    for (const auto& service : allowed_services) {
        std::cout << service << " ";
    }
    std::cout << std::endl;
    
    return EXIT_SUCCESS;
}
