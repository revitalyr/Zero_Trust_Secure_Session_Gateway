// Example demonstrating C++23 modules usage
// This file shows how the project will use modules once compiler support is available

import zerossg.common;
import zerossg.constants;
import zerossg.types;
import zerossg.interfaces;
import zerossg.std;
import zerossg.result;

// Explicit usage of zerossg namespace preferred for maintenance

int main() {
    std::cout << "Zero Trust Secure Session Gateway" << std::endl;
    std::cout << "Version: " << zerossg::APPLICATION_VERSION << std::endl;
    
    // Example of using semantic types
    zerossg::UserName username = "admin";
    zerossg::PasswordHash password_hash = "hashed_password";
    zerossg::ClientIp client_ip = "192.168.1.100";
    zerossg::ServiceName service_name = "ssh";
    
    std::cout << "User: " << username << std::endl;
    std::cout << "Client IP: " << client_ip << std::endl;
    std::cout << "Target Service: " << service_name << std::endl;
    
    // Example of using Result type
    zerossg::Result<zerossg::User> user_result = zerossg::make_result_success(zerossg::User{
        .username = username,
        .password_hash = password_hash,
        .role = zerossg::Role::ADMIN,
        .status = zerossg::UserStatus::ACTIVE
    });
    
    if (user_result) {
        const zerossg::User& user = user_result.value();
        std::cout << "User created successfully with role: ";
        switch (user.role) {
            case zerossg::Role::ADMIN: std::cout << "ADMIN"; break;
            case zerossg::Role::OPERATOR: std::cout << "OPERATOR"; break;
            case zerossg::Role::VIEWER: std::cout << "VIEWER"; break;
        }
        std::cout << std::endl;
    } else {
        std::cout << "Error: " << user_result.error() << std::endl;
    }
    
    // Example of using time types
    zerossg::Hours session_timeout = zerossg::DEFAULT_SESSION_TIMEOUT;
    zerossg::Milliseconds block_duration = zerossg::DEFAULT_BLOCK_DURATION;
    
    std::cout << "Session timeout: " << session_timeout.count() << " hours" << std::endl;
    std::cout << "Block duration: " << block_duration.count() << " milliseconds" << std::endl;
    
    // Example of using collection types
    zerossg::Strings allowed_services = {"ssh", "web", "database"};
    std::cout << "Allowed services: ";
    for (const auto& service : allowed_services) {
        std::cout << service << " ";
    }
    std::cout << std::endl;
    
    return 0; // EXIT_SUCCESS requires stdlib or import std
}
