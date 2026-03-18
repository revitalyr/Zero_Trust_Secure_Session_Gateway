# Modules Migration Guide

## Overview

This guide explains the migration from traditional C++ includes to C++23 modules in the Zero Trust Secure Session Gateway project.

## Migration Strategy

### Phase 1: Foundation (Completed)
- ✅ Basic module structure established
- ✅ Common types and utilities modularized
- ✅ Core interfaces defined
- ✅ Build system updated for modules

### Phase 2: Core Modules (Completed)
- ✅ Logging system modularized
- ✅ Network layer modularized
- ✅ Configuration management modularized
- ✅ Type system modularized

### Phase 3: Security Modules (In Progress)
- 🔄 Authentication module
- 🔄 Authorization module
- 🔄 Session management
- 🔄 Security controls

### Phase 4: Interface Modules (In Progress)
- 🔄 Web server interface
- 🔄 CLI interface
- 🔄 Gateway server integration

## Module Dependencies

```
Level 0 (Foundation):
├── std.ixx              # Standard library imports
├── common.ixx            # Common types and utilities
└── network.ixx           # Network type aliases

Level 1 (Core):
├── types.ixx              # Core type definitions
├── constants.ixx          # System constants
├── interfaces.ixx         # Abstract interfaces
└── third_party/          # Third-party library wrappers

Level 2 (Implementation):
├── logging/logger.ixx     # Logging system
├── config/config_manager.ixx # Configuration
├── auth/authenticator.ixx  # Authentication
├── rbac/authorizer.ixx     # Authorization
├── session/session_manager.ixx # Sessions
├── security/security_manager.ixx # Security
├── network/gateway_server.ixx # Gateway
├── cli/cli_interface.ixx   # CLI
└── web/web_server.ixx      # Web server
```

## Conversion Examples

### Traditional Includes → Modules

**Before (Traditional)**:
```cpp
// authenticator.h
#pragma once

#include <string>
#include <vector>
#include <memory>
#include <expected>
#include "types.h"
#include "interfaces.h"
#include "logger.h"

class AuthenticationManager {
public:
    AuthenticationManager();
    std::expected<std::string, std::string> authenticate(
        const std::string& username, 
        const std::string& password
    );
private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};
```

**After (Modules)**:
```cpp
// authenticator.ixx
export module zerossg.auth.authenticator;

import zerossg.std;         // std::string, std::vector, etc.
import zerossg.common;       // smart pointers, Result type
import zerossg.types;        // core types
import zerossg.interfaces;    // abstract interfaces
import zerossg.logging.logger; // logging

export namespace zerossg {
    export class AuthenticationManager {
    public:
        AuthenticationManager();
        Result<String> authenticate(
            const UserName& username, 
            const PasswordHash& password
        );
    private:
        class Impl;
        UniquePtr<Impl> m_impl;
    };
}
```

### Implementation Unit Migration

**Before**:
```cpp
// authenticator.cpp
#include "authenticator.h"
#include "logger.h"
#include "crypto_utils.h"
#include "database.h"

AuthenticationManager::AuthenticationManager() 
    : m_impl(std::make_unique<Impl>()) {}
```

**After**:
```cpp
// authenticator.cpp
module zerossg.auth.authenticator;

import zerossg.std;              // All standard library
import zerossg.common;            // Common utilities
import zerossg.types;             // Type definitions
import zerossg.interfaces;         // Interfaces
import zerossg.logging.logger;    // Logging
import zerossg.third_party.openssl; // Crypto functions
// ... other imports

AuthenticationManager::AuthenticationManager() 
    : m_impl(std::make_unique<Impl>()) {}
```

## Common Migration Patterns

### 1. Type Aliases

```cpp
// In common.ixx
export module zerossg.common;

import zerossg.std;

export namespace zerossg {
    // Modern type aliases
    using String = std::string;
    using Result = std::expected<T, std::string>;
    using UniquePtr = std::unique_ptr<T>;
    using SharedPtr = std::shared_ptr<T>;
    
    // Semantic type aliases
    using UserName = std::string;
    using PasswordHash = std::string;
    using SessionId = std::string;
    using ErrorMessage = std::string;
}
```

### 2. Forward Declarations in Interfaces

```cpp
// gateway_server.ixx
export module zerossg.network.gateway_server;

import zerossg.common;
import zerossg.network;
import zerossg.std;

export namespace zerossg {
    // Forward declarations to reduce interface complexity
    class AuthenticationManager;
    class AuthorizationManager;
    class SessionManager;
    class SecurityManager;
    class ConfigManager;
    
    export class GatewayServer {
    public:
        GatewayServer() = default;
        Result<void> initialize(const ConfigManager& config);
        Result<void> start();
        Result<void> stop();
    private:
        UniquePtr<AuthenticationManager> m_auth_manager;
        UniquePtr<AuthorizationManager> m_authz_manager;
        UniquePtr<SessionManager> m_session_manager;
        UniquePtr<SecurityManager> m_security_manager;
    };
}
```

### 3. Implementation with Full Imports

```cpp
// gateway_server.cpp
module zerossg.network.gateway_server;

import zerossg.auth.authenticator;      // Full implementation access
import zerossg.rbac.authorizer;         // Complete authorization
import zerossg.session.session_manager;  // Session management
import zerossg.security.security_manager; // Security controls
import zerossg.config.config_manager;   // Configuration
import zerossg.logging.logger;          // Logging
// ... all necessary imports

Result<void> GatewayServer::initialize(const ConfigManager& config) {
    // Full access to all imported types
    m_auth_manager = std::make_unique<AuthenticationManager>();
    m_authz_manager = std::make_unique<AuthorizationManager>();
    // ... implementation
}
```

## Build System Updates

### CMakeLists.txt for Modules

```cmake
# Enable C++23 modules
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_SCAN_FOR_MODULES ON)

# Create library with modules
add_library(zerossg_lib)

# Add module interface files
target_sources(zerossg_lib
    PUBLIC
        FILE_SET CXX_MODULES FILES
        "include/zerossg/std.ixx"
        "include/zerossg/common.ixx"
        "include/zerossg/network.ixx"
        "include/zerossg/types.ixx"
        "include/zerossg/interfaces.ixx"
        "include/zerossg/constants.ixx"
        "include/zerossg/logging/logger.ixx"
        "include/zerossg/config/config_manager.ixx"
        "include/zerossg/auth/authenticator.ixx"
        "include/zerossg/rbac/authorizer.ixx"
        "include/zerossg/session/session_manager.ixx"
        "include/zerossg/security/security_manager.ixx"
        "include/zerossg/network/gateway_server.ixx"
        "include/zerossg/cli/cli_interface.ixx"
        "include/zerossg/web/web_server.ixx"
)

# Add implementation files
target_sources(zerossg_lib
    PRIVATE
        "src/config/config_manager.cpp"
        "src/logging/logger.cpp"
        "src/auth/authenticator.cpp"
        "src/rbac/authorizer.cpp"
        "src/session/session_manager.cpp"
        "src/security/security_manager.cpp"
        "src/network/gateway_server.cpp"
        "src/cli/cli_interface.cpp"
        "src/web/web_server_impl.cpp"
)
```

## Testing with Modules

### Test File Structure

```cpp
// test_logger.cpp
#define BOOST_UT_DISABLE_MODULE
#include <boost/ut.hpp>

import zerossg.logging.logger;
import zerossg.constants;

namespace zerossg::tests {
    using namespace boost::ut;

    suite logger_tests = [] {
        "logger_creation"_test = [] {
            Logger logger("test_logger", LogLevel::INFO);
            expect(true) << "Logger created successfully";
        };

        "logger_3arg_constructor"_test = [] {
            std::string test_log_file = "test_logger.log";
            Logger logger("test_logger", LogLevel::INFO, test_log_file);
            expect(std::filesystem::exists(test_log_file)) << "Log file should be created";
        };
    };
}
```

### CMake Test Configuration

```cmake
# Test executable with modules
add_executable(zerossg_tests 
    "tests/test_authentication.cpp"
    "tests/test_authorization.cpp" 
    "tests/test_session_manager.cpp"
    "tests/test_logger.cpp"
    "tests/test_web_server.cpp"
    src/auth/authenticator.cpp
    src/rbac/authorizer.cpp
    src/session/session_manager.cpp
    src/logging/logger.cpp
)

target_link_libraries(zerossg_tests 
    PRIVATE zerossg_lib
    Boost::date_time
    Boost::container
    yaml-cpp
    Boost::ut
)
```

## Troubleshooting

### Common Issues and Solutions

1. **Module Not Found**
   ```
   error C2230: could not find module 'zerossg.example'
   ```
   **Solution**: Check module export syntax and CMake configuration

2. **Circular Dependencies**
   ```
   error C2653: 'Example': is not a class or namespace name
   ```
   **Solution**: Use forward declarations, restructure dependencies

3. **ICE in MSVC**
   ```
   fatal error C1001: Internal compiler error
   ```
   **Solution**: Reduce interface complexity, use forward declarations

4. **Link Errors**
   ```
   error LNK2019: unresolved external symbol
   ```
   **Solution**: Ensure all implementation units are included in build

## Best Practices

### 1. Module Interface Design
- Keep interfaces minimal
- Use forward declarations extensively
- Export only what's necessary
- Group related functionality

### 2. Dependency Management
- Clear dependency hierarchy
- Avoid circular dependencies
- Use implementation units for heavy dependencies
- Import at module level, not class level

### 3. Performance Considerations
- Modules enable better optimization
- Reduced compilation times
- Better binary size
- Improved incremental builds

### 4. Maintenance
- Clear module boundaries
- Document module interfaces
- Use consistent naming conventions
- Test module boundaries

## Future Enhancements

### Module Partitions
For large modules, consider partitions:

```cpp
// big_module.ixx
export module zerossg.big_module;

export module zerossg.big_module:part1;
export module zerossg.big_module:part2;
export module zerossg.big_module:part3;

// part1.ixx
export module zerossg.big_module:part1;

// part2.ixx  
export module zerossg.big_module:part2;

// part3.ixx
export module zerossg.big_module:part3;
```

### Private Module Fragments
For implementation details:

```cpp
export module zerossg.example:private;

module :private;
// Implementation details not exported
```

---

This migration guide provides a comprehensive approach to modernizing C++ codebases with C++23 modules.
