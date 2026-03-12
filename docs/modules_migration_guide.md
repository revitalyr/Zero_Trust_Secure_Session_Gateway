# C++23 Modules Migration Guide

## Overview

This document outlines the migration strategy for C++23 modules in the Zero Trust Secure Session Gateway project.

## Current Status

The project has been prepared for C++23 modules with the following module files created:

- `include/zerossg/common.ixx` - Core type aliases and utilities
- `include/zerossg/constants.ixx` - Application constants
- `include/zerossg/types.ixx` - Data structures and enums
- `include/zerossg/interfaces.ixx` - Abstract interfaces

## Module Structure

### zerossg.common
Exports all fundamental type aliases, smart pointers, network types, and error handling utilities.

```cpp
export module zerossg.common;
export import <chrono>;
export import <memory>;
export import <string>;
// ... other imports

export namespace zerossg {
    export using UserName = std::string;
    export using Result = std::expected<T, std::string>;
    // ... other exports
}
```

### zerossg.constants
Exports all application constants and configuration values.

```cpp
export module zerossg.constants;
export import zerossg.common;

export namespace zerossg {
    export constexpr const char* APPLICATION_NAME = "Zero Trust Secure Session Gateway";
    // ... other constants
}
```

### zerossg.types
Exports data structures, enums, and concepts.

```cpp
export module zerossg.types;
export import zerossg.common;

export namespace zerossg {
    export struct User { /* ... */ };
    export enum class Role : uint8_t { /* ... */ };
    // ... other types
}
```

### zerossg.interfaces
Exports all abstract interfaces.

```cpp
export module zerossg.interfaces;
export import zerossg.common;
export import zerossg.types;

export namespace zerossg {
    export class IAuthenticator { /* ... */ };
    // ... other interfaces
}
```

## Migration Steps

### Phase 1: Compiler Support
1. Ensure compiler supports C++23 modules (MSVC 19.34+, GCC 13+, Clang 17+)
2. Update CMakeLists.txt to enable modules:
   ```cmake
   set(CMAKE_CXX_STANDARD 23)
   set(CMAKE_CXX_STANDARD_REQUIRED ON)
   set(CMAKE_CXX_EXTENSIONS OFF)
   ```

### Phase 2: Gradual Migration
1. Start with utility modules (common, constants, types)
2. Migrate interfaces to use modules
3. Update implementation files to import modules
4. Remove traditional header files

### Phase 3: Implementation Modules
Create implementation modules for each component:
- `zerossg.auth` - Authentication implementation
- `zerossg.session` - Session management
- `zerossg.security` - Security controls
- `zerossg.tls` - TLS handling
- `zerossg.config` - Configuration management

## Usage Examples

### Traditional Headers (Current)
```cpp
#include "zerossg/interfaces.hpp"
#include "zerossg/common.hpp"

void authenticate_user() {
    zerossg::UserName user = "admin";
    auto result = authenticator->authenticate(user, "password");
}
```

### C++23 Modules (Future)
```cpp
import zerossg.interfaces;
import zerossg.common;

void authenticate_user() {
    zerossg::UserName user = "admin";
    auto result = authenticator->authenticate(user, "password");
}
```

## Benefits

1. **Faster Compilation**: Modules eliminate redundant parsing
2. **Better Encapsulation**: Explicit export control
3. **Cleaner Dependencies**: No more include order issues
4. **Reduced Header Pollution**: Only exported symbols are visible
5. **Improved Build Times**: Incremental compilation of modules

## Compatibility

During transition period:
- Keep both header files and module files
- Use `#ifdef __cpp_modules` for conditional compilation
- Provide fallback to traditional includes

## Testing

Ensure module compatibility by:
1. Building with module-enabled compilers
2. Testing all exported symbols
3. Verifying template instantiation
4. Checking cross-module dependencies

## Performance Expectations

Expected improvements:
- 20-40% faster compilation times
- 10-20% reduced memory usage during compilation
- Faster incremental builds

## Notes

- Modules require C++23 or later
- Some third-party libraries may not support modules yet
- Build system configuration required for proper module handling
- Debugging tools need module support

## Future Enhancements

1. Partitioned modules for large components
2. Module partitions for better organization
3. Header units for standard library integration
4. Precompiled modules for distribution
