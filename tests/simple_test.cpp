#include <iostream>
#include <string>

int main() {
    std::cout << "Simple test - checking basic functionality\n";
    
    // Test basic string operations
    std::string test = "Hello, ZeroTrust!";
    std::cout << "Test string: " << test << std::endl;
    
    // Test basic math
    int result = 2 + 2;
    std::cout << "2 + 2 = " << result << std::endl;
    
    if (result == 4) {
        std::cout << "✅ Basic test passed!\n";
        return 0;
    } else {
        std::cout << "❌ Basic test failed!\n";
        return 1;
    }
}
