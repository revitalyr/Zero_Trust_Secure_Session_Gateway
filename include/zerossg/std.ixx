export module std;

// Standard Library headers (alphabetical order)
export import <algorithm>;
export import <atomic>;
export import <chrono>;
export import <concepts>;
export import <cctype>;
export import <cstdlib>;
export import <cstdint>;
export import <expected>;
export import <filesystem>;
export import <fstream>;
export import <functional>;
export import <iomanip>;
export import <iostream>;
export import <memory>;
export import <mutex>;
export import <optional>;
export import <queue>;
export import <random>;
export import <sstream>;
export import <stdexcept>;
export import <string>;
export import <string_view>;
export import <thread>;
export import <unordered_map>;
export import <unordered_set>;
export import <variant>;
export import <vector>;

// Export all necessary types from std namespace
export namespace std {
    // String types
    using std::string;
    using std::string_view;
    
    // Container types
    using std::vector;
    using std::unordered_map;
    using std::unordered_set;
    
    // Smart pointers
    using std::shared_ptr;
    using std::unique_ptr;
    
    // Synchronization
    using std::mutex;
    using std::lock_guard;
    
    // Time types
    using std::chrono::seconds;
    using std::chrono::milliseconds;
    using std::chrono::hours;
    using std::chrono::minutes;
    
    // File system
    using std::filesystem::exists;
    using std::ifstream;
    using std::ofstream;
    
    // Utility types
    using std::stoi;
    using std::to_string;
    using std::transform;
    using std::tolower;
    using std::getenv;
    
    // Exception handling
    using std::exception;
    using std::expected;
    
    // Other utilities
    using std::optional;
    using std::queue;
    using std::random_device;
    using std::mt19937;
    using std::uniform_int_distribution;
}
