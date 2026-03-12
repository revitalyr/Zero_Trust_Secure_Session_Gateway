#pragma once

#include <string>
#include <string_view>
#include <memory>
#include <vector>
#include <unordered_map>
#include <chrono>
#include <optional>
#include <functional>
#include <stdexcept>
#include <system_error>
#include <mutex>
#include <expected>
#include <concepts>
#include <boost/asio.hpp>

namespace zerossg {

// Modern C++26 type aliases with semantic naming
using string_view = std::string_view;

template<typename T>
using unique_ptr = std::unique_ptr<T>;

template<typename T>
using shared_ptr = std::shared_ptr<T>;

template<typename T>
using weak_ptr = std::weak_ptr<T>;

template<typename T>
using vector = std::vector<T>;

template<typename K, typename V>
using unordered_map = std::unordered_map<K, V>;

using system_clock = std::chrono::system_clock;
using steady_clock = std::chrono::steady_clock;
using milliseconds = std::chrono::milliseconds;
using seconds = std::chrono::seconds;

// Semantic type aliases for member data types
using UserName = std::string;
using PasswordHash = std::string;
using SessionId = std::string;
using ClientIp = std::string;
using StringId = std::string;
using TokenString = std::string;
using ServiceName = std::string;
using HostAddress = std::string;
using SecretKey = std::vector<unsigned char>;
using ErrorMessage = std::string;

// Semantic type aliases for file names
using FileName = std::string;
using LogFileName = std::string;
using ConfigFileName = std::string;

// Semantic type aliases for database
using DbType = std::string;
using ConnectionString = std::string;
using Password = std::string;

// Semantic type aliases for counts and sizes
using UserCount = std::size_t;
using SessionCount = std::size_t;
using AttemptCount = std::size_t;
using PortNumber = std::uint16_t;
using PortNo = std::uint16_t;
using SecretSize = std::size_t;
using RateLimit = std::size_t;
using Threshold = std::size_t;
using Count = std::size_t;

// Semantic type aliases for time-related types
using TimePoint = std::chrono::system_clock::time_point;
using Duration = std::chrono::seconds;
using TimeoutDuration = std::chrono::seconds;
using Milliseconds = std::chrono::milliseconds;
using Hours = std::chrono::hours;
using Minutes = std::chrono::minutes;

// Semantic type aliases for collections
using Strings = std::vector<std::string>;
template<typename T>
using Roles = std::vector<T>;

// Smart pointer aliases
template<typename T>
using SessionManagerPtr = std::unique_ptr<T>;

// Network type aliases
using TcpEndpoint = boost::asio::ip::tcp::endpoint;

// Synchronization aliases
template<typename Mutex>
using LockGuard = std::lock_guard<Mutex>;

// Modern expected-based error handling (C++23)
template<typename T>
using Result = std::expected<T, std::string>;

// Helper functions for Result creation
template<typename T>
constexpr Result<T> make_result_success(T&& value) noexcept {
    return Result<T>{std::forward<T>(value)};
}

template<typename T>
constexpr Result<T> make_result_error(std::string error) noexcept {
    return std::unexpected<T>(std::move(error));
}

// Specialization for void using std::expected
using ResultVoid = std::expected<void, std::string>;

inline constexpr ResultVoid make_result_success() noexcept {
    return ResultVoid{};
}

inline constexpr ResultVoid make_result_error(std::string error) noexcept {
    return std::unexpected<void>(std::move(error));
}

// Concepts for type constraints
template<typename T>
concept StringLike = requires(T t) {
    { std::string_view{t} } -> std::convertible_to<std::string_view>;
};

template<typename T>
concept ChronoDuration = requires {
    typename T::rep;
    typename T::period;
    { typename T::clock::now() } -> std::same_as<typename T::time_point>;
};

template<typename T>
concept SmartPointer = requires(T t) {
    typename T::element_type;
    { *t } -> std::same_as<typename T::element_type&>;
    { t.get() } -> std::same_as<typename T::element_type*>;
    { static_cast<bool>(t) } -> std::convertible_to<bool>;
};

// Modern utility functions
template<typename T>
requires std::is_move_constructible_v<T>
constexpr auto move_if_noexcept(T& value) noexcept {
    if constexpr (std::is_nothrow_move_constructible_v<T>) {
        return std::move(value);
    } else {
        return value;
    }
}

template<typename T, typename... Args>
requires std::constructible_from<T, Args...>
constexpr auto make_unique_if_possible(Args&&... args) 
    noexcept(std::is_nothrow_constructible_v<T, Args...>) {
    return std::unique_ptr<T>{
        std::construct_at(
            std::allocator<T>().allocate(1), 
            std::forward<Args>(args)...
        )
    };
}

// Type traits extensions
template<typename T>
struct is_result_type : std::false_type {};

template<typename T>
struct is_result_type<std::expected<T, std::string>> : std::true_type {};

template<typename T>
inline constexpr bool is_result_type_v = is_result_type<T>::value;

// Functional utilities
template<typename F, typename... Args>
requires std::invocable<F, Args...>
constexpr auto invoke_if_noexcept(F&& f, Args&&... args) 
    noexcept(std::is_nothrow_invocable_v<F, Args...>) {
    if constexpr (std::is_nothrow_invocable_v<F, Args...>) {
        return std::forward<F>(f)(std::forward<Args>(args)...);
    } else {
        return std::forward<F>(f)(std::forward<Args>(args)...);
    }
}

} // namespace zerossg
