module;
#include <expected>
#include <string>
#include <string_view>
#include <vector>
#include <memory>
#include <optional>
#include <unordered_map>
#include <chrono>
#include <cstdint>
#include <cstddef>
#include <utility>
#include <mutex>
#include <shared_mutex>

export module zerossg.common;

export namespace zerossg {

// Modern C++26 type aliases with semantic naming
using StringView = std::string_view;

template<typename T>
using UniquePtr = std::unique_ptr<T>;

template<typename T>
using SharedPtr = std::shared_ptr<T>;

template<typename T>
using WeakPtr = std::weak_ptr<T>;

template<typename T>
using Optional = std::optional<T>;

template<typename T>
using Vector = std::vector<T>;

template<typename K, typename V>
using UnorderedMap = std::unordered_map<K, V>;

template<typename T, typename E = std::string>
using Result = std::expected<T, E>;

using SystemClock = std::chrono::system_clock;
using SteadyClock = std::chrono::steady_clock;
using TimePoint = std::chrono::system_clock::time_point;

// Semantic type aliases for basic types
using String = std::string;
using UserName = std::string;
using StringId = std::string;
using ServiceName = std::string;
using IpAddress = std::string; // Generic IP Address
using ClientIp = IpAddress; // Specific use
using ErrorMessage = std::string;
using SecretKey = std::vector<unsigned char>;
using TokenString = std::string;
using SessionId = std::string;
using PasswordHash = std::string;
using Password = std::string;
using Permission = std::string;
using RoleString = std::string;
using EventString = std::string;
using RoleStringView = std::string_view;
using EventStringView = std::string_view;
using SessionIdView = std::string_view;
using ClientIpView = std::string_view;
using DurationString = std::string;
using JwtPayloadString = std::string;
using JwtSignature = std::string;
using JwtHeaderPayload = std::string;
using Bytes = std::vector<unsigned char>;

// Numeric type aliases
using PortNo = uint16_t;
using RateLimit = size_t;
using Threshold = size_t;
using UserCount = size_t;
using SessionCount = size_t;
using AttemptCount = size_t;
using Count = size_t;

// Time duration aliases
using TimeoutDuration = std::chrono::seconds;
using Milliseconds = std::chrono::milliseconds;
using Seconds = std::chrono::seconds;
using Hours = std::chrono::hours;
using Minutes = std::chrono::minutes;

// Semantic type aliases for collections
using Strings = std::vector<std::string>;
template<typename T>
using Roles = std::vector<T>;

// Smart pointer aliases
template<typename T>
using SessionManagerPtr = std::unique_ptr<T>;

// Synchronization aliases
template<typename Mutex>
using LockGuard = std::lock_guard<Mutex>;
template<typename Mutex>
using SharedLock = std::shared_lock<Mutex>;

// Helper functions for Result creation
template<typename T>
constexpr Result<std::decay_t<T>> make_result_success(T&& value) noexcept {
    return std::forward<T>(value);
}

inline constexpr Result<void> make_result_success() noexcept {
    return {};
}

template<typename T, typename E = std::string>
constexpr Result<T, E> make_result_error(E error) noexcept {
    return std::unexpected(std::move(error));
}

// File name aliases
using FilePath = std::string;
using FileName = std::string;
using LogFileName = std::string;
using ConfigFileName = std::string;
using DirectoryPath = std::string;
using FileContent = std::string;
using FileExtension = std::string;

// Config aliases
using ConfigKey = std::string;
using ConfigValue = std::string;
using ConfigKeys = std::vector<ConfigKey>;
using StringArray = std::vector<std::string>;

// TLS aliases
using CertificateData = std::string;
using CipherListString = std::string;

// Network aliases
using RequestString = std::string;
using ResponseString = std::string;
using StatusString = std::string;
using MessageString = std::string;
using ErrorString = std::string;
using EventTypeString = std::string;
using LogDetails = std::string;

// Database-related type aliases
using DbType = std::string;
using ConnectionString = std::string;
using HostAddress = std::string;

// C++23 modern features
template<typename T>
concept ResultTypeConcept = requires(T t) {
    typename T::value_type;
    typename T::error_type;
    { t.has_value() } -> std::convertible_to<bool>;
    { t.value() } -> std::convertible_to<typename T::value_type>;
    { t.error() } -> std::convertible_to<typename T::error_type>;
};

// Modern monadic operations for Result
template<typename T, typename F>
requires std::invocable<F, T>
constexpr auto transform(const Result<T>& result, F&& func) noexcept {
    if (result) {
        return make_result_success(std::invoke(std::forward<F>(func), *result));
    }
    return make_result_error<T>(result.error());
}

template<typename T, typename F>
requires std::invocable<F, T>
constexpr auto and_then(const Result<T>& result, F&& func) noexcept {
    if (result) {
        return std::invoke(std::forward<F>(func), *result);
    }
    return make_result_error<typename std::invoke_result_t<F, T>::value_type>(result.error());
}

// C++23 std::expected utilities
template<typename T>
constexpr bool is_success(const Result<T>& result) noexcept {
    return result.has_value();
}

template<typename T>
constexpr bool is_error(const Result<T>& result) noexcept {
    return !result.has_value();
}

} // namespace zerossg
