export module zerossg.common;

// C++23 Standard Library exports
export import <chrono>;
export import <concepts>;
export import <expected>;
export import <generator>;
export import <memory>;
export import <mutex>;
export import <optional>;
export import <string>;
export import <string_view>;
export import <unordered_map>;
export import <variant>;
export import <vector>;

// Boost exports
export import <boost/asio.hpp>;
export import <boost/asio/ssl.hpp>;

export namespace zerossg {

// Modern C++26 type aliases with semantic naming
export using stringView = std::string_view;

template<typename T>
export using uniquePtr = std::unique_ptr<T>;

template<typename T>
export using sharedPtr = std::shared_ptr<T>;

template<typename T>
export using weakPtr = std::weak_ptr<T>;

template<typename T>
export using vector = std::vector<T>;

template<typename K, typename V>
export using unorderedMap = std::unordered_map<K, V>;

export using systemClock = std::chrono::system_clock;
export using steadyClock = std::chrono::steady_clock;
export using milliseconds = std::chrono::milliseconds;
export using seconds = std::chrono::seconds;

// Semantic type aliases for basic types
export using UserName = std::string;
export using StringId = std::string;
export using ServiceName = std::string;
export using ClientIp = std::string;
export using ErrorMessage = std::string;
export using SecretKey = std::vector<unsigned char>;
export using TokenString = std::string;
export using SessionId = std::string;
export using PasswordHash = std::string;
export using Password = std::string;

// Numeric type aliases
export using PortNo = uint16_t;
export using RateLimit = size_t;
export using Threshold = size_t;
export using UserCount = size_t;
export using SessionCount = size_t;
export using AttemptCount = size_t;
export using Count = size_t;

// Time duration aliases
export using timeoutDuration = std::chrono::seconds;
export using milliseconds = std::chrono::milliseconds;
export using hours = std::chrono::hours;
export using minutes = std::chrono::minutes;

// Semantic type aliases for collections
export using strings = std::vector<std::string>;
template<typename T>
export using roles = std::vector<T>;

// Semantic type aliases for plural collections
template<typename T>
export using users = std::vector<T>;
export using sessions = std::vector<Session>;
export using targetServices = std::vector<TargetService>;
export using securityEvents = std::vector<SecurityEvent>;
export using connectionInfos = std::vector<ConnectionInfo>;

// Smart pointer aliases
template<typename T>
export using SessionManagerPtr = std::unique_ptr<T>;

// Network type aliases
export using TcpEndpoint = boost::asio::ip::tcp::endpoint;
export using SslContext = boost::asio::ssl::context;
export using SslStream = boost::asio::ssl::stream<boost::asio::ip::tcp::socket>;
export using TcpSocket = boost::asio::ip::tcp::socket;
export using TcpAcceptor = boost::asio::ip::tcp::acceptor;
export using IoContext = boost::asio::io_context;

// SSL verification type aliases
export using SslVerifyMode = boost::asio::ssl::verify_mode;
export using SslVerifyContext = boost::asio::ssl::verify_context;

// Synchronization aliases
template<typename Mutex>
export using LockGuard = std::lock_guard<Mutex>;

// Modern expected-based error handling (C++23)
export template<typename T>
using Result = std::expected<T, std::string>;

// Helper functions for Result creation
export template<typename T>
constexpr Result<T> make_result_success(T&& value) noexcept {
    return Result<T>{std::forward<T>(value)};
}

export template<typename T>
constexpr Result<T> make_result_error(std::string error) noexcept {
    return std::unexpected<T>(std::move(error));
}

// Specialization for void using std::expected
export using ResultVoid = std::expected<void, std::string>;

export inline constexpr ResultVoid make_result_success() noexcept {
    return ResultVoid{};
}

export inline constexpr ResultVoid make_result_error(std::string error) noexcept {
    return std::unexpected<void>(std::move(error));
}

// File name aliases
export using FileName = std::string;
export using LogFileName = std::string;
export using ConfigFileName = std::string;

// Database-related type aliases
export using DbType = std::string;
export using ConnectionString = std::string;
export using HostAddress = std::string;

// C++23 modern features
export template<typename T>
concept ResultType = requires(T t) {
    typename T::value_type;
    typename T::error_type;
    { t.has_value() } -> std::convertible_to<bool>;
    { t.value() } -> std::convertible_to<typename T::value_type>;
    { t.error() } -> std::convertible_to<typename T::error_type>;
};

// Modern monadic operations for Result
export template<typename T, typename F>
requires std::invocable<F, T>
constexpr auto transform(const Result<T>& result, F&& func) noexcept {
    if (result) {
        return make_result_success(std::invoke(std::forward<F>(func), *result));
    }
    return make_result_error<T>(result.error());
}

export template<typename T, typename F>
requires std::invocable<F, T>
constexpr auto and_then(const Result<T>& result, F&& func) noexcept {
    if (result) {
        return std::invoke(std::forward<F>(func), *result);
    }
    return make_result_error<typename std::invoke_result_t<F, T>::value_type>(result.error());
}

// C++23 std::expected utilities
export template<typename T>
constexpr bool is_success(const Result<T>& result) noexcept {
    return result.has_value();
}

export template<typename T>
constexpr bool is_error(const Result<T>& result) noexcept {
    return !result.has_value();
}

} // namespace zerossg
