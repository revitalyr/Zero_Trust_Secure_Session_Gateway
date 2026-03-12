export module zerossg.common;

// C++ Standard Library exports
export import <chrono>;
export import <concepts>;
export import <expected>;
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
export using string_view = std::string_view;

template<typename T>
export using unique_ptr = std::unique_ptr<T>;

template<typename T>
export using shared_ptr = std::shared_ptr<T>;

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
export using TimeoutDuration = std::chrono::seconds;
export using Milliseconds = std::chrono::milliseconds;
export using Hours = std::chrono::hours;
export using Minutes = std::chrono::minutes;

// Semantic type aliases for collections
export using Strings = std::vector<std::string>;
template<typename T>
export using Roles = std::vector<T>;

// Semantic type aliases for plural collections
template<typename T>
export using Users = std::vector<T>;
export using Sessions = std::vector<Session>;
export using TargetServices = std::vector<TargetService>;
export using SecurityEvents = std::vector<SecurityEvent>;
export using ConnectionInfos = std::vector<ConnectionInfo>;

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

} // namespace zerossg
