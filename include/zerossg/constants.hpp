#pragma once

// Project headers
#include "common.hpp"

// C++ Standard Library headers
#include <chrono>
#include <cstdint>
#include <string>

namespace zerossg {

// Application constants
constexpr const char* APPLICATION_NAME = "Zero Trust Secure Session Gateway";
constexpr const char* APPLICATION_VERSION = "1.0.0";
constexpr const char* VENDOR_NAME = "ZeroTrust Security";

// Network constants
constexpr const char* DEFAULT_LISTEN_ADDRESS = "0.0.0.0";
constexpr PortNumber DEFAULT_LISTEN_PORT = 8443;
constexpr const char* DEFAULT_TLS_CERT_FILE = "server.crt";
constexpr const char* DEFAULT_TLS_KEY_FILE = "server.key";
constexpr const char* DEFAULT_CA_CERT_FILE = "";
constexpr const char* DEFAULT_CIPHER_LIST = "HIGH:!aNULL:!MD5:!RC4";

// Security constants
constexpr RateLimit DEFAULT_RATE_LIMIT_MAX_REQUESTS = 100;
constexpr Minutes DEFAULT_RATE_LIMIT_WINDOW = 5; // 5 minutes
constexpr Threshold DEFAULT_BRUTE_FORCE_THRESHOLD = 5;
constexpr Minutes DEFAULT_BRUTE_FORCE_WINDOW = 15; // 15 minutes
constexpr Milliseconds DEFAULT_BLOCK_DURATION{3600000}; // 1 hour
constexpr Hours DEFAULT_SECRET_ROTATION_INTERVAL = 24; // 24 hours

// Session constants
constexpr Hours DEFAULT_SESSION_TIMEOUT = 1; // 1 hour
constexpr SessionCount DEFAULT_MAX_SESSIONS_PER_USER = 5;
constexpr Minutes DEFAULT_CLEANUP_INTERVAL = 5; // 5 minutes

// JWT constants
constexpr size_t JWT_SECRET_SIZE = 32;
constexpr Seconds TOKEN_EXPIRY_TIME = 3600; // 1 hour
constexpr std::size_t BCRYPT_ROUNDS = 12;
constexpr Seconds SECRET_ROTATION_INTERVAL = 86400; // 24 hours
constexpr size_t MAX_FAILED_ATTEMPTS = 5;
constexpr Seconds FAILED_ATTEMPT_WINDOW = 900; // 15 minutes

// Database constants
constexpr Count DEFAULT_CONNECTION_POOL_SIZE = 10;
constexpr Seconds DEFAULT_CONNECTION_TIMEOUT = 30;

// Logging constants
constexpr Count DEFAULT_MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB
constexpr Count DEFAULT_MAX_FILES = 3;
constexpr const char* DEFAULT_LOG_LEVEL = "info";
constexpr const char* DEFAULT_LOG_PATTERN = "[%Y-%m-%d %H:%M:%S.%e] [%l] %v";
constexpr const char* DEFAULT_LOG_FILE = "logs/zerossg.log";
constexpr const char* DEFAULT_SECURITY_LOG_FILE = "logs/security.log";
constexpr const char* DEFAULT_AUDIT_LOG_FILE = "logs/audit.log";

// Configuration file constants
constexpr const char* DEFAULT_CONFIG_FILE = "config.json";
constexpr const char* DEFAULT_PERSISTENCE_FILE = "sessions.json";
constexpr const char* DEFAULT_DB_TYPE = "memory";
constexpr const char* DEFAULT_CONNECTION_STRING = "localhost:5432/zerossg";
constexpr const char* DEFAULT_DB_USERNAME = "zerossg";
constexpr const char* DEFAULT_DB_PASSWORD = "";

// Error messages
constexpr const char* ERROR_USER_NOT_FOUND = "User not found";
constexpr const char* ERROR_USER_ALREADY_EXISTS = "User already exists";
constexpr const char* ERROR_INVALID_CREDENTIALS = "Invalid credentials";
constexpr const char* ERROR_TOKEN_EXPIRED = "Token has expired";
constexpr const char* ERROR_TOKEN_REVOKED = "Token has been revoked";
constexpr const char* ERROR_TOKEN_INVALID = "Invalid token";
constexpr const char* ERROR_RATE_LIMIT_EXCEEDED = "Rate limit exceeded";
constexpr const char* ERROR_BRUTE_FORCE_DETECTED = "Brute force attack detected";
constexpr const char* ERROR_IP_BLOCKED = "IP address blocked";
constexpr const char* ERROR_SERVICE_NOT_FOUND = "Service not found";
constexpr const char* ERROR_ACCESS_DENIED = "Access denied";
constexpr const char* ERROR_SESSION_NOT_FOUND = "Session not found";
constexpr const char* ERROR_SESSION_EXPIRED = "Session has expired";
constexpr const char* ERROR_CONFIG_LOAD_FAILED = "Failed to load configuration";
constexpr const char* ERROR_CONFIG_SAVE_FAILED = "Failed to save configuration";
constexpr const char* ERROR_TLS_INITIALIZATION_FAILED = "TLS initialization failed";
constexpr const char* ERROR_CERTIFICATE_VERIFICATION_FAILED = "Certificate verification failed";

// Success messages
constexpr const char* SUCCESS_AUTHENTICATION = "Authentication successful";
constexpr const char* SUCCESS_LOGOUT = "Logout successful";
constexpr const char* SUCCESS_SESSION_CREATED = "Session created";
constexpr const char* SUCCESS_CONFIG_SAVED = "Configuration saved";
constexpr const char* SUCCESS_TLS_INITIALIZED = "TLS initialized";

// JWT claim keys
constexpr const char* JWT_CLAIM_ISSUER = "iss";
constexpr const char* JWT_CLAIM_SUBJECT = "sub";
constexpr const char* JWT_CLAIM_AUDIENCE = "aud";
constexpr const char* JWT_CLAIM_EXPIRED = "exp";
constexpr const char* JWT_CLAIM_ISSUED_AT = "iat";
constexpr const char* JWT_CLAIM_JWT_ID = "jti";
constexpr const char* JWT_CLAIM_USERNAME = "username";
constexpr const char* JWT_CLAIM_ROLE = "role";
constexpr const char* JWT_CLAIM_CLIENT_IP = "client_ip";
constexpr const char* JWT_CLAIM_TARGET_SERVICE = "target_service";

// HTTP status codes
constexpr int HTTP_STATUS_OK = 200;
constexpr int HTTP_STATUS_CREATED = 201;
constexpr int HTTP_STATUS_BAD_REQUEST = 400;
constexpr int HTTP_STATUS_UNAUTHORIZED = 401;
constexpr int HTTP_STATUS_FORBIDDEN = 403;
constexpr int HTTP_STATUS_NOT_FOUND = 404;
constexpr int HTTP_STATUS_INTERNAL_SERVER_ERROR = 500;
constexpr int HTTP_STATUS_SERVICE_UNAVAILABLE = 503;

// HTTP headers
constexpr const char* HTTP_HEADER_AUTHORIZATION = "Authorization";
constexpr const char* HTTP_HEADER_CONTENT_TYPE = "Content-Type";
constexpr const char* HTTP_HEADER_CONTENT_LENGTH = "Content-Length";
constexpr const char* HTTP_HEADER_USER_AGENT = "User-Agent";
constexpr const char* HTTP_HEADER_X_FORWARDED_FOR = "X-Forwarded-For";
constexpr const char* HTTP_HEADER_X_REAL_IP = "X-Real-IP";
constexpr const char* HTTP_HEADER_X_SESSION_ID = "X-Session-ID";
constexpr const char* HTTP_HEADER_X_CLIENT_CERT = "X-Client-Cert";

// MIME types
constexpr const char* MIME_TYPE_JSON = "application/json";
constexpr const char* MIME_TYPE_XML = "application/xml";
constexpr const char* MIME_TYPE_TEXT = "text/plain";
constexpr const char* MIME_TYPE_HTML = "text/html";
constexpr const char* MIME_TYPE_BINARY = "application/octet-stream";

// Protocol versions
constexpr const char* HTTP_VERSION_1_1 = "HTTP/1.1";
constexpr const char* TLS_VERSION_1_2 = "TLSv1.2";
constexpr const char* TLS_VERSION_1_3 = "TLSv1.3";

// Character encodings
constexpr const char* ENCODING_UTF8 = "UTF-8";
constexpr const char* ENCODING_BASE64 = "Base64";

// Time formats
constexpr const char* TIME_FORMAT_ISO_8601 = "%Y-%m-%dT%H:%M:%SZ";
constexpr const char* TIME_FORMAT_LOG = "%Y-%m-%d %H:%M:%S";
constexpr const char* TIME_FORMAT_DATE_ONLY = "%Y-%m-%d";

// File extensions
constexpr const char* FILE_EXTENSION_JSON = ".json";
constexpr const char* FILE_EXTENSION_XML = ".xml";
constexpr const char* FILE_EXTENSION_YAML = ".yaml";
constexpr const char* FILE_EXTENSION_YML = ".yml";
constexpr const char* FILE_EXTENSION_CRT = ".crt";
constexpr const char* FILE_EXTENSION_KEY = ".key";
constexpr const char* FILE_EXTENSION_LOG = ".log";

// Directory names
constexpr const char* DIRECTORY_LOGS = "logs";
constexpr const char* DIRECTORY_CONFIG = "config";
constexpr const char* DIRECTORY_CERTS = "certs";
constexpr const char* DIRECTORY_DATA = "data";
constexpr const char* DIRECTORY_TEMP = "temp";
constexpr const char* DIRECTORY_BACKUP = "backup";

// Environment variable names
constexpr const char* ENV_VCPKG_ROOT = "VCPKG_ROOT";
constexpr const char* ENV_OPENSSL_ROOT_DIR = "OPENSSL_ROOT_DIR";
constexpr const char* ENV_CONFIG_FILE = "ZEROSSG_CONFIG_FILE";
constexpr const char* ENV_LOG_LEVEL = "ZEROSSG_LOG_LEVEL";
constexpr const char* ENV_DEBUG = "ZEROSSG_DEBUG";

// Service names
constexpr const char* SERVICE_SSH = "ssh";
constexpr const char* SERVICE_WEB = "web";
constexpr const char* SERVICE_DATABASE = "database";
constexpr const char* SERVICE_API = "api";
constexpr const char* SERVICE_MONITORING = "monitoring";

// Role names
constexpr const char* ROLE_ADMIN = "admin";
constexpr const char* ROLE_OPERATOR = "operator";
constexpr const char* ROLE_VIEWER = "viewer";

// Security event types
constexpr const char* EVENT_LOGIN_SUCCESS = "login_success";
constexpr const char* EVENT_LOGIN_FAILURE = "login_failure";
constexpr const char* EVENT_SESSION_START = "session_start";
constexpr const char* EVENT_SESSION_TERMINATION = "session_termination";
constexpr const char* EVENT_AUTHENTICATION_ERROR = "authentication_error";
constexpr const char* EVENT_ACCESS_VIOLATION = "access_violation";
constexpr const char* EVENT_RATE_LIMIT_EXCEEDED = "rate_limit_exceeded";
constexpr const char* EVENT_BRUTE_FORCE_DETECTED = "brute_force_detected";

// Permission names
constexpr const char* PERMISSION_READ = "read";
constexpr const char* PERMISSION_WRITE = "write";
constexpr const char* PERMISSION_EXECUTE = "execute";
constexpr const char* PERMISSION_ADMIN = "admin";

// CLI commands
constexpr const char* CMD_START = "start";
constexpr const char* CMD_STOP = "stop";
constexpr const char* CMD_STATUS = "status";
constexpr const char* CMD_RELOAD = "reload";
constexpr const char* CMD_EXPORT_LOGS = "export-logs";
constexpr const char* CMD_HELP = "help";
constexpr const char* CMD_VERSION = "version";

// Exit codes
constexpr int EXIT_SUCCESS = 0;
constexpr int EXIT_FAILURE = 1;
constexpr int EXIT_CONFIG_ERROR = 2;
constexpr int EXIT_TLS_ERROR = 3;
constexpr int EXIT_AUTHENTICATION_ERROR = 4;
constexpr int EXIT_AUTHORIZATION_ERROR = 5;

// Maximum limits
constexpr size_t MAX_USERNAME_LENGTH = 255;
constexpr size_t MAX_PASSWORD_LENGTH = 128;
constexpr size_t MAX_SESSION_ID_LENGTH = 64;
constexpr size_t MAX_TOKEN_LENGTH = 1024;
constexpr size_t MAX_FILE_PATH_LENGTH = 4096;
constexpr size_t MAX_CONFIG_FILE_SIZE = 1024 * 1024; // 1MB
constexpr size_t MAX_LOG_MESSAGE_LENGTH = 8192;
constexpr size_t MAX_HEADER_SIZE = 8192;
constexpr size_t MAX_REQUEST_SIZE = 1024 * 1024; // 1MB
constexpr size_t MAX_RESPONSE_SIZE = 1024 * 1024; // 1MB

// Timeout values
constexpr Milliseconds NETWORK_TIMEOUT{30000}; // 30 seconds
constexpr Milliseconds TLS_HANDSHAKE_TIMEOUT{10000}; // 10 seconds
constexpr Milliseconds READ_TIMEOUT{60000}; // 1 minute
constexpr Milliseconds WRITE_TIMEOUT{60000}; // 1 minute
constexpr Milliseconds KEEP_ALIVE_TIMEOUT{30000}; // 30 seconds

// Buffer sizes
constexpr size_t BUFFER_SIZE_SMALL = 1024;
constexpr size_t BUFFER_SIZE_MEDIUM = 4096;
constexpr size_t BUFFER_SIZE_LARGE = 8192;
constexpr size_t BUFFER_SIZE_XLARGE = 16384;

// Thread pool sizes
constexpr Count MIN_THREAD_COUNT = 1;
constexpr Count MAX_THREAD_COUNT = 256;
constexpr Count DEFAULT_THREAD_COUNT = 0; // Auto-detect

// Cache sizes
constexpr size_t DEFAULT_CACHE_SIZE = 1000;
constexpr size_t MAX_CACHE_SIZE = 10000;

// Retry configuration
constexpr Count MAX_RETRY_ATTEMPTS = 3;
constexpr Milliseconds RETRY_DELAY_BASE{1000}; // 1 second
constexpr Milliseconds RETRY_DELAY_MAX{10000}; // 10 seconds

// Health check intervals
constexpr Seconds HEALTH_CHECK_INTERVAL{30}; // 30 seconds
constexpr Seconds HEALTH_CHECK_TIMEOUT{5}; // 5 seconds

// Metrics collection intervals
constexpr Seconds METRICS_COLLECTION_INTERVAL{60}; // 1 minute
constexpr Seconds STATISTICS_UPDATE_INTERVAL{300}; // 5 minutes

} // namespace zerossg
