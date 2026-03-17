module;

#include <chrono>
#undef EXIT_SUCCESS
#undef EXIT_FAILURE

export module zerossg.constants;

// Type aliases for time and size
export using Seconds = std::chrono::seconds;
export using Milliseconds = std::chrono::milliseconds;
export using Count = std::size_t;

// Configuration file constants
export constexpr const char* DEFAULT_CONFIG_FILE = "config.json";
export constexpr const char* DEFAULT_PERSISTENCE_FILE = "sessions.json";
export constexpr const char* DEFAULT_DB_TYPE = "memory";
export constexpr const char* DEFAULT_CONNECTION_STRING = "localhost:5432/zerossg";
export constexpr const char* DEFAULT_DB_USERNAME = "zerossg";
export constexpr const char* DEFAULT_DB_PASSWORD = "";

// JWT constants
export constexpr size_t JWT_SECRET_SIZE = 32;
export constexpr std::chrono::seconds TOKEN_EXPIRY_TIME{3600}; // 1 hour
export constexpr std::size_t BCRYPT_ROUNDS = 12;
export constexpr std::chrono::seconds SECRET_ROTATION_INTERVAL{86400}; // 24 hours
export constexpr size_t MAX_FAILED_ATTEMPTS = 5;
export constexpr std::chrono::seconds FAILED_ATTEMPT_WINDOW{900}; // 15 minutes

// Database constants
export constexpr Count DEFAULT_CONNECTION_POOL_SIZE = 10;
export constexpr std::chrono::seconds DEFAULT_CONNECTION_TIMEOUT{30};

// Logging constants
export constexpr Count DEFAULT_MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB
export constexpr Count DEFAULT_MAX_FILES = 3;
export constexpr const char* DEFAULT_LOG_LEVEL = "info";
export constexpr const char* DEFAULT_LOG_PATTERN = "[%Y-%m-%d %H:%M:%S.%e] [%l] %v";
export constexpr const char* DEFAULT_LOG_FILE = "logs/zerossg.log";
export constexpr const char* DEFAULT_SECURITY_LOG_FILE = "logs/security.log";
export constexpr const char* DEFAULT_AUDIT_LOG_FILE = "logs/audit.log";

// Error messages
export constexpr const char* ERROR_USER_NOT_FOUND = "User not found";
export constexpr const char* ERROR_USER_ALREADY_EXISTS = "User already exists";
export constexpr const char* ERROR_INVALID_CREDENTIALS = "Invalid credentials";
export constexpr const char* ERROR_TOKEN_EXPIRED = "Token has expired";
export constexpr const char* ERROR_TOKEN_REVOKED = "Token has been revoked";
export constexpr const char* ERROR_TOKEN_INVALID = "Invalid token";
export constexpr const char* ERROR_RATE_LIMIT_EXCEEDED = "Rate limit exceeded";
export constexpr const char* ERROR_BRUTE_FORCE_DETECTED = "Brute force attack detected";
export constexpr const char* ERROR_IP_BLOCKED = "IP address blocked";
export constexpr const char* ERROR_SERVICE_NOT_FOUND = "Service not found";
export constexpr const char* ERROR_ACCESS_DENIED = "Access denied";
export constexpr const char* ERROR_SESSION_NOT_FOUND = "Session not found";
export constexpr const char* ERROR_SESSION_EXPIRED = "Session has expired";
export constexpr const char* ERROR_CONFIG_LOAD_FAILED = "Failed to load configuration";
export constexpr const char* ERROR_CONFIG_SAVE_FAILED = "Failed to save configuration";
export constexpr const char* ERROR_FAILED_TO_LOAD_CONFIG = "Failed to load configuration";
export constexpr const char* ERROR_TLS_INITIALIZATION_FAILED = "TLS initialization failed";
export constexpr const char* ERROR_CERTIFICATE_VERIFICATION_FAILED = "Certificate verification failed";
export constexpr const char* ERROR_USERNAME_PASSWORD_REQUIRED = "Username and password required";
export constexpr const char* ERROR_USER_NOT_FOUND_AFTER_AUTH = "User not found after successful authentication";
export constexpr const char* ERROR_NOT_AUTHENTICATED = "Not authenticated";
export constexpr const char* ERROR_TARGET_SERVICE_REQUIRED = "Target service required";
export constexpr const char* ERROR_NO_ACTIVE_SESSION = "No active session";

// Detailed Error Messages and Prefixes
export constexpr const char* ERROR_CONFIG_FILE_NOT_FOUND = "Configuration file not found: ";
export constexpr const char* ERROR_UNSUPPORTED_CONFIG_FORMAT = "Unsupported configuration format: ";
export constexpr const char* ERROR_TARGET_SERVICE_NOT_FOUND_PREFIX = "Target service not found: ";
export constexpr const char* ERROR_CONFIG_WRITE_OPEN_FAILED_PREFIX = "Failed to open config file for writing: ";
export constexpr const char* ERROR_CONFIG_SAVE_FAILED_PREFIX = "Failed to save config: ";
export constexpr const char* ERROR_YAML_PARSE_PREFIX = "YAML parse error: ";
export constexpr const char* ERROR_YAML_LOAD_PREFIX = "Failed to load YAML config: ";
export constexpr const char* ERROR_CONFIG_OPEN_FAILED_PREFIX = "Failed to open config file: ";
export constexpr const char* ERROR_JSON_PARSE_PREFIX = "JSON parse error: ";
export constexpr const char* ERROR_JSON_LOAD_PREFIX = "Failed to load JSON config: ";
export constexpr const char* ERROR_TARGET_SERVICE_HOST_PORT_MISSING = "Target service host or port missing";
export constexpr const char* ERROR_TARGET_SERVICE_PARSE_FAILED_PREFIX = "Failed to parse target service: ";
export constexpr const char* ERROR_INVALID_LISTEN_ADDRESS = "Invalid listen address: ";
export constexpr const char* ERROR_INVALID_SERVER_PORT = "Invalid server port";
export constexpr const char* ERROR_JWT_SECRET_TOO_SHORT = "JWT secret is too short";
export constexpr const char* ERROR_INVALID_TOKEN_EXPIRY = "Invalid token expiry";
export constexpr const char* ERROR_INVALID_SESSION_TIMEOUT = "Invalid session timeout";
export constexpr const char* ERROR_INVALID_MAX_SESSIONS = "Invalid max sessions";
export constexpr const char* ERROR_INVALID_LOG_LEVEL = "Invalid log level: ";
export constexpr const char* ERROR_INVALID_LOG_MAX_SIZE = "Invalid max log file size";
export constexpr const char* ERROR_INVALID_LOG_MAX_FILES = "Invalid max log files";
export constexpr const char* ERROR_DB_HOST_EMPTY = "Database host is empty";
export constexpr const char* ERROR_INVALID_DB_PORT = "Invalid database port";
export constexpr const char* ERROR_DB_NAME_EMPTY = "Database name is empty";
export constexpr const char* ERROR_TARGET_SERVICE_NAME_EMPTY = "Target service name is empty";
export constexpr const char* ERROR_TARGET_SERVICE_HOST_EMPTY_PREFIX = "Target service host empty: ";
export constexpr const char* ERROR_INVALID_TARGET_SERVICE_PORT_PREFIX = "Invalid target service port: ";
export constexpr const char* ERROR_TARGET_SERVICE_NO_ROLES_PREFIX = "Target service has no allowed roles: ";
export constexpr const char* ERROR_FILE_OPEN_FAILED_PREFIX = "Failed to open file: ";
export constexpr const char* ERROR_FILE_READ_FAILED_PREFIX = "Failed to read file: ";
export constexpr const char* ERROR_FILE_WRITE_OPEN_FAILED_PREFIX = "Failed to open file for writing: ";
export constexpr const char* ERROR_FILE_WRITE_FAILED_PREFIX = "Failed to write file: ";

// Success messages
export constexpr const char* SUCCESS_AUTHENTICATION = "Authentication successful";
export constexpr const char* SUCCESS_LOGOUT = "Logout successful";
export constexpr const char* SUCCESS_SESSION_CREATED = "Session created";
export constexpr const char* SUCCESS_CONFIG_SAVED = "Configuration saved";
export constexpr const char* SUCCESS_TLS_INITIALIZED = "TLS initialized";
export constexpr const char* MESSAGE_LOGIN_SUCCESSFUL = "Login successful";
export constexpr const char* MESSAGE_SESSION_CREATED = "Session created";
export constexpr const char* MESSAGE_PROXY_REQUEST_PROCESSED = "Proxy request processed";
export constexpr const char* MESSAGE_LOGOUT_SUCCESSFUL = "Logout successful";

// JWT claim keys
export constexpr const char* JWT_CLAIM_ISSUER = "iss";
export constexpr const char* JWT_CLAIM_SUBJECT = "sub";
export constexpr const char* JWT_CLAIM_AUDIENCE = "aud";
export constexpr const char* JWT_CLAIM_EXPIRED = "exp";
export constexpr const char* JWT_CLAIM_ISSUED_AT = "iat";
export constexpr const char* JWT_CLAIM_JWT_ID = "jti";
export constexpr const char* JWT_CLAIM_USERNAME = "username";
export constexpr const char* JWT_CLAIM_ROLE = "role";
export constexpr const char* JWT_CLAIM_CLIENT_IP = "client_ip";
export constexpr const char* JWT_CLAIM_TARGET_SERVICE = "target_service";

// JSON protocol constants
export constexpr const char* JSON_KEY_TYPE = "type";
export constexpr const char* JSON_KEY_STATUS = "status";
export constexpr const char* JSON_KEY_MESSAGE = "message";
export constexpr const char* JSON_KEY_DATA = "data";
export constexpr const char* JSON_KEY_TIMESTAMP = "timestamp";
export constexpr const char* JSON_KEY_USERNAME = "username";
export constexpr const char* JSON_KEY_PASSWORD = "password";
export constexpr const char* JSON_KEY_TOKEN = "token";
export constexpr const char* JSON_KEY_USER = "user";
export constexpr const char* JSON_KEY_ROLE = "role";
export constexpr const char* JSON_KEY_TARGET_SERVICE = "target_service";
export constexpr const char* JSON_KEY_SESSION_ID = "session_id";

export constexpr const char* JSON_VALUE_LOGIN = "login";
export constexpr const char* JSON_VALUE_SESSION = "session";
export constexpr const char* JSON_VALUE_PROXY = "proxy";
export constexpr const char* JSON_VALUE_LOGOUT = "logout";
export constexpr const char* JSON_VALUE_SUCCESS = "success";
export constexpr const char* JSON_VALUE_ERROR = "error";
export constexpr const char* JSON_VALUE_PROXY_ACTIVE = "proxy_active";

// HTTP status codes
export constexpr int HTTP_STATUS_OK = 200;
export constexpr int HTTP_STATUS_CREATED = 201;
export constexpr int HTTP_STATUS_BAD_REQUEST = 400;
export constexpr int HTTP_STATUS_UNAUTHORIZED = 401;
export constexpr int HTTP_STATUS_FORBIDDEN = 403;
export constexpr int HTTP_STATUS_NOT_FOUND = 404;
export constexpr int HTTP_STATUS_INTERNAL_SERVER_ERROR = 500;
export constexpr int HTTP_STATUS_SERVICE_UNAVAILABLE = 503;

// HTTP headers
export constexpr const char* HTTP_HEADER_AUTHORIZATION = "Authorization";
export constexpr const char* HTTP_HEADER_CONTENT_TYPE = "Content-Type";
export constexpr const char* HTTP_HEADER_CONTENT_LENGTH = "Content-Length";
export constexpr const char* HTTP_HEADER_USER_AGENT = "User-Agent";
export constexpr const char* HTTP_HEADER_X_FORWARDED_FOR = "X-Forwarded-For";
export constexpr const char* HTTP_HEADER_X_REAL_IP = "X-Real-IP";
export constexpr const char* HTTP_HEADER_X_SESSION_ID = "X-Session-ID";
export constexpr const char* HTTP_HEADER_X_CLIENT_CERT = "X-Client-Cert";

// MIME types
export constexpr const char* MIME_TYPE_JSON = "application/json";
export constexpr const char* MIME_TYPE_XML = "application/xml";
export constexpr const char* MIME_TYPE_TEXT = "text/plain";
export constexpr const char* MIME_TYPE_HTML = "text/html";
export constexpr const char* MIME_TYPE_BINARY = "application/octet-stream";

// Protocol versions
export constexpr const char* HTTP_VERSION_1_1 = "HTTP/1.1";
export constexpr const char* TLS_VERSION_1_2 = "TLSv1.2";
export constexpr const char* TLS_VERSION_1_3 = "TLSv1.3";

// Network constants
export constexpr const char* MESSAGE_DELIMITER = "\n\n";

// Character encodings
export constexpr const char* ENCODING_UTF8 = "UTF-8";
export constexpr const char* ENCODING_BASE64 = "Base64";

// Time formats
export constexpr const char* TIME_FORMAT_ISO_8601 = "%Y-%m-%dT%H:%M:%SZ";
export constexpr const char* TIME_FORMAT_LOG = "%Y-%m-%d %H:%M:%S";
export constexpr const char* TIME_FORMAT_DATE_ONLY = "%Y-%m-%d";

// File extensions
export constexpr const char* FILE_EXTENSION_JSON = ".json";
export constexpr const char* FILE_EXTENSION_XML = ".xml";
export constexpr const char* FILE_EXTENSION_YAML = ".yaml";
export constexpr const char* FILE_EXTENSION_YML = ".yml";
export constexpr const char* FILE_EXTENSION_CRT = ".crt";
export constexpr const char* FILE_EXTENSION_KEY = ".key";
export constexpr const char* FILE_EXTENSION_LOG = ".log";

// Format constants
export constexpr const char* FORMAT_JSON = "json";
export constexpr const char* FORMAT_YAML = "yaml";
export constexpr const char* FORMAT_YML = "yml";

// Configuration Keys
export constexpr const char* CONFIG_KEY_SERVER = "server";
export constexpr const char* CONFIG_KEY_LISTEN_ADDRESS = "listen_address";
export constexpr const char* CONFIG_KEY_LISTEN_PORT = "listen_port";
export constexpr const char* CONFIG_KEY_TLS_CERT_FILE = "tls_cert_file";
export constexpr const char* CONFIG_KEY_TLS_KEY_FILE = "tls_key_file";
export constexpr const char* CONFIG_KEY_CA_CERT_FILE = "ca_cert_file";
export constexpr const char* CONFIG_KEY_THREAD_COUNT = "thread_count";

export constexpr const char* CONFIG_KEY_SECURITY = "security";
export constexpr const char* CONFIG_KEY_JWT_SECRET = "jwt_secret";
export constexpr const char* CONFIG_KEY_TOKEN_EXPIRY_HOURS = "token_expiry_hours";
export constexpr const char* CONFIG_KEY_MAX_LOGIN_ATTEMPTS = "max_login_attempts";
export constexpr const char* CONFIG_KEY_LOCKOUT_DURATION_MINUTES = "lockout_duration_minutes";

export constexpr const char* CONFIG_KEY_SESSION = "session";
export constexpr const char* CONFIG_KEY_TIMEOUT_SECONDS = "timeout_seconds";
export constexpr const char* CONFIG_KEY_MAX_CONCURRENT_SESSIONS = "max_concurrent_sessions";

export constexpr const char* CONFIG_KEY_LOGGING = "logging";
export constexpr const char* CONFIG_KEY_LEVEL = "level";
export constexpr const char* CONFIG_KEY_FILE_PATH = "file_path";
export constexpr const char* CONFIG_KEY_MAX_FILE_SIZE_MB = "max_file_size_mb";
export constexpr const char* CONFIG_KEY_MAX_FILES = "max_files";

export constexpr const char* CONFIG_KEY_DATABASE = "database";
export constexpr const char* CONFIG_KEY_HOST = "host";
export constexpr const char* CONFIG_KEY_PORT = "port";
export constexpr const char* CONFIG_KEY_NAME = "name";
export constexpr const char* CONFIG_KEY_USERNAME = "username";
export constexpr const char* CONFIG_KEY_PASSWORD = "password";
export constexpr const char* CONFIG_KEY_SSL_MODE = "ssl_mode";

export constexpr const char* CONFIG_KEY_TARGET_SERVICES = "target_services";
export constexpr const char* CONFIG_KEY_TLS_ENABLED = "tls_enabled";
export constexpr const char* CONFIG_KEY_ALLOWED_ROLES = "allowed_roles";

// Directory names
export constexpr const char* DIRECTORY_LOGS = "logs";
export constexpr const char* DIRECTORY_CONFIG = "config";
export constexpr const char* DIRECTORY_CERTS = "certs";
export constexpr const char* DIRECTORY_DATA = "data";
export constexpr const char* DIRECTORY_TEMP = "temp";
export constexpr const char* DIRECTORY_BACKUP = "backup";

// Environment variable names
export constexpr const char* ENV_VCPKG_ROOT = "VCPKG_ROOT";
export constexpr const char* ENV_OPENSSL_ROOT_DIR = "OPENSSL_ROOT_DIR";
export constexpr const char* ENV_CONFIG_FILE = "ZEROSSG_CONFIG_FILE";
export constexpr const char* ENV_LOG_LEVEL = "ZEROSSG_LOG_LEVEL";
export constexpr const char* ENV_DEBUG = "ZEROSSG_DEBUG";

// Service names
export constexpr const char* SERVICE_SSH = "ssh";
export constexpr const char* SERVICE_WEB = "web";
export constexpr const char* SERVICE_DATABASE = "database";
export constexpr const char* SERVICE_API = "api";
export constexpr const char* SERVICE_MONITORING = "monitoring";

// Role names
export constexpr const char* ROLE_ADMIN = "admin";
export constexpr const char* ROLE_OPERATOR = "operator";
export constexpr const char* ROLE_VIEWER = "viewer";

// Role enum values
export constexpr int ADMIN = 0;
export constexpr int OPERATOR = 1;
export constexpr int VIEWER = 2;

// Security event types
export constexpr const char* EVENT_LOGIN_SUCCESS = "login_success";
export constexpr const char* EVENT_LOGIN_FAILURE = "login_failure";
export constexpr const char* EVENT_SESSION_START = "session_start";
export constexpr const char* EVENT_SESSION_TERMINATION = "session_termination";
export constexpr const char* EVENT_AUTHENTICATION_ERROR = "authentication_error";
export constexpr const char* EVENT_ACCESS_VIOLATION = "access_violation";
export constexpr const char* EVENT_RATE_LIMIT_EXCEEDED = "rate_limit_exceeded";
export constexpr const char* EVENT_BRUTE_FORCE_DETECTED = "brute_force_detected";

// Permission names
export constexpr const char* PERMISSION_READ = "read";
export constexpr const char* PERMISSION_WRITE = "write";
export constexpr const char* PERMISSION_EXECUTE = "execute";
export constexpr const char* PERMISSION_ADMIN = "admin";

// Service host addresses
export constexpr const char* HOST_SSH_SERVER = "internal-ssh-server";
export constexpr const char* HOST_WEB_SERVER = "internal-web-server";
export constexpr const char* HOST_DB_SERVER = "internal-db-server";

// Service names for default services
export constexpr const char* SERVICE_WEB_ADMIN = "web-admin";
export constexpr const char* SERVICE_SSH_INTERNAL = "ssh";
export constexpr const char* SERVICE_DATABASE_INTERNAL = "database";

// Port numbers
export constexpr const int DEFAULT_SSH_PORT = 22;
export constexpr const int DEFAULT_WEB_PORT = 8080;
export constexpr const int DEFAULT_DATABASE_PORT = 5432;

// CLI commands
export constexpr const char* CMD_START = "start";
export constexpr const char* CMD_STOP = "stop";
export constexpr const char* CMD_STATUS = "status";
export constexpr const char* CMD_RELOAD = "reload";
export constexpr const char* CMD_EXPORT_LOGS = "export-logs";
export constexpr const char* CMD_HELP = "help";
export constexpr const char* CMD_VERSION = "version";

// Exit codes
export constexpr int EXIT_SUCCESS = 0;
export constexpr int EXIT_FAILURE = 1;
export constexpr int EXIT_CONFIG_ERROR = 2;
export constexpr int EXIT_TLS_ERROR = 3;
export constexpr int EXIT_AUTHENTICATION_ERROR = 4;
export constexpr int EXIT_AUTHORIZATION_ERROR = 5;

// Maximum limits
export constexpr size_t MAX_USERNAME_LENGTH = 255;
export constexpr size_t MAX_PASSWORD_LENGTH = 128;
export constexpr size_t MAX_SESSION_ID_LENGTH = 64;
export constexpr size_t MAX_TOKEN_LENGTH = 1024;
export constexpr size_t MAX_FILE_PATH_LENGTH = 4096;
export constexpr size_t MAX_CONFIG_FILE_SIZE = 1024 * 1024; // 1MB
export constexpr size_t MAX_LOG_MESSAGE_LENGTH = 8192;
export constexpr size_t MAX_HEADER_SIZE = 8192;
export constexpr size_t MAX_REQUEST_SIZE = 1024 * 1024; // 1MB
export constexpr size_t MAX_RESPONSE_SIZE = 1024 * 1024; // 1MB

// Timeout values
export constexpr std::chrono::milliseconds NETWORK_TIMEOUT{30000}; // 30 seconds
export constexpr std::chrono::milliseconds TLS_HANDSHAKE_TIMEOUT{10000}; // 10 seconds
export constexpr std::chrono::milliseconds READ_TIMEOUT{60000}; // 1 minute
export constexpr std::chrono::milliseconds WRITE_TIMEOUT{60000}; // 1 minute
export constexpr std::chrono::milliseconds KEEP_ALIVE_TIMEOUT{30000}; // 30 seconds

// Buffer sizes
export constexpr size_t BUFFER_SIZE_SMALL = 1024;
export constexpr size_t BUFFER_SIZE_MEDIUM = 4096;
export constexpr size_t BUFFER_SIZE_LARGE = 8192;
export constexpr size_t BUFFER_SIZE_XLARGE = 16384;

// Thread pool sizes
export constexpr Count MIN_THREAD_COUNT = 1;
export constexpr Count MAX_THREAD_COUNT = 256;
export constexpr Count DEFAULT_THREAD_COUNT = 0; // Auto-detect

// Cache sizes
export constexpr size_t DEFAULT_CACHE_SIZE = 1000;
export constexpr size_t MAX_CACHE_SIZE = 10000;

// Retry configuration
export constexpr Count MAX_RETRY_ATTEMPTS = 3;
export constexpr std::chrono::milliseconds RETRY_DELAY_BASE{1000}; // 1 second
export constexpr std::chrono::milliseconds RETRY_DELAY_MAX{10000}; // 10 seconds

// Health check intervals
export constexpr std::chrono::seconds HEALTH_CHECK_INTERVAL{30}; // 30 seconds
export constexpr std::chrono::seconds HEALTH_CHECK_TIMEOUT{5}; // 5 seconds
