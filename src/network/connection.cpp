module;
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

module zerossg.network.connection;

import zerossg.network.gateway_server;
import zerossg.logging.logger;
import zerossg.std;
import zerossg.constants;
import zerossg.types;

using json = nlohmann::json;

namespace zerossg {

Connection::Connection(GatewayServer& server, IoContext& io_context, SslContext& ssl_context)
    : m_server(server)
    , m_socket(io_context, ssl_context) {
}

Connection::~Connection() {
    stop();
}

void Connection::start() {
    m_client_ip = m_socket.lowest_layer().remote_endpoint().address().to_string();
    do_handshake();
}

void Connection::stop() {
    try {
        if (m_socket.lowest_layer().is_open()) {
            m_socket.lowest_layer().close();
        }
    } catch (...) {
        // Ignore errors during shutdown
    }
    m_server.unregister_connection(shared_from_this());
}

void Connection::do_handshake() {
    m_socket.async_handshake(
        boost::asio::ssl::stream_base::server,
        [self = shared_from_this()](const boost::system::error_code& error) {
            if (!error) {
                self->do_read();
            } else {
                self->m_server.m_logger->error(std::format("Handshake error: {}", error.message()));
            }
        }
    );
}

void Connection::do_read() {
    boost::asio::async_read_until(
        m_socket, m_buffer, zerossg::MESSAGE_DELIMITER,
        [self = shared_from_this()](const boost::system::error_code& error, size_t bytes_transferred) {
            self->handle_read(error, bytes_transferred);
        }
    );
}

void Connection::handle_read(const boost::system::error_code& error, size_t bytes_transferred) {
    if (error) {
        if (error != boost::asio::error::eof) {
            m_server.m_logger->error(std::format("Read error: {}", error.message()));
        }
        return;
    }
    
    std::istream is(&m_buffer);
    std::string request_line;
    std::getline(is, request_line);
    
    handle_request(request_line);
    
    do_read();
}

void Connection::handle_request(const RequestString& request) {
    try {
        const json request_json = json::parse(request);
        const String request_type = request_json.value(zerossg::JSON_KEY_TYPE, "");
        
        String response;
        
        if (request_type == zerossg::JSON_VALUE_LOGIN) {
            response = process_login_request(request);
        } else if (request_type == zerossg::JSON_VALUE_SESSION) {
            response = process_session_request(request);
        } else if (request_type == zerossg::JSON_VALUE_PROXY) {
            response = process_proxy_request(request);
        } else if (request_type == zerossg::JSON_VALUE_LOGOUT) {
            response = process_logout_request(request);
        } else {
            response = create_error_response(std::format("Unknown request type: {}", request_type));
        }
        
        do_write(response + zerossg::MESSAGE_DELIMITER);
    } catch (const json::exception& e) {
        do_write(create_error_response(std::format("Invalid JSON: {}", e.what())) + zerossg::MESSAGE_DELIMITER);
    } catch (const std::exception& e) {
        do_write(create_error_response(std::format("Request processing error: {}", e.what())) + zerossg::MESSAGE_DELIMITER);
    }
}

ResponseString Connection::process_login_request(const RequestString& request) {
    json request_json = json::parse(request);
    String username = request_json.value(zerossg::JSON_KEY_USERNAME, "");
    String password = request_json.value(zerossg::JSON_KEY_PASSWORD, "");
    
    if (username.empty() || password.empty()) {
        return create_error_response(zerossg::ERROR_USERNAME_PASSWORD_REQUIRED);
    }
    
    auto rate_limit_result = m_server.m_security_manager->check_rate_limit(m_client_ip);
    if (!rate_limit_result.is_success() || !rate_limit_result.value()) {
        return create_error_response(zerossg::ERROR_RATE_LIMIT_EXCEEDED);
    }
    
    auto auth_result = m_server.m_auth_manager->authenticate(username, password);
    if (!auth_result.is_success()) {
        m_server.m_security_manager->record_failed_attempt(m_client_ip);
        return create_error_response(std::format("Authentication failed: {}", auth_result.error()));
    }
    
    m_server.m_security_manager->record_successful_login(m_client_ip);
    
    auto user_result = m_server.m_auth_manager->get_user(username);
    if (!user_result.is_success() || !user_result.value().has_value()) {
        return create_error_response(zerossg::ERROR_USER_NOT_FOUND_AFTER_AUTH);
    }
    
    m_user = user_result.value().value();
    m_authenticated = true;
    
    String token = auth_result.value();
    
    json response_data = {
        {zerossg::JSON_KEY_TOKEN, token},
        {zerossg::JSON_KEY_USER, {
            {zerossg::JSON_KEY_USERNAME, m_user.user_name()},
            {zerossg::JSON_KEY_ROLE, role_to_string(m_user.role())}
        }}
    };
    
    return create_response(zerossg::JSON_VALUE_SUCCESS, zerossg::MESSAGE_LOGIN_SUCCESSFUL, response_data);
}

ResponseString Connection::process_session_request(const RequestString& request) {
    if (!m_authenticated) {
        return create_error_response(zerossg::ERROR_NOT_AUTHENTICATED);
    }
    
    json request_json = json::parse(request);
    String target_service = request_json.value(zerossg::JSON_KEY_TARGET_SERVICE, "");
    
    if (target_service.empty()) {
        return create_error_response(zerossg::ERROR_TARGET_SERVICE_REQUIRED);
    }
    
    auto authz_result = m_server.m_authz_manager->can_access_service(m_user, target_service);
    if (!authz_result.is_success() || !authz_result.value()) {
        return create_error_response(std::format("Access denied to service: {}", target_service));
    }
    
    auto session_result = m_server.m_session_manager->create_session(m_user, m_client_ip, target_service);
    if (!session_result.is_success()) {
        return create_error_response(std::format("Session creation failed: {}", session_result.error()));
    }
    
    m_session_id = session_result.value();
    
    json response_data = {
        {zerossg::JSON_KEY_SESSION_ID, m_session_id},
        {zerossg::JSON_KEY_TARGET_SERVICE, target_service}
    };
    
    return create_response(zerossg::JSON_VALUE_SUCCESS, zerossg::MESSAGE_SESSION_CREATED, response_data);
}

ResponseString Connection::process_proxy_request(const RequestString& request) {
    if (!m_authenticated || m_session_id.empty()) {
        return create_error_response(zerossg::ERROR_NO_ACTIVE_SESSION);
    }
    
    json response_data = {
        {zerossg::JSON_KEY_SESSION_ID, m_session_id},
        {zerossg::JSON_KEY_STATUS, zerossg::JSON_VALUE_PROXY_ACTIVE}
    };
    
    return create_response(zerossg::JSON_VALUE_SUCCESS, zerossg::MESSAGE_PROXY_REQUEST_PROCESSED, response_data);
}

ResponseString Connection::process_logout_request(const RequestString& request) {
    if (!m_authenticated) {
        return create_error_response(zerossg::ERROR_NOT_AUTHENTICATED);
    }
    
    if (!m_session_id.empty()) {
        m_server.m_session_manager->terminate_session(m_session_id);
        m_session_id.clear();
    }
    
    m_authenticated = false;
    
    return create_response(zerossg::JSON_VALUE_SUCCESS, zerossg::MESSAGE_LOGOUT_SUCCESSFUL);
}

void Connection::do_write(const ResponseString& response) {
    boost::asio::async_write(
        m_socket, boost::asio::buffer(response),
        [self = shared_from_this()](const boost::system::error_code& error, size_t) {
            if (error) {
                self->m_server.m_logger->error(std::format("Write error: {}", error.message()));
            }
        }
    );
}

ResponseString Connection::create_response(const StatusString& status, const MessageString& message, const json& data) {
    json response = {
        {zerossg::JSON_KEY_STATUS, status},
        {zerossg::JSON_KEY_MESSAGE, message},
        {zerossg::JSON_KEY_TIMESTAMP, std::chrono::duration_cast<std::chrono::seconds>(
            SystemClock::now().time_since_epoch()).count()}
    };
    
    if (!data.empty()) {
        response[zerossg::JSON_KEY_DATA] = data;
    }
    
    return response.dump();
}

ResponseString Connection::create_error_response(const ErrorString& error) {
    return create_response(zerossg::JSON_VALUE_ERROR, error);
}

void Connection::log_connection_event(const EventTypeString& event_type, const LogDetails& details) {
    m_server.m_logger->info(std::format("[{}] {}: {}", event_type, m_client_ip, details));
}

} // namespace zerossg