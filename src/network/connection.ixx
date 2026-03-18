export module zerossg.network.connection;

import zerossg.common;
import zerossg.types;
import zerossg.third_party.nlohmann_json;

export namespace zerossg {

// Forward declaration to break circular dependency
class GatewayServer;

export class Connection : public std::enable_shared_from_this<Connection> {
public:
    Connection(GatewayServer& server, IoContext& io_context, SslContext& ssl_context);
    ~Connection();

    void start();
    void stop();

    // Socket is public for GatewayServer to use in async_accept
    SslStream m_socket;

private:
    void do_handshake();
    void do_read();
    void handle_read(const boost::system::error_code& error, size_t bytes_transferred);
    void handle_request(const RequestString& request);
    void do_write(const ResponseString& response);

    ResponseString process_login_request(const RequestString& request);
    ResponseString process_session_request(const RequestString& request);
    ResponseString process_proxy_request(const RequestString& request);
    ResponseString process_logout_request(const RequestString& request);

    ResponseString create_response(const StatusString& status, const MessageString& message, const nlohmann::json& data = {});
    ResponseString create_error_response(const ErrorString& error);

    void log_connection_event(const EventTypeString& event_type, const LogDetails& details);

    GatewayServer& m_server;
    boost::asio::streambuf m_buffer;
    ClientIp m_client_ip;
    bool m_authenticated{false};
    SessionId m_session_id;
    User m_user;
};

// Alias for shared_ptr to Connection
using ConnectionPtr = SharedPtr<Connection>;

} // namespace zerossg