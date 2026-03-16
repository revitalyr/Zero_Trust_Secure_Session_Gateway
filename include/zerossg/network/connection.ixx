export module zerossg.network.connection;

export import zerossg.interfaces;
export import zerossg.std;
export import zerossg.third_party.openssl;

export namespace zerossg {

export class Connection : public std::enable_shared_from_this<Connection> {
public:
    Connection(IoContext& io_context, SslContext& ssl_context);
    ~Connection() = default;

    void start();
    void stop();
    
    bool is_active() const { return m_active; }
    String get_client_ip() const { return m_client_ip; }
    TimePoint get_start_time() const { return m_start_time; }

private:
    void do_handshake();
    void do_read();
    void do_write(const String& response);
    
    void handle_handshake(const ErrorCode& error);
    void handle_read(const ErrorCode& error, size_t bytes_transferred);
    void handle_write(const ErrorCode& error);

    SslStream m_socket;
    bool m_active = false;
    String m_client_ip;
    TimePoint m_start_time;
    String m_buffer;
    static constexpr size_t MAX_BUFFER_SIZE = 8192;
};

} // namespace zerossg
