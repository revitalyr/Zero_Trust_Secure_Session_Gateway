module;

#include <boost/asio/ssl.hpp>

export module zerossg.tls.tls_handler;

// Import required modules
import zerossg.interfaces;
import zerossg.logging.logger;
import zerossg.std;
import zerossg.third_party.openssl;

export namespace zerossg {

export class TlsHandler {
public:
    explicit TlsHandler(IoContext& io_context);
    ~TlsHandler();

    Result<void> initialize(const String& cert_file, const String& key_file);
    boost::asio::ssl::context& get_context() noexcept;

private:
    boost::asio::ssl::context m_ssl_context;
    zerossg::IoContext& m_io_context;
    int m_verify_depth;
    zerossg::String m_cipher_list;
    zerossg::String m_tls_cert_file;
    zerossg::String m_tls_key_file;

    zerossg::Result<void> load_certificates();
    zerossg::Result<void> configure_ssl_context();
};

} // namespace zerossg
