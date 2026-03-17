module;

#include <boost/asio/ssl.hpp>

export module zerossg.tls.tls_handler;

// Import required modules
import zerossg.interfaces;
import zerossg.logging.logger;
import zerossg.std;
import zerossg.third_party.openssl;

// Export TlsHandler class
export class zerossg::TlsHandler {
public:
    explicit TlsHandler(zerossg::IoContext& io_context);
    ~TlsHandler();

    zerossg::Result<void> initialize(const zerossg::String& cert_file, const zerossg::String& key_file);
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
