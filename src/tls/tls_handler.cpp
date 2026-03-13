module zerossg.tls.tls_handler;

import zerossg.interfaces;
import zerossg.logging.logger;
import zerossg.result;
import zerossg.std;
import zerossg.third_party.openssl;

namespace zerossg {

TlsHandler::TlsHandler(IoContext& io_context)
    : m_ssl_context(boost::asio::ssl::context::tlsv12_server)
    , m_io_context(io_context)
    , m_verify_depth(9)
    , m_cipher_list(zerossg::DEFAULT_CIPHER_LIST) {
    
    // Set default options
    m_ssl_context.set_options(
        boost::asio::ssl::context::default_workarounds |
        boost::asio::ssl::context::no_sslv2 |
        boost::asio::ssl::context::no_sslv3 |
        boost::asio::ssl::context::single_dh_use
    );
    
    // Set verification mode to none by default (can be overridden)
    m_ssl_context.set_verify_mode(boost::asio::ssl::verify_none);
}

TlsHandler::~TlsHandler() = default;

zerossg::Result<void> TlsHandler::initialize(const zerossg::FilePath& cert_file, const zerossg::FilePath& key_file) {
    try {
        // Load certificate chain
        auto cert_result = load_certificate_chain(cert_file);
        if (!cert_result.is_success()) {
            return make_result_error(std::format("{}{}", zerossg::ERROR_TLS_CERT_LOAD_FAILED_PREFIX, cert_result.error()));
        }
        
        // Load private key
        auto key_result = load_private_key(key_file);
        if (!key_result.is_success()) {
            return make_result_error(std::format("{}{}", zerossg::ERROR_TLS_KEY_LOAD_FAILED_PREFIX, key_result.error()));
        }
        
        // Set cipher list
        if (!m_cipher_list.empty()) {
            if (SSL_CTX_set_cipher_list(m_ssl_context.native_handle(), m_cipher_list.c_str()) != 1) {
                return make_result_error(zerossg::ERROR_TLS_SET_CIPHER_LIST_FAILED);
            }
        }
        
        // Set verification depth
        SSL_CTX_set_verify_depth(m_ssl_context.native_handle(), m_verify_depth);
        
        return make_result_success();
    } catch (const std::exception& e) {
        return make_result_error(std::format("{}{}", zerossg::ERROR_TLS_INIT_FAILED_PREFIX, e.what()));
    }
}

zerossg::SslContext& TlsHandler::get_context() {
    return m_ssl_context;
}

zerossg::Result<bool> TlsHandler::verify_certificate(const zerossg::CertificateData& cert_data) {
    try {
        // Create a memory BIO for the certificate data
        BIO* bio = BIO_new_mem_buf(cert_data.data(), static_cast<int>(cert_data.size()));
        if (!bio) {
            return make_result_error<bool>(zerossg::ERROR_TLS_BIO_CREATION_FAILED);
        }
        
        // Load certificate
        X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
        
        if (!cert) {
            return make_result_error<bool>(zerossg::ERROR_TLS_CERT_PARSE_FAILED);
        }
        
        // Basic validation checks
        int result = X509_check_cert(cert);
        X509_free(cert);
        
        return make_result_success(result == 1);
    } catch (const std::exception& e) {
        return make_result_error<bool>(std::format("{}{}", zerossg::ERROR_TLS_CERT_VERIFY_FAILED_PREFIX, e.what()));
    }
}

zerossg::Result<void> TlsHandler::load_certificate_chain(const zerossg::FilePath& cert_file) {
    auto validation_result = validate_certificate_file(cert_file);
    if (!validation_result.is_success()) {
        return validation_result;
    }
    
    try {
        m_ssl_context.use_certificate_chain_file(cert_file);
        return make_result_success();
    } catch (const std::exception& e) {
        return make_result_error(std::format("{}{}", zerossg::ERROR_TLS_CERT_CHAIN_LOAD_FAILED_PREFIX, e.what()));
    }
}

zerossg::Result<void> TlsHandler::load_private_key(const zerossg::FilePath& key_file) {
    auto validation_result = validate_key_file(key_file);
    if (!validation_result.is_success()) {
        return validation_result;
    }
    
    try {
        m_ssl_context.use_private_key_file(key_file, boost::asio::ssl::context::pem);
        return make_result_success();
    } catch (const std::exception& e) {
        return make_result_error(std::format("{}{}", zerossg::ERROR_TLS_KEY_LOAD_FAILED_PREFIX, e.what()));
    }
}

zerossg::Result<void> TlsHandler::set_verify_mode(zerossg::SslVerifyMode mode) {
    try {
        m_ssl_context.set_verify_mode(mode);
        if (mode != boost::asio::ssl::verify_none) {
            m_ssl_context.set_verify_callback(verify_certificate_callback);
        }
        return make_result_success();
    } catch (const std::exception& e) {
        return make_result_error(std::format("{}{}", zerossg::ERROR_TLS_SET_VERIFY_MODE_FAILED_PREFIX, e.what()));
    }
}

zerossg::Result<void> TlsHandler::add_ca_certificate(const zerossg::FilePath& ca_file) {
    try {
        m_ssl_context.load_verify_file(ca_file);
        return make_result_success();
    } catch (const std::exception& e) {
        return make_result_error(std::format("{}{}", zerossg::ERROR_TLS_CA_CERT_LOAD_FAILED_PREFIX, e.what()));
    }
}

void TlsHandler::set_verify_depth(int depth) {
    m_verify_depth = depth;
    SSL_CTX_set_verify_depth(m_ssl_context.native_handle(), depth);
}

void TlsHandler::set_cipher_list(const zerossg::CipherListString& cipher_list) {
    m_cipher_list = cipher_list;
}

bool TlsHandler::verify_certificate_callback(bool preverified, zerossg::SslVerifyContext& ctx) {
    // This is a simplified verification callback
    // In production, you would want to implement more sophisticated verification
    // including certificate revocation checking, hostname verification, etc.
    
    if (!preverified) {
        char subject_name[256];
        X509* cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
        X509_NAME_oneline(X509_get_subject_name(cert), subject_name, 256);
        
        // Log verification failure (in a real implementation)
        // log_error("Certificate verification failed for: " + std::string(subject_name));
        
        return false;
    }
    
    return true;
}

zerossg::Result<void> TlsHandler::validate_certificate_file(const zerossg::FilePath& cert_file) {
    std::ifstream file(cert_file);
    if (!file.is_open()) {
        return make_result_error(std::format("{}{}", zerossg::ERROR_TLS_CERT_FILE_NOT_FOUND_PREFIX, cert_file));
    }
    
    // Check if file contains certificate data
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    if (content.find(zerossg::PEM_CERTIFICATE_HEADER) == std::string::npos) {
        return make_result_error(std::format("{}{}", zerossg::ERROR_TLS_INVALID_CERT_FORMAT_PREFIX, cert_file));
    }
    
    return make_result_success();
}

zerossg::Result<void> TlsHandler::validate_key_file(const zerossg::FilePath& key_file) {
    std::ifstream file(key_file);
    if (!file.is_open()) {
        return make_result_error(std::format("{}{}", zerossg::ERROR_TLS_KEY_FILE_NOT_FOUND_PREFIX, key_file));
    }
    
    // Check if file contains private key data
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    if (content.find(zerossg::PEM_BEGIN_HEADER) == std::string::npos || 
        content.find(zerossg::PEM_PRIVATE_KEY_FOOTER_PART) == std::string::npos) {
        return make_result_error(std::format("{}{}", zerossg::ERROR_TLS_INVALID_KEY_FORMAT_PREFIX, key_file));
    }
    
    return make_result_success();
}

zerossg::ErrorString TlsHandler::get_ssl_error_string(unsigned long err_code) {
    char buffer[256];
    ERR_error_string_n(err_code, buffer, sizeof(buffer));
    return std::string(buffer);
}

} // namespace zerossg
