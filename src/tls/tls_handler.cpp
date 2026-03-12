#include "zerossg/tls/tls_handler.hpp"
#include <openssl/err.h>
#include <fstream>
#include <sstream>

namespace zerossg {

TlsHandler::TlsHandler(IoContext& io_context)
    : m_ssl_context(boost::asio::ssl::context::tlsv12_server)
    , m_io_context(io_context)
    , m_verify_depth(9)
    , m_cipher_list("HIGH:!aNULL:!MD5:!RC4") {
    
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

Result<void> TlsHandler::initialize(const string& cert_file, const string& key_file) {
    try {
        // Load certificate chain
        auto cert_result = load_certificate_chain(cert_file);
        if (!cert_result.is_success()) {
            return Result<void>::error("Failed to load certificate: " + cert_result.error());
        }
        
        // Load private key
        auto key_result = load_private_key(key_file);
        if (!key_result.is_success()) {
            return Result<void>::error("Failed to load private key: " + key_result.error());
        }
        
        // Set cipher list
        if (!m_cipher_list.empty()) {
            if (SSL_CTX_set_cipher_list(m_ssl_context.native_handle(), m_cipher_list.c_str()) != 1) {
                return Result<void>::error("Failed to set cipher list");
            }
        }
        
        // Set verification depth
        SSL_CTX_set_verify_depth(m_ssl_context.native_handle(), m_verify_depth);
        
        return Result<void>::success();
    } catch (const std::exception& e) {
        return Result<void>::error("TLS initialization failed: " + string(e.what()));
    }
}

SslContext& TlsHandler::get_context() {
    return m_ssl_context;
}

Result<bool> TlsHandler::verify_certificate(const string& cert_data) {
    try {
        // Create a memory BIO for the certificate data
        BIO* bio = BIO_new_mem_buf(cert_data.data(), static_cast<int>(cert_data.size()));
        if (!bio) {
            return Result<bool>::error("Failed to create BIO for certificate");
        }
        
        // Load certificate
        X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
        
        if (!cert) {
            return Result<bool>::error("Failed to parse certificate");
        }
        
        // Basic validation checks
        int result = X509_check_cert(cert);
        X509_free(cert);
        
        return Result<bool>::success(result == 1);
    } catch (const std::exception& e) {
        return Result<bool>::error("Certificate verification failed: " + string(e.what()));
    }
}

Result<void> TlsHandler::load_certificate_chain(const string& cert_file) {
    auto validation_result = validate_certificate_file(cert_file);
    if (!validation_result.is_success()) {
        return validation_result;
    }
    
    try {
        m_ssl_context.use_certificate_chain_file(cert_file);
        return Result<void>::success();
    } catch (const std::exception& e) {
        return Result<void>::error("Failed to load certificate chain: " + string(e.what()));
    }
}

Result<void> TlsHandler::load_private_key(const string& key_file) {
    auto validation_result = validate_key_file(key_file);
    if (!validation_result.is_success()) {
        return validation_result;
    }
    
    try {
        m_ssl_context.use_private_key_file(key_file, boost::asio::ssl::context::pem);
        return Result<void>::success();
    } catch (const std::exception& e) {
        return Result<void>::error("Failed to load private key: " + string(e.what()));
    }
}

Result<void> TlsHandler::set_verify_mode(SslVerifyMode mode) {
    try {
        m_ssl_context.set_verify_mode(mode);
        if (mode != boost::asio::ssl::verify_none) {
            m_ssl_context.set_verify_callback(verify_certificate_callback);
        }
        return Result<void>::success();
    } catch (const std::exception& e) {
        return Result<void>::error("Failed to set verify mode: " + string(e.what()));
    }
}

Result<void> TlsHandler::add_ca_certificate(const string& ca_file) {
    try {
        m_ssl_context.load_verify_file(ca_file);
        return Result<void>::success();
    } catch (const std::exception& e) {
        return Result<void>::error("Failed to load CA certificate: " + string(e.what()));
    }
}

void TlsHandler::set_verify_depth(int depth) {
    m_verify_depth = depth;
    SSL_CTX_set_verify_depth(m_ssl_context.native_handle(), depth);
}

void TlsHandler::set_cipher_list(const string& cipher_list) {
    m_cipher_list = cipher_list;
}

bool TlsHandler::verify_certificate_callback(bool preverified, SslVerifyContext& ctx) {
    // This is a simplified verification callback
    // In production, you would want to implement more sophisticated verification
    // including certificate revocation checking, hostname verification, etc.
    
    if (!preverified) {
        char subject_name[256];
        X509* cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
        X509_NAME_oneline(X509_get_subject_name(cert), subject_name, 256);
        
        // Log the verification failure (in a real implementation)
        // log_error("Certificate verification failed for: " + string(subject_name));
        
        return false;
    }
    
    return true;
}

Result<void> TlsHandler::validate_certificate_file(const string& cert_file) {
    std::ifstream file(cert_file);
    if (!file.is_open()) {
        return Result<void>::error("Certificate file not found: " + cert_file);
    }
    
    // Check if file contains certificate data
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    if (content.find("-----BEGIN CERTIFICATE-----") == std::string::npos) {
        return Result<void>::error("Invalid certificate file format: " + cert_file);
    }
    
    return Result<void>::success();
}

Result<void> TlsHandler::validate_key_file(const string& key_file) {
    std::ifstream file(key_file);
    if (!file.is_open()) {
        return Result<void>::error("Private key file not found: " + key_file);
    }
    
    // Check if file contains private key data
    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    if (content.find("-----BEGIN") == std::string::npos || 
        content.find("PRIVATE KEY-----") == std::string::npos) {
        return Result<void>::error("Invalid private key file format: " + key_file);
    }
    
    return Result<void>::success();
}

string TlsHandler::get_ssl_error_string(unsigned long err_code) {
    char buffer[256];
    ERR_error_string_n(err_code, buffer, sizeof(buffer));
    return string(buffer);
}

} // namespace zerossg
