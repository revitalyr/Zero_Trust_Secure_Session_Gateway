#pragma once

#include "zerossg/interfaces.hpp"
#include <boost/asio/ssl.hpp>
#include <string>

namespace zerossg {

class TlsHandler : public ITlsHandler {
public:
    TlsHandler(boost::asio::io_context& io_context);
    ~TlsHandler() override;
    
    // ITlsHandler interface
    Result<void> initialize(const string& cert_file, const string& key_file) override;
    boost::asio::ssl::context& get_context() override;
    Result<bool> verify_certificate(const string& cert_data) override;
    
    // Certificate management
    Result<void> load_certificate_chain(const string& cert_file);
    Result<void> load_private_key(const string& key_file);
    Result<void> set_verify_mode(boost::asio::ssl::verify_mode mode);
    Result<void> add_ca_certificate(const string& ca_file);
    
    // Configuration
    void set_verify_depth(int depth);
    void set_cipher_list(const string& cipher_list);
    
private:
    boost::asio::ssl::context m_ssl_context;
    boost::asio::io_context& m_io_context;
    
    // SSL configuration
    int m_verify_depth;
    string m_cipher_list;
    
    // Certificate verification callback
    static bool verify_certificate_callback(bool preverified, boost::asio::ssl::verify_context& ctx);
    
    // Helper methods
    Result<void> validate_certificate_file(const string& cert_file);
    Result<void> validate_key_file(const string& key_file);
    string get_ssl_error_string(unsigned long err_code);
};

} // namespace zerossg
