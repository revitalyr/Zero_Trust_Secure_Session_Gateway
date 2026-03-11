#include "zerossg/proxy/proxy_manager.hpp"
#include <iostream>

namespace zerossg {

// ProxyManager implementation
ProxyManager::ProxyManager(boost::asio::io_context& io_context)
    : m_io_context(io_context) {
}

ProxyManager::~ProxyManager() {
    // Clean up all active proxies
    std::lock_guard<std::mutex> lock(m_proxies_mutex);
    m_proxies.clear();
}

Result<void> ProxyManager::start_proxy(const string& session_id, const ConnectionInfo& client_conn, 
                                      const TargetService& target) {
    std::lock_guard<std::mutex> lock(m_proxies_mutex);
    
    // Check if proxy already exists for this session
    if (m_proxies.find(session_id) != m_proxies.end()) {
        return Result<void>::error("Proxy already exists for session: " + session_id);
    }
    
    try {
        // Create new proxy connection
        auto proxy = std::make_shared<ProxyConnection>(*this, session_id, client_conn, target);
        m_proxies[session_id] = proxy;
        
        // Start the proxy
        proxy->start();
        
        return Result<void>::success();
    } catch (const std::exception& e) {
        // Clean up on failure
        m_proxies.erase(session_id);
        return Result<void>::error("Failed to start proxy: " + string(e.what()));
    }
}

Result<void> ProxyManager::stop_proxy(const string& session_id) {
    std::lock_guard<std::mutex> lock(m_proxies_mutex);
    
    auto it = m_proxies.find(session_id);
    if (it == m_proxies.end()) {
        return Result<void>::error("Proxy not found for session: " + session_id);
    }
    
    // Stop and remove the proxy
    it->second->stop();
    m_proxies.erase(it);
    
    return Result<void>::success();
}

bool ProxyManager::is_proxy_active(const string& session_id) {
    std::lock_guard<std::mutex> lock(m_proxies_mutex);
    
    auto it = m_proxies.find(session_id);
    return it != m_proxies.end() && it->second->is_active();
}

Result<vector<string>> ProxyManager::get_active_proxies() {
    std::lock_guard<std::mutex> lock(m_proxies_mutex);
    
    vector<string> active_proxies;
    
    for (const auto& pair : m_proxies) {
        if (pair.second->is_active()) {
            active_proxies.push_back(pair.first);
        }
    }
    
    return Result<vector<string>>::success(std::move(active_proxies));
}

Result<void> ProxyManager::cleanup_inactive_proxies() {
    std::lock_guard<std::mutex> lock(m_proxies_mutex);
    
    auto it = m_proxies.begin();
    while (it != m_proxies.end()) {
        if (!it->second->is_active()) {
            it = m_proxies.erase(it);
        } else {
            ++it;
        }
    }
    
    return Result<void>::success();
}

size_t ProxyManager::get_active_proxy_count() const {
    std::lock_guard<std::mutex> lock(m_proxies_mutex);
    
    size_t count = 0;
    for (const auto& pair : m_proxies) {
        if (pair.second->is_active()) {
            count++;
        }
    }
    
    return count;
}

uint64_t ProxyManager::get_total_bytes_transferred() const {
    return m_total_bytes_transferred.load();
}

void ProxyManager::remove_proxy(const string& session_id) {
    std::lock_guard<std::mutex> lock(m_proxies_mutex);
    m_proxies.erase(session_id);
}

void ProxyManager::update_statistics(uint64_t bytes_transferred) {
    m_total_bytes_transferred.fetch_add(bytes_transferred);
}

// ProxyConnection implementation
ProxyConnection::ProxyConnection(ProxyManager& manager, const string& session_id,
                               const ConnectionInfo& client_conn, const TargetService& target)
    : m_manager(manager)
    , m_session_id(session_id)
    , m_client_conn(client_conn)
    , m_target_service(target)
    , m_client_socket(manager.m_io_context)
    , m_target_socket(manager.m_io_context) {
}

ProxyConnection::~ProxyConnection() {
    stop();
}

void ProxyConnection::start() {
    try {
        m_active.store(true);
        
        // Setup SSL if needed
        setup_ssl_if_needed();
        
        // Connect to target service
        connect_to_target();
    } catch (const std::exception& e) {
        handle_error("start", boost::system::errc::make_error_code(boost::system::errc::connection_aborted));
    }
}

void ProxyConnection::stop() {
    if (!m_active.exchange(false)) {
        return; // Already stopped
    }
    
    try {
        boost::system::error_code ec;
        
        if (m_client_ssl_socket) {
            m_client_ssl_socket->shutdown(ec);
            m_client_ssl_socket->lowest_layer().close(ec);
        } else {
            m_client_socket.close(ec);
        }
        
        if (m_target_ssl_socket) {
            m_target_ssl_socket->shutdown(ec);
            m_target_ssl_socket->lowest_layer().close(ec);
        } else {
            m_target_socket.close(ec);
        }
        
        // Update statistics
        m_manager.update_statistics(m_bytes_sent + m_bytes_received);
        
        // Remove from manager
        m_manager.remove_proxy(m_session_id);
    } catch (const std::exception& e) {
        std::cerr << "Error during proxy shutdown: " << e.what() << std::endl;
    }
}

void ProxyConnection::connect_to_target() {
    try {
        boost::asio::ip::tcp::endpoint target_endpoint(
            boost::asio::ip::make_address(m_target_service.host),
            m_target_service.port
        );
        
        get_target_socket().async_connect(target_endpoint,
            [self = shared_from_this()](const boost::system::error_code& error) {
                self->handle_target_connect(error);
            }
        );
    } catch (const std::exception& e) {
        handle_error("connect_to_target", boost::system::errc::make_error_code(boost::system::errc::connection_aborted));
    }
}

void ProxyConnection::handle_target_connect(const boost::system::error_code& error) {
    if (error) {
        handle_error("handle_target_connect", error);
        return;
    }
    
    // Start data forwarding between client and target
    start_data_forwarding();
}

void ProxyConnection::start_data_forwarding() {
    if (!m_active.load()) {
        return;
    }
    
    // Start reading from both directions
    read_from_client();
    read_from_target();
}

void ProxyConnection::read_from_client() {
    if (!m_active.load()) {
        return;
    }
    
    boost::asio::async_read_until(get_client_socket(), m_client_to_target_buffer, '\n',
        [self = shared_from_this()](const boost::system::error_code& error, size_t bytes_transferred) {
            self->handle_client_read(error, bytes_transferred);
        }
    );
}

void ProxyConnection::handle_client_read(const boost::system::error_code& error, size_t bytes_transferred) {
    if (error) {
        handle_error("handle_client_read", error);
        return;
    }
    
    m_bytes_received += bytes_transferred;
    write_to_target(bytes_transferred);
}

void ProxyConnection::write_to_target(size_t bytes_to_write) {
    if (!m_active.load()) {
        return;
    }
    
    boost::asio::async_write(get_target_socket(), 
        m_client_to_target_buffer.data(),
        boost::asio::transfer_exactly(bytes_to_write),
        [self = shared_from_this()](const boost::system::error_code& error, size_t bytes_transferred) {
            self->handle_target_write(error, bytes_transferred);
        }
    );
}

void ProxyConnection::handle_target_write(const boost::system::error_code& error, size_t bytes_transferred) {
    if (error) {
        handle_error("handle_target_write", error);
        return;
    }
    
    m_client_to_target_buffer.consume(bytes_transferred);
    
    // Continue reading from client
    read_from_client();
}

void ProxyConnection::read_from_target() {
    if (!m_active.load()) {
        return;
    }
    
    boost::asio::async_read_until(get_target_socket(), m_target_to_client_buffer, '\n',
        [self = shared_from_this()](const boost::system::error_code& error, size_t bytes_transferred) {
            self->handle_target_read(error, bytes_transferred);
        }
    );
}

void ProxyConnection::handle_target_read(const boost::system::error_code& error, size_t bytes_transferred) {
    if (error) {
        handle_error("handle_target_read", error);
        return;
    }
    
    m_bytes_received += bytes_transferred;
    write_to_client(bytes_transferred);
}

void ProxyConnection::write_to_client(size_t bytes_to_write) {
    if (!m_active.load()) {
        return;
    }
    
    boost::asio::async_write(get_client_socket(),
        m_target_to_client_buffer.data(),
        boost::asio::transfer_exactly(bytes_to_write),
        [self = shared_from_this()](const boost::system::error_code& error, size_t bytes_transferred) {
            self->handle_client_write(error, bytes_transferred);
        }
    );
}

void ProxyConnection::handle_client_write(const boost::system::error_code& error, size_t bytes_transferred) {
    if (error) {
        handle_error("handle_client_write", error);
        return;
    }
    
    m_bytes_sent += bytes_transferred;
    m_target_to_client_buffer.consume(bytes_transferred);
    
    // Continue reading from target
    read_from_target();
}

void ProxyConnection::handle_error(const string& operation, const boost::system::error_code& error) {
    if (!m_active.load()) {
        return; // Already shutting down
    }
    
    std::cerr << "Proxy error in " << operation << ": " << error.message() << std::endl;
    cleanup();
}

void ProxyConnection::cleanup() {
    stop();
}

boost::asio::ip::tcp::socket& ProxyConnection::get_client_socket() {
    return m_client_ssl_socket ? m_client_ssl_socket->lowest_layer() : m_client_socket;
}

boost::asio::ip::tcp::socket& ProxyConnection::get_target_socket() {
    return m_target_ssl_socket ? m_target_ssl_socket->lowest_layer() : m_target_socket;
}

void ProxyConnection::setup_ssl_if_needed() {
    // This is a simplified implementation
    // In a real implementation, you would properly set up SSL contexts
    // and handle SSL handshakes for both client and target connections
    
    if (m_target_service.tls_enabled) {
        // Create SSL context for target connection
        // This would need proper certificate verification
        // m_target_ssl_socket = std::make_unique<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>>(
        //     m_target_socket, ssl_context);
    }
}

} // namespace zerossg
