module;

#include <mutex>
export module zerossg.proxy.proxy_manager;

export import zerossg.common;
import zerossg.network;
export import zerossg.types;

export namespace zerossg {

// Forward declarations
export class ProxyManager;
export class ProxyConnection;

// Proxy manager interface class
export class ProxyManager {
public:
    virtual ~ProxyManager() = default;
    virtual Result<void> start_proxy(const std::string& session_id, const ConnectionInfo& client_conn, const TargetService& target) = 0;
    virtual Result<void> stop_proxy(const std::string& session_id) = 0;
    virtual bool is_proxy_active(const std::string& session_id) = 0;
    virtual Result<std::vector<std::string>> get_active_proxies() = 0;
    virtual Result<void> cleanup_inactive_proxies() = 0;
    virtual size_t get_active_proxy_count() = 0;
    virtual size_t get_total_bytes_transferred() = 0;
    virtual std::vector<std::pair<std::string, size_t>> get_proxy_statistics() = 0;
};

} // namespace zerossg
