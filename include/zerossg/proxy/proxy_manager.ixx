export module zerossg.proxy.proxy_manager;

export import <memory>;
export import <string>;
export import <vector>;
export import <unordered_map>;
export import <mutex>;

export namespace zerossg {

// Forward declarations
export class ProxyManager;
export class ProxyConnection;

// Proxy manager interface class
export class ProxyManager {
public:
    virtual ~ProxyManager() = default;
    virtual Result<void> start_proxy(const string& session_id, const ConnectionInfo& client_conn, const TargetService& target) = 0;
    virtual Result<void> stop_proxy(const string& session_id) = 0;
    virtual bool is_proxy_active(const string& session_id) = 0;
    virtual Result<vector<string>> get_active_proxies() = 0;
    virtual Result<void> cleanup_inactive_proxies() = 0;
    virtual size_t get_active_proxy_count() = 0;
    virtual size_t get_total_bytes_transferred() = 0;
    virtual vector<pair<string, size_t>> get_proxy_statistics() = 0;
};

} // namespace zerossg
