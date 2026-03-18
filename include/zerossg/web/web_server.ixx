module;

#include <memory>
#include <string>
#include <functional>
#include <expected>

export module zerossg.web.web_server;

export namespace zerossg {

// Type aliases for web server
using String = std::string;
template<typename T, typename E = std::string>
using Result = std::expected<T, E>;

// HTTP response structure
struct HttpResponse {
    int status_code = 200;
    String content_type = "text/html";
    String body;
    
    HttpResponse() = default;
    HttpResponse(int code, String type, String content)
        : status_code(code), content_type(std::move(type)), body(std::move(content)) {}
};

// Web server interface
export class WebServer {
public:
    WebServer() = default;
    virtual ~WebServer() = default;
    
    // Server lifecycle
    Result<void> start(const String& address, int port);
    Result<void> stop();
    bool is_running() const;
    
    // Port checking
    static bool is_port_available(const String& address, int port);
    static bool is_port_available(int port);
    
    // HTTP handlers
    HttpResponse handle_root();
    HttpResponse handle_status();
    HttpResponse handle_config();
    HttpResponse handle_users();
    HttpResponse handle_sessions();
    HttpResponse handle_logs();
    HttpResponse handle_not_found();
    
    // Utility methods
    String get_status_json() const;
    String get_config_json() const;
    
private:
    bool m_running = false;
    String m_address = "localhost";
    int m_port = 8080;
    
    // HTTP server implementation
    void run_http_server();
    void handle_client(int clientSocket);
    HttpResponse route_request(const String& path);
    HttpResponse make_json_response(const String& json);
    HttpResponse make_html_response(const String& html);
};

// Factory function
export std::unique_ptr<WebServer> create_web_server();

} // namespace zerossg
