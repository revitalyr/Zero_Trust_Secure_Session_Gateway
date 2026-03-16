module;

// Include Boost headers for network type aliases
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/ssl/verify_context.hpp>

export module zerossg.network;

export namespace zerossg {

// Network type aliases
using TcpEndpoint = boost::asio::ip::tcp::endpoint;
using SslContext = boost::asio::ssl::context;
using SslStream = boost::asio::ssl::stream<boost::asio::ip::tcp::socket>;
using TcpSocket = boost::asio::ip::tcp::socket;
using TcpAcceptor = boost::asio::ip::tcp::acceptor;
using IoContext = boost::asio::io_context;

// SSL verification type aliases
using SslVerifyMode = boost::asio::ssl::verify_mode;
using SslVerifyContext = boost::asio::ssl::verify_context;

} // namespace zerossg
