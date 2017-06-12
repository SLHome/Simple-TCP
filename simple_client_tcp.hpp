#pragma once

#include <memory>
#include <utility>
#include <mutex>
#include <string>
#include <unordered_map>
#include <cstdint>
#include <cstdlib>

#include <boost/asio.hpp>

#include "net_utils.hpp"

namespace SimpleTCP {
	struct DefaultTransporter {
		typedef boost::asio::ip::tcp::socket socket_type;
		template <typename Client>
		void init(Client&) const {}
		template <typename Client>
		void connect(Client& client) const {
			if (!client.socket || !client.socket->is_open()) {
				std::unique_ptr<boost::asio::ip::tcp::resolver::query> query;
				if (!client.config.has_proxy_server()) {
					query = std::make_unique<boost::asio::ip::tcp::resolver::query>(client.host, std::to_string(client.port));
				}
				else {
					auto proxy_host_port = parse_host_port(client.config.proxy_server(), 8080);
					query = std::make_unique<boost::asio::ip::tcp::resolver::query>(proxy_host_port.first, std::to_string(proxy_host_port.second));
				}
				boost::asio::deadline_timer timer(client.io_service);
				client.resolver.async_resolve(*query, [&client, &timer](const boost::system::error_code &ec, boost::asio::ip::tcp::resolver::iterator it) {
					if (!ec) {
						{
							std::lock_guard<std::mutex> lock(client.socket_mutex);
							client.socket = std::make_unique<socket_type>(client.io_service);
						}


						client.make_and_start_timeout_connect_timer(timer);
						boost::asio::async_connect(*(client.socket), it, [&client, &timer](const boost::system::error_code &ec, boost::asio::ip::tcp::resolver::iterator /*it*/) {
							timer.cancel();
							if (!ec) {
								boost::asio::ip::tcp::no_delay option(true);
								client.socket->set_option(option);
							}
							else {
								std::lock_guard<std::mutex> lock(client.socket_mutex);
								client.socket = nullptr;
								throw boost::system::system_error(ec);
							}
						});
					}
					else {
						std::lock_guard<std::mutex> lock(client.socket_mutex);
						client.socket = nullptr;
						throw boost::system::system_error(ec);
					}
				});
				client.io_service.reset();
				client.io_service.run();
			}
		}
	};
	
	class DefaultConfig {
	public:
		/// Set timeout on requests in seconds. Default value: 0 (no timeout). 
		constexpr size_t timeout() const noexcept {
			return 100;
		}
		/// Set connect timeout in seconds. Default value: 0 (Config::timeout is then used instead).
		constexpr size_t timeout_connect() const noexcept {
			return 100;
		}
		/// Set proxy server (server:port)
		constexpr const char* proxy_server() const noexcept {
			return nullptr;
		}
		constexpr bool has_proxy_server() const noexcept {
			return false;
		}
		typedef DefaultTransporter transporter_type;
		const transporter_type& get_transporter() const noexcept {
			return transporter_type{};
		}
	};

	
	template <typename Config = DefaultConfig>
	class TCPClient {
		friend class Config::transporter_type;

	public:
		typedef typename Config::transporter_type transporter_type;
		typedef typename transporter_type::socket_type socket_type;
		typedef Config config_type;

		
	protected:
		Config config;

		boost::asio::io_service io_service;
		boost::asio::ip::tcp::resolver resolver;

		std::unique_ptr<socket_type> socket;
		std::mutex socket_mutex;



		std::string host;
		std::uint16_t port;


	public:
		const Config& get_config() const {
			return config;
		}
		const std::string& get_host() const {
			return host;
		}
		const std::uint16_t& get_port() const {
			return port;
		}

	public:
		TCPClient(const std::string& host_port, std::uint16_t default_port, Config config = Config{}) :resolver(io_service), config(std::move(config)) {
			std::tie(host, port) = parse_host_port(host_port, default_port);
			config.get_transporter().init(*this);
		}

		TCPClient(std::string&& host_port, std::uint16_t default_port, Config config = Config{}) :resolver(io_service), config(std::move(config)) {
			std::tie(host, port) = parse_host_port(std::move(host_port), default_port);
			config.get_transporter().init(*this);
		}

		TCPClient(const TCPClient& client) = delete;
		TCPClient(TCPClient&& client) = default;
		TCPClient& operator=(const TCPClient& client) = delete;
		TCPClient& operator=(TCPClient&& client) = default;

	protected:
		void make_and_start_timeout_timer(boost::asio::deadline_timer& timer) {
			make_timeout_timer(timer, config.timeout(), [this](const boost::system::error_code& ec) {
				if (!ec) {
					std::lock_guard<std::mutex> lock(socket_mutex);
					if (socket) {
						boost::system::error_code ec;
						socket->lowest_layer().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
						socket->lowest_layer().close();
					}
				}
			});
		}

		void make_and_start_timeout_connect_timer(boost::asio::deadline_timer& timer) {
			make_timeout_timer(timer, config.timeout_connect(), [this](const boost::system::error_code& ec) {
				if (!ec) {
					std::lock_guard<std::mutex> lock(socket_mutex);
					if (socket) {
						boost::system::error_code ec;
						socket->lowest_layer().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
						socket->lowest_layer().close();
					}
				}
			});
		}

		void connect() {
			config.get_transporter().connect(*this);
		}

	public:
		template <typename Buffer>
		void send(Buffer&& buffer) {
			
			connect();

			boost::asio::deadline_timer timer(io_service);
			make_and_start_timeout_timer(timer);
			boost::asio::async_write(*socket, std::forward<Buffer>(buffer),
				[this, &timer](const boost::system::error_code &ec, size_t /*bytes_transferred*/) {
				timer.cancel();
				if (ec) {
					std::lock_guard<std::mutex> lock(socket_mutex);
					socket = nullptr;
					throw boost::system::system_error(ec);
				}
			});
			io_service.reset();
			io_service.run();
		}

		template <typename Buffer>
		void receive(Buffer& buffer) {
			
			connect();

			boost::asio::deadline_timer timer(io_service);
			make_and_start_timeout_timer(timer);
			boost::asio::async_read(*socket, buffer,
				[this, &timer](const boost::system::error_code& ec, size_t /*bytes_transferred*/) {
				timer.cancel();
				if (ec) {
					std::lock_guard<std::mutex> lock(socket_mutex);
					this->socket = nullptr;
					if (ec != boost::asio::error::eof) throw boost::system::system_error(ec);
				}
			});
			io_service.reset();
			io_service.run();
		}

		template <typename Buffer>
		size_t receive_until(Buffer& buffer, const std::string& delim) {

			connect();

			boost::asio::deadline_timer timer(io_service);
			make_and_start_timeout_timer(timer);
			size_t ret = 0;
			boost::asio::async_read_until(*socket, buffer, delim,
				[this, &timer, &ret](const boost::system::error_code& ec, size_t bytes_transferred) {
				timer.cancel();
				ret = bytes_transferred;
				if (ec) {
					std::lock_guard<std::mutex> lock(socket_mutex);
					this->socket = nullptr;
					throw boost::system::system_error(ec);
				}
			});
			io_service.reset();
			io_service.run();
			return ret;
		}

		template <typename Buffer>
		size_t receive_exactly(Buffer& buffer, const size_t count) {

			connect();

			boost::asio::deadline_timer timer(io_service);
			make_and_start_timeout_timer(timer);
			size_t ret = 0;
			boost::asio::async_read(*socket, buffer, boost::asio::transfer_exactly(count),
				[this, &timer, &ret](const boost::system::error_code& ec, size_t bytes_transferred) {
				timer.cancel();
				ret = bytes_transferred;
				if (ec) {
					std::lock_guard<std::mutex> lock(socket_mutex);
					this->socket = nullptr;
					throw boost::system::system_error(ec);
				}
			});
			io_service.reset();
			io_service.run();
			return ret;
		}

		boost::asio::streambuf receive() {
			boost::asio::streambuf buffer;
			receive(buffer);
			return std::move(buffer);
		}
	};

	typedef TCPClient<DefaultConfig> DefaultTCPClient;
}