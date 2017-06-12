#pragma once

#include <memory>
#include <utility>
#include <mutex>
#include <string>
#include <unordered_map>
#include <cstdint>
#include <cstdlib>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/functional/hash.hpp>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include "net_utils.hpp"
#include "simple_client_tcp.hpp"

#ifndef CASE_INSENSITIVE_EQUALS_AND_HASH
#define CASE_INSENSITIVE_EQUALS_AND_HASH
//Based on http://www.boost.org/doc/libs/1_60_0/doc/html/unordered/hash_equality.html
class case_insensitive_equals {
public:
	bool operator()(const std::string &key1, const std::string &key2) const {
		return boost::algorithm::iequals(key1, key2);
	}
};
class case_insensitive_hash {
public:
	size_t operator()(const std::string &key) const {
		std::size_t seed = 0;
		for (auto &c : key)
			boost::hash_combine(seed, std::tolower(c));
		return seed;
	}
};
#endif

namespace SimpleTCP {
	struct SecureTransporter {
		typedef boost::asio::ssl::stream<boost::asio::ip::tcp::socket> socket_type;
		
		class Response {
			friend class SecureTransporter;
		public:
			std::string http_version, status_code;

			std::istream content;

			std::unordered_multimap<std::string, std::string, case_insensitive_hash, case_insensitive_equals> header;

		private:
			inline void parse_header() {
				std::string line;
				getline(this->content, line);
				size_t version_end = line.find(' ');
				if (version_end != std::string::npos) {
					if (5<line.size())
						this->http_version = line.substr(5, version_end - 5);
					if ((version_end + 1)<line.size())
						this->status_code = line.substr(version_end + 1, line.size() - (version_end + 1) - 1);

					getline(this->content, line);
					size_t param_end;
					while ((param_end = line.find(':')) != std::string::npos) {
						size_t value_start = param_end + 1;
						if ((value_start)<line.size()) {
							if (line[value_start] == ' ')
								value_start++;
							if (value_start<line.size())
								this->header.insert(std::make_pair(line.substr(0, param_end), line.substr(value_start, line.size() - value_start - 1)));
						}

						getline(this->content, line);
					}
				}
			}

		private:
			boost::asio::streambuf content_buffer;

			Response() : content(&content_buffer) {}
		};


		boost::asio::ssl::context context;

		bool verify_certificate;

		SecureTransporter(bool verify_certificate = true, const std::string& cert_file = std::string(), const std::string& private_key_file = std::string(), const std::string& verify_file = std::string()) :context(boost::asio::ssl::context::tlsv12), verify_certificate(verify_certificate) {
			if (cert_file.size()>0 && private_key_file.size()>0) {
				context.use_certificate_chain_file(cert_file);
				context.use_private_key_file(private_key_file, boost::asio::ssl::context::pem);
			}

			if (verify_file.size()>0)
				context.load_verify_file(verify_file);
			else
				context.set_default_verify_paths();

			if (verify_file.size()>0 || verify_certificate)
				context.set_verify_mode(boost::asio::ssl::verify_peer);
			else
				context.set_verify_mode(boost::asio::ssl::verify_none);
		}

		template <typename Client>
		void init(Client& client) {
			if (verify_certificate)context.set_verify_callback(boost::asio::ssl::rfc2818_verification(client.host));
		}
		
		template <typename Client>
		void connect(Client& client) {
			if (!client.socket || !client.socket->lowest_layer().is_open()) {
				{
					std::unique_ptr<boost::asio::ip::tcp::resolver::query> query;
					if (client.config.proxy_server() == nullptr)
						query = std::unique_ptr<boost::asio::ip::tcp::resolver::query>(new boost::asio::ip::tcp::resolver::query(client.host, std::to_string(client.port)));
					else {
						auto proxy_host_port = parse_host_port(client.config.proxy_server(), 8080);
						query = std::unique_ptr<boost::asio::ip::tcp::resolver::query>(new boost::asio::ip::tcp::resolver::query(proxy_host_port.first, std::to_string(proxy_host_port.second)));
					}
					boost::asio::deadline_timer timer(client.io_service);
					client.resolver.async_resolve(*query, [&client, &timer, &context = this->context]
					(const boost::system::error_code &ec, boost::asio::ip::tcp::resolver::iterator it) {
						if (!ec) {
							{
								std::lock_guard<std::mutex> lock(client.socket_mutex);
								client.socket = std::make_unique<socket_type>(client.io_service, context);
							}

							client.make_and_start_timeout_connect_timer(timer);
							boost::asio::async_connect(client.socket->lowest_layer(), it, [&client, &timer]
							(const boost::system::error_code &ec, boost::asio::ip::tcp::resolver::iterator /*it*/) {
								timer.cancel();
								if (!ec) {
									boost::asio::ip::tcp::no_delay option(true);
									client.socket->lowest_layer().set_option(option);
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

				if (client.config.proxy_server() != nullptr) {
					boost::asio::streambuf write_buffer;
					std::ostream write_stream(&write_buffer);
					auto host_port = client.host + ':' + std::to_string(client.port);
					write_stream << "CONNECT " + host_port + " HTTP/1.1\r\n" << "Host: " << host_port << "\r\n\r\n";
					boost::asio::deadline_timer timer(client.io_service);
					client.make_and_start_timeout_timer(timer);
					boost::asio::async_write(client.socket->next_layer(), write_buffer,
						[&client, &timer](const boost::system::error_code &ec, size_t /*bytes_transferred*/) {
						timer.cancel();
						if (ec) {
							std::lock_guard<std::mutex> lock(client.socket_mutex);
							client.socket = nullptr;
							throw boost::system::system_error(ec);
						}
					});
					client.io_service.reset();
					client.io_service.run();

					std::shared_ptr<Response> response(new Response());
					client.make_and_start_timeout_timer(timer);
					boost::asio::async_read_until(client.socket->next_layer(), response->content_buffer, "\r\n\r\n",
						[&client, &timer](const boost::system::error_code& ec, size_t /*bytes_transferred*/) {
						timer.cancel();
						if (ec) {
							std::lock_guard<std::mutex> lock(client.socket_mutex);
							client.socket = nullptr;
							throw boost::system::system_error(ec);
						}
					});
					client.io_service.reset();
					client.io_service.run();
					response->parse_header();
					if (response->status_code.empty() || response->status_code.compare(0, 3, "200") != 0) {
						std::lock_guard<std::mutex> lock(client.socket_mutex);
						client.socket = nullptr;
						throw boost::system::system_error(boost::system::error_code(boost::system::errc::permission_denied, boost::system::generic_category()));
					}
				}

				boost::asio::deadline_timer timer(client.io_service);
				client.make_and_start_timeout_timer(timer);
				client.socket->async_handshake(boost::asio::ssl::stream_base::client,
					[&client, &timer](const boost::system::error_code& ec) {
					timer.cancel();
					if (ec) {
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

	class SecureConfig : public DefaultConfig {
	public:
		typedef SecureTransporter transporter_type;
		transporter_type transporter;
		SecureConfig(const SecureConfig&) = default;
		SecureConfig(SecureConfig&&) = default;
		SecureConfig(bool verify_certificate = true, const std::string& cert_file = std::string(), const std::string& private_key_file = std::string(), const std::string& verify_file = std::string()) : transporter(verify_certificate, cert_file, private_key_file, verify_file) {}
		transporter_type& get_transporter() noexcept {
			return transporter;
		}

		const transporter_type& get_transporter() const noexcept {
			return transporter;
		}
	};

	typedef TCPClient<SecureConfig> SecureTCPClient;
}