#pragma once


#include "simple_client_smtp.hpp"
#include "simple_client_tcp_tls.hpp"

#include "simple_crypto.hpp"

namespace SimpleTCP {
	
	class NoAuthAgent {
	public:
		template <typename Client, typename Transporter>
		void authenticate(Client&, Transporter&) const {}
	};

	class UsernamePasswordAuthAgent {
	public:
		std::string username, password;
		UsernamePasswordAuthAgent() {}
		UsernamePasswordAuthAgent(UsernamePasswordAuthAgent&&) = default;
		UsernamePasswordAuthAgent(const UsernamePasswordAuthAgent&) = default;
		UsernamePasswordAuthAgent& operator=(UsernamePasswordAuthAgent&&) = default;
		UsernamePasswordAuthAgent& operator=(const UsernamePasswordAuthAgent&) = default;
		UsernamePasswordAuthAgent(const std::string& username, const std::string& password) :username(SimpleTCP::Crypto::Base64::encode(escape(username))), password(SimpleTCP::Crypto::Base64::encode(password)) {}


		template <typename Client, typename Transporter>
		void authenticate(Client& client, Transporter& transporter) const {
			
			transporter.send_noconnect(client, [](std::ostream& write_stream) {
				write_stream << "AUTH LOGIN" << "\r\n";
			});

			transporter.receive_noconnect(client, [](std::istream& read_stream) {
				SMTPCode code;
				read_stream >> code;
				if (read_stream.fail() || code != SMTPCode::LOGIN)throw boost::system::system_error(boost::asio::error::operation_aborted);
			});

			transporter.send_noconnect(client, [this](std::ostream& write_stream) {
				write_stream << username << "\r\n";
			});

			transporter.receive_noconnect(client, [](std::istream& read_stream) {
				SMTPCode code;
				read_stream >> code;
				if (read_stream.fail() || code != SMTPCode::LOGIN)throw boost::system::system_error(boost::asio::error::operation_aborted);
			});

			transporter.send_noconnect(client, [this](std::ostream& write_stream) {
				write_stream << password << "\r\n";
			});

			transporter.receive_noconnect(client, [](std::istream& read_stream) {
				SMTPCode code;
				read_stream >> code;
				if (read_stream.fail() || code != SMTPCode::AUTH_SUCCESS)throw boost::system::system_error(boost::asio::error::operation_aborted);
			});


		}
	};

	class SecureSMTPTransporter : public SecureTransporter {
	public:
		SecureSMTPTransporter(bool verify_certificate = true, const std::string& cert_file = std::string(), const std::string& private_key_file = std::string(), const std::string& verify_file = std::string()) : SecureTransporter(verify_certificate, cert_file, private_key_file, verify_file) {}
		
		template <typename Client>
		void init(Client& client) {
			if (verify_certificate)context.set_verify_callback(boost::asio::ssl::rfc2818_verification(client.host));
		}

		template <typename Client, typename Callback>
		void send_noconnect(Client& client, Callback&& callback) {
			boost::asio::streambuf write_buffer;
			std::ostream write_stream(&write_buffer);
			std::forward<Callback>(callback)(write_stream);
			client.send_noconnect(write_buffer, *client.socket);
		}

		template <typename Client, typename Callback>
		void receive_noconnect(Client& client, Callback&& callback) {
			boost::asio::streambuf read_buffer;
			std::istream recv_stream(&read_buffer);

			client.receive_until_noconnect(read_buffer, "\r\n", *client.socket);
#ifdef SIMPLE_TCP_PRINT_RECEIVED_RESPONSES_TO_STDERR
			std::string str(boost::asio::buffers_begin(read_buffer.data()), boost::asio::buffers_end(read_buffer.data()));
			std::cerr << str;
#endif
			std::forward<Callback>(callback)(recv_stream);
		}

		template <typename Client, typename Callback>
		void send_noconnect_next(Client& client, Callback&& callback) {
			boost::asio::streambuf write_buffer;
			std::ostream write_stream(&write_buffer);
			std::forward<Callback>(callback)(write_stream);
			client.send_noconnect(write_buffer, client.socket->next_layer());
		}

		template <typename Client, typename Callback>
		void receive_noconnect_next(Client& client, Callback&& callback) {
			boost::asio::streambuf read_buffer;
			std::istream recv_stream(&read_buffer);

			client.receive_until_noconnect(read_buffer, "\r\n", client.socket->next_layer());
#ifdef SIMPLE_TCP_PRINT_RECEIVED_RESPONSES_TO_STDERR
			std::string str(boost::asio::buffers_begin(read_buffer.data()), boost::asio::buffers_end(read_buffer.data()));
			std::cerr << str;
#endif
			std::forward<Callback>(callback)(recv_stream);
		}
		
		template <typename Client>
		void connect(Client& client) {
			if (!client.socket || !client.socket->next_layer().is_open()) {
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
							boost::asio::async_connect(client.socket->next_layer(), it, [&client, &timer]
							(const boost::system::error_code &ec, boost::asio::ip::tcp::resolver::iterator /*it*/) {
								timer.cancel();
								if (!ec) {
									boost::asio::ip::tcp::no_delay option(true);
									client.socket->next_layer().set_option(option);
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
#ifdef SIMPLE_TCP_PRINT_RECEIVED_RESPONSES_TO_STDERR
				cerr << client.get_host() << ":" << client.get_port() << endl;
#endif


				receive_noconnect_next(client, [](std::istream& read_stream) {
					SMTPCode code;
					read_stream >> code;
					if (read_stream.fail() || code != SMTPCode::READY)throw boost::system::system_error(boost::asio::error::operation_aborted);
				});
				send_noconnect_next(client, [this, name = client.get_config().fully_qualified_domain_name()](std::ostream& write_stream) {
					write_stream << "EHLO " << name << "\r\n";
				});
				receive_noconnect_next(client, [](std::istream& read_stream) {});
				send_noconnect_next(client, [this](std::ostream& write_stream) {
					write_stream << "STARTTLS" << "\r\n";
				});
				while (true) {
					bool br = false;
					receive_noconnect_next(client, [&br](std::istream& read_stream) {
						std::string str;
						read_stream >> str;
						str.resize(3);
						if (str == "220")br = true;
					});
					if (br)break;
				}
				

				{
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


				send_noconnect(client, [this, name = client.get_config().fully_qualified_domain_name()](std::ostream& write_stream) {
					write_stream << "EHLO " << name << "\r\n";
				});

				receive_noconnect(client, [](std::istream& read_stream) {});



				client.get_config().get_auth_agent().authenticate(client, *this);

			}
		}
	};
	
	template <typename SMTPAuthAgent = NoAuthAgent, typename Transporter = SecureSMTPTransporter>
	class SecureSMTPConfig : public SecureConfig<Transporter> {
	public:
		SecureSMTPConfig(const SecureSMTPConfig&) = default;
		SecureSMTPConfig(SecureSMTPConfig&&) = default;
		SecureSMTPConfig(bool verify_certificate = true, const std::string& cert_file = std::string(), const std::string& private_key_file = std::string(), const std::string& verify_file = std::string()) : SecureConfig(verify_certificate, cert_file, private_key_file, verify_file) {}
		SecureSMTPConfig(SMTPAuthAgent auth_agent, bool verify_certificate = true, const std::string& cert_file = std::string(), const std::string& private_key_file = std::string(), const std::string& verify_file = std::string()) : SecureConfig(verify_certificate, cert_file, private_key_file, verify_file), auth_agent(std::move(auth_agent)) {}
		const char* fully_qualified_domain_name() const noexcept {
			return "222.164.227.88";
		}
		std::uint16_t default_port() const noexcept {
			return 587;
		}
		SMTPAuthAgent auth_agent;
		SMTPAuthAgent& get_auth_agent() noexcept {
			return auth_agent;
		}
		const SMTPAuthAgent& get_auth_agent() const noexcept {
			return auth_agent;
		}
	};
	
	typedef SMTPClient<SecureSMTPConfig<>> SecureSMTPClient;
	typedef SMTPClient<SecureSMTPConfig<UsernamePasswordAuthAgent>> SecureUsernamePasswordSMTPClient;
}