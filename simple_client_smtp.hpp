#pragma once

#include <ostream>
#include <unordered_map>
#include <memory>
#include <string>
#include <iterator>
#include <istream>
#include <ostream>
#include <sstream>
#include <stdexcept>

#include <boost/asio.hpp>

#include "simple_client_tcp.hpp"


namespace SimpleTCP {

	class DefaultSMTPConfig {
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
		constexpr const char* fully_qualified_domain_name() const noexcept {
			return "222.164.227.88";
		}
	};


	template <typename Client>
	class SMTPProcessor {
	public:
		

	public:
		typedef Client client_type;
		typedef typename Client::socket_type socket_type;
		typedef typename Client::config_type config_type;
	protected:
		Client client;
	public:
		const config_type& get_config() const {
			return client.get_config();
		}
	public:
		SMTPProcessor(Client client) :client(client) {}

		SMTPProcessor(const std::string& host_port, config_type config = config_type{}) :client(host_port, 25, std::move(config)) {}

		SMTPProcessor(std::string&& host_port, config_type config = config_type{}) :client(std::move(host_port), 25, std::move(config)) {}

	private:
		enum class SMTPCode : std::uint16_t {
			READY = 220,
			CLOSE = 221,
			OK = 250,
			DATA = 354
		};
		static std::string to_string(const SMTPCode& x) {
			return std::to_string(static_cast<std::uint16_t>(x));
		}
		SMTPCode receive_code_from_server() {
			boost::asio::streambuf buf;
			std::istream recv_stream(&buf);
			client.receive_exactly(buf, 3);
			std::uint16_t code;
			recv_stream >> code;
			if (recv_stream.fail())throw std::invalid_argument("Invalid code received.");
			client.receive_until(buf, "\r\n");
			cerr << code << recv_stream.rdbuf();
			return static_cast<SMTPCode>(code);
		}
		
		void send_string(const char* code, const std::string& str) {
			boost::asio::streambuf write_buffer;
			std::ostream write_stream(&write_buffer);
			write_stream << code;
			if (!str.empty()) {
				write_stream << ' ' << str;
			}
			write_stream << "\r\n";
			client.send(write_buffer);
		}
		void send_string(const char* code, const char* str) {
			boost::asio::streambuf write_buffer;
			std::ostream write_stream(&write_buffer);
			write_stream << code;
			if (str != nullptr) {
				write_stream << ' ' << str;
			}
			write_stream << "\r\n";
			client.send(write_buffer);
		}
		void send_string(const char* code) {
			boost::asio::streambuf write_buffer;
			std::ostream write_stream(&write_buffer);
			write_stream << code << "\r\n";
			client.send(write_buffer);
		}
		template <typename Callback>
		void send_data_and_CRLF(const char* code, Callback&& callback) {
			boost::asio::streambuf write_buffer;
			std::ostream write_stream(&write_buffer);
			write_stream << code << ' ';
			callback(write_stream);
			write_stream << "\r\n";
			client.send(write_buffer);
		}
		template <typename Callback>
		void send_data(Callback&& callback) {
			boost::asio::streambuf write_buffer;
			std::ostream write_stream(&write_buffer);
			callback(write_stream);
			client.send(write_buffer);
		}

		void append_from(const std::string& from) {
			send_data_and_CRLF("MAIL", [&](std::ostream& write_stream) {
				write_stream << "FROM:<" << from << ">";
			});
			SMTPCode ret = receive_code_from_server();
			if (ret != SMTPCode::OK) throw std::invalid_argument("Invalid code received (" + to_string(ret) + ").");
		}

		void append_from(std::string&& from) {
			send_data_and_CRLF("MAIL", [&](std::ostream& write_stream) {
				write_stream << "FROM:<" << std::move(from) << ">";
			});
			SMTPCode ret = receive_code_from_server();
			if (ret != SMTPCode::OK) throw std::invalid_argument("Invalid code received (" + to_string(ret) + ").");
		}
		void append_from(const char* from) {
			send_data_and_CRLF("MAIL", [&](std::ostream& write_stream) {
				write_stream << "FROM:<" << from << ">";
			});
			SMTPCode ret = receive_code_from_server();
			if (ret != SMTPCode::OK) throw std::invalid_argument("Invalid code received (" + to_string(ret) + ").");
		}

		void append_to(const std::string& to) {
			send_data_and_CRLF("MAIL", [&](std::ostream& write_stream) {
				write_stream << "RCPT:<" << to << ">";
			});
			SMTPCode ret = receive_code_from_server();
			if (ret != SMTPCode::OK) throw std::invalid_argument("Invalid code received (" + to_string(ret) + ").");
		}

		void append_to(std::string&& to) {
			send_data_and_CRLF("MAIL", [&](std::ostream& write_stream) {
				write_stream << "RCPT:<" << std::move(to) << ">";
			});
			SMTPCode ret = receive_code_from_server();
			if (ret != SMTPCode::OK) throw std::invalid_argument("Invalid code received (" + to_string(ret) + ").");
		}

		void append_to(const char* to) {
			send_data_and_CRLF("MAIL", [&](std::ostream& write_stream) {
				write_stream << "RCPT:<" << to << ">";
			});
			SMTPCode ret = receive_code_from_server();
			if (ret != SMTPCode::OK) throw std::invalid_argument("Invalid code received (" + to_string(ret) + ").");
		}

		template <typename T, typename A>
		void append_to(const std::vector<T, A>& data) {
			std::for_each(data.begin(), data.end(), [this](const T& to) {
				append_to(to);
			});
		}

		template <typename T, typename A>
		void append_to(std::vector<T, A>&& data) {
			std::for_each(std::make_move_iterator(data.begin()), std::make_move_iterator(data.end()), [this](T&& to) {
				append_to(std::move(to));
			});
		}

	public:
		template <typename TFrom, typename TTo, typename TCc, typename TBcc>
		void send_mail(TFrom&& from, TTo&& to, TCc&& cc, TBcc&& bcc, std::istream& body) {
			SMTPCode ret;
			ret = receive_code_from_server();
			if (ret != SMTPCode::READY) throw std::invalid_argument("Invalid code received (" + to_string(ret) + ").");
			send_string("HELO", get_config().fully_qualified_domain_name());
			ret = receive_code_from_server();
			if (ret != SMTPCode::OK) throw std::invalid_argument("Invalid code received (" + to_string(ret) + ").");
			append_from(std::forward<TFrom>(from));
			append_to(std::forward<TTo>(to));
			append_to(std::forward<TCc>(cc));
			append_to(std::forward<TBcc>(bcc));
			send_string("DATA");
			ret = receive_code_from_server();
			if (ret != SMTPCode::DATA) throw std::invalid_argument("Invalid code received (" + to_string(ret) + ").");
			send_data([&](std::ostream& write_stream) {
				write_stream << body.rdbuf();
			});
			ret = receive_code_from_server();
			if (ret != SMTPCode::OK) throw std::invalid_argument("Invalid code received (" + to_string(ret) + ").");
			send_string("QUIT");
			ret = receive_code_from_server();
		}
		template <typename TFrom, typename TTo>
		void send_mail(TFrom&& from, TTo&& to, const std::string& body) {
			send_mail(std::forward<TFrom>(from), std::forward<TTo>(to), vector<std::string>(), vector<std::string>(), std::istringstream(body));
		}
		template <typename TFrom, typename TTo>
		void send_mail(TFrom&& from, TTo&& to, std::string&& body) {
			send_mail(std::forward<TFrom>(from), std::forward<TTo>(to), vector<std::string>(), vector<std::string>(), std::istringstream(std::move(body)));
		}
	};

	template <typename Config>
	using SMTPClient = SMTPProcessor<TCPClient<Config>>;

	typedef SMTPClient<DefaultSMTPConfig> DefaultSMTPClient;
}