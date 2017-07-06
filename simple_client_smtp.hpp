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
#include <type_traits>
#include <chrono>
#include <ctime>
#ifdef SIMPLE_TCP_PRINT_RECEIVED_RESPONSES_TO_STDERR
#include <iostream>
#endif

#include <boost/asio.hpp>
#include <boost/algorithm/string/join.hpp>
#include <boost/algorithm/string/split.hpp>

#include "simple_client_tcp.hpp"


namespace SimpleTCP {

	class DefaultSMTPTransporter : public DefaultTransporter {
	public:

		template <typename Client>
		void init(Client&) const {}
		template <typename Client>
		void connect(Client& client) const {
			if (!client.socket || !client.socket->is_open()) {
				{
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



#ifdef SIMPLE_TCP_PRINT_RECEIVED_RESPONSES_TO_STDERR
				cerr << client.get_host() << ":" << client.get_port() << endl;
#endif

				{
					boost::asio::streambuf read_buffer;
					std::istream recv_stream(&read_buffer);

					client.receive_until_noconnect(read_buffer, "\r\n", *client.socket);
					SMTPCode code;
					std::string str;
					recv_stream >> code;
					if (recv_stream.fail() || code != SMTPCode::READY)throw boost::system::system_error(boost::asio::error::operation_aborted);
					getline(recv_stream, str, '\n');
					if (str.empty())throw boost::system::system_error(boost::asio::error::operation_aborted);
#ifdef SIMPLE_TCP_PRINT_RECEIVED_RESPONSES_TO_STDERR
					str.pop_back();
					cerr << str << endl;
#endif
				}
				{
					boost::asio::streambuf write_buffer;
					std::ostream write_stream(&write_buffer);
					write_stream << "HELO " << client.get_config().fully_qualified_domain_name() << "\r\n";
					client.send_noconnect(write_buffer, *client.socket);
				}
				{
					boost::asio::streambuf read_buffer;
					std::istream recv_stream(&read_buffer);

					client.receive_until_noconnect(read_buffer, "\r\n", *client.socket);
					SMTPCode code;
					std::string str;
					recv_stream >> code;
					if (recv_stream.fail() || code != SMTPCode::OK)throw boost::system::system_error(boost::asio::error::operation_aborted);
					getline(recv_stream, str, '\n');
					if (str.empty())throw boost::system::system_error(boost::asio::error::operation_aborted);
#ifdef SIMPLE_TCP_PRINT_RECEIVED_RESPONSES_TO_STDERR
					str.pop_back();
					cerr << str << endl;
#endif
				}
			}
		}
	};
	
	template <typename Transporter = DefaultSMTPTransporter>
	class DefaultSMTPConfig : public DefaultConfig<Transporter> {
	public:
		constexpr std::uint16_t default_port() const noexcept {
			return 25;
		}
		constexpr const char* fully_qualified_domain_name() const noexcept {
			return "222.164.227.88";
		}
	};


	enum class RecipientType :std::uint8_t {
		DEFAULT, FROM, TO, CC, BCC
	};
	struct Recipient {
		std::string name, email;
		RecipientType type;
		Recipient() :type(RecipientType::DEFAULT) {}
		Recipient(const Recipient&) = default;
		Recipient(Recipient&&) = default;
		Recipient& operator=(const Recipient&) = default;
		Recipient& operator=(Recipient&&) = default;
		Recipient(const RecipientType& type) :type(type) {}
		template <typename TEmail>
		Recipient(const RecipientType& type, TEmail&& email) : email(std::forward<TEmail>(email)), type(type) {}
		template <typename TName, typename TEmail>
		Recipient(const RecipientType& type, TName&& name, TEmail&& email) : name(std::forward<TName>(name)), email(std::forward<TEmail>(email)), type(type) {}
	};


	inline std::string escape(const std::string& str) {
		std::string ret;
		for (const char& c : str) {
			if (c == '\"' || c == '\\') {
				ret.push_back('\\');
			}
			ret.push_back(c);
		}
		return ret;
	}

	inline std::string stringify_recipient(const Recipient& recipient) {
		if (recipient.name.empty()) {
			return '\"' + recipient.email + '\"';
		}
		else {
			return '\"' + escape(recipient.name) + '\"' + ' ' + '<' + recipient.email + '>';
		}
	}

	enum class SMTPCode : std::uint16_t {
		READY = 220,
		CLOSE = 221,
		AUTH_SUCCESS = 235,
		OK = 250,
		LOGIN = 334,
		DATA = 354
	};
	inline static std::string to_string(const SMTPCode& x) {
		return std::to_string(static_cast<std::uint16_t>(x));
	}
	inline std::ostream& operator<<(std::ostream& os, const SMTPCode& code) {
		return os << static_cast<std::uint16_t>(code);
	}
	inline std::istream& operator>>(std::istream& os, SMTPCode& code) {
		std::uint16_t x;
		os >> x;
		code = static_cast<SMTPCode>(x);
		return os;
	}

	namespace EmailType {
		struct base_tag {};
		struct plain_tag :base_tag {};
		struct html_tag :base_tag {};
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

		SMTPProcessor(const std::string& host_port, config_type config = config_type{}) :client(host_port, std::move(config)) {}

		SMTPProcessor(std::string&& host_port, config_type config = config_type{}) :client(std::move(host_port), std::move(config)) {}

	private:
		
		SMTPCode receive_code_from_server() {
			boost::asio::streambuf buf;
			std::istream recv_stream(&buf);
			client.receive_exactly(buf, 3);
			std::uint16_t code;
			recv_stream >> code;
			if (recv_stream.fail())throw std::invalid_argument("Invalid code received.");
			client.receive_until(buf, "\r\n");
#ifdef SIMPLE_TCP_PRINT_RECEIVED_RESPONSES_TO_STDERR
			cerr << code << recv_stream.rdbuf();
#endif
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
			std::forward<Callback>(callback)(write_stream);
			write_stream << "\r\n";
			client.send(write_buffer);
		}
		template <typename Callback>
		void send_data(Callback&& callback) {
			boost::asio::streambuf write_buffer;
			std::ostream write_stream(&write_buffer);
			std::forward<Callback>(callback)(write_stream);
			client.send(write_buffer);
		}
		void send_CRLF() {
			boost::asio::streambuf write_buffer;
			std::ostream write_stream(&write_buffer);
			write_stream << "\r\n";
			client.send(write_buffer);
		}

		template <typename TKey, typename TValue>
		void send_header(TKey&& key, TValue&& value) {
			boost::asio::streambuf write_buffer;
			std::ostream write_stream(&write_buffer);
			write_stream << std::forward<TKey>(key) << ": " << std::forward<TValue>(value) << "\r\n";
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
			send_data_and_CRLF("RCPT", [&](std::ostream& write_stream) {
				write_stream << "TO:<" << to << ">";
			});
			SMTPCode ret = receive_code_from_server();
			if (ret != SMTPCode::OK) throw std::invalid_argument("Invalid code received (" + to_string(ret) + ").");
		}

		void append_to(std::string&& to) {
			send_data_and_CRLF("RCPT", [&](std::ostream& write_stream) {
				write_stream << "TO:<" << std::move(to) << ">";
			});
			SMTPCode ret = receive_code_from_server();
			if (ret != SMTPCode::OK) throw std::invalid_argument("Invalid code received (" + to_string(ret) + ").");
		}

		void append_to(const char* to) {
			send_data_and_CRLF("RCPT", [&](std::ostream& write_stream) {
				write_stream << "TO:<" << to << ">";
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


	private:
		void add_sender(const Recipient& sender) {
			append_from(sender.email);
		}
		void add_recipient_impl(const Recipient& recipient) {
			append_to(recipient.email);
		}
		// from https://stackoverflow.com/a/7728728/1021959
		/*template<typename T>
		struct has_const_iterator {
		private:
			template<typename C> static char test(typename C::const_iterator*);
			template<typename C> static int  test(...);
		public:
			enum { value = sizeof(test<T>(0)) == sizeof(char) };
		};*/
		//typename std::enable_if<has_const_iterator<Container>::value>::type add_recipient(const Container &recipients)
		template <typename Container>
		std::void_t<decltype(&std::remove_reference_t<Container>::begin), decltype(&std::remove_reference_t<Container>::end)> add_recipient_impl(const Container& recipients) {
			for (const auto& recipient : recipients) {
				add_recipient_impl(recipient);
			}
		}

		template <typename T, typename ...TT>
		void add_recipient(T&& recipient, TT&& ...recipients) {
			add_recipient_impl(std::forward<T>(recipient));
			add_recipient(std::forward<TT>(recipients)...);
		}

		void add_recipient() {}

		

		std::string make_TO_field_impl(const Recipient& recipient) {
			return stringify_recipient(recipient);
		}

		template <typename...>
		struct _std_string{
			typedef std::string type;
		};
		template <typename...T>
		using _std_string_t = typename _std_string<T...>::type;

		template <typename Container>
		_std_string_t<decltype(&std::remove_reference_t<Container>::begin), decltype(&std::remove_reference_t<Container>::end)> make_TO_field_impl(const Container& recipients) {
			std::string ret;
			for (auto it = recipients.begin(); it != recipients.end(); ++it) {
				std::string ret2 = make_TO_field_impl(*it);;
				if (!ret.empty() && !ret2.empty()) ret += ", ";
				ret += std::move(ret2);
			}
			return ret;
		}

		template <typename T, typename ...TT>
		std::string make_TO_field(T&& recipient, TT&& ...recipients) {
			std::string ret = make_TO_field_impl(std::forward<T>(recipient));
			std::string ret2 = make_TO_field(std::forward<TT>(recipients)...);
			if (!ret.empty() && !ret2.empty()) ret += ", ";
			ret += std::move(ret2);
			return std::move(ret);
		}

		std::string make_TO_field() {
			return "";
		}

		inline std::tm* safe_gmtime(const std::time_t* timer, std::tm* tm_struct) noexcept {
#ifdef _MSC_VER
			gmtime_s(tm_struct, timer);
			return tm_struct;
#else
			return gmtime_r(timer, tm_struct);
#endif
		}


		inline std::string to_timestamp(const std::chrono::system_clock::time_point& timestamp) {
			std::time_t upd_time = std::chrono::system_clock::to_time_t(timestamp);
			char buf[128];
			std::tm tm_struct;
			safe_gmtime(&upd_time, &tm_struct);
			//Tue, 15 Jan 2008 16:02:43 -0500
			std::strftime(buf, sizeof buf, "%a, %e %b %Y %T +0000", &tm_struct);
			return std::string(buf);
		}

	public:


		// note: mailwriter must write a trailing \r\n
		// also, the caller must guarantee that the mailwriter writes only proper characters fitting into 7 bit encoding
		//std::void_t<decltype(std::remove_reference_t<TSubjectWriter>::operator()), decltype(std::remove_reference_t<TBodyWriter>::operator())>
		template <typename TEmailTag, typename TSubjectWriter, typename TBodyWriter, typename TSender, typename... TRecipient>
		std::enable_if_t<std::is_base_of_v<EmailType::base_tag, TEmailTag>, std::void_t<decltype(&std::remove_reference_t<TSubjectWriter>::operator()), decltype(&std::remove_reference_t<TBodyWriter>::operator())>> send_mail(TEmailTag, TSubjectWriter&& subjectwriter, TBodyWriter&& mailwriter, TSender&& sender, TRecipient&&... recipient) {
			SMTPCode ret;
			/*ret = receive_code_from_server();
			if (ret != SMTPCode::READY) throw std::invalid_argument("Invalid code received (" + to_string(ret) + ").");
			send_string("HELO", get_config().fully_qualified_domain_name());
			ret = receive_code_from_server();
			if (ret != SMTPCode::OK) throw std::invalid_argument("Invalid code received (" + to_string(ret) + ").");*/
			add_sender(sender);
			add_recipient(recipient...);
			send_string("DATA");
			ret = receive_code_from_server();
			if (ret != SMTPCode::DATA) throw std::invalid_argument("Invalid code received (" + to_string(ret) + ").");
			send_header("From", stringify_recipient(std::forward<TSender>(sender)));
			send_header("To", make_TO_field(std::forward<TRecipient>(recipient)...));
			send_data([&](std::ostream& write_stream) {
				write_stream << "Subject: ";
				std::forward<TSubjectWriter>(subjectwriter)(write_stream);
				write_stream << "\r\n";
			});
			send_header("Date", to_timestamp(std::chrono::system_clock::now()));
			if (std::is_same<std::decay_t<TEmailTag>, EmailType::html_tag>::value) {
				send_header("MIME-Version", "1.0");
				send_header("Content-Type", "text/html; charset=\"UTF-8\"");
				send_header("Content-Transfer-Encoding", "quoted-printable");
			}
			send_CRLF();
			send_data(std::forward<TBodyWriter>(mailwriter));
			send_string(".");
			ret = receive_code_from_server();
			if (ret != SMTPCode::OK) throw std::invalid_argument("Invalid code received (" + to_string(ret) + ").");
			send_string("QUIT");
			ret = receive_code_from_server();
		}

		/*template <typename TSender, typename... TRecipient>
		void send_mail(std::istream& subject, std::istream& body, TSender&& sender, TRecipient&&... recipient) {
			send_mail([&](std::ostream& write_stream) {
				write_stream << subject.rdbuf();
			}, [&](std::ostream& write_stream) {
				write_stream << body.rdbuf();
			}, std::forward<TSender>(sender), std::forward<TRecipient>(recipient)...);
		}

		template <typename TSender, typename... TRecipient>
		void send_mail(const std::string& subject, const std::string& body, TSender&& sender, TRecipient&&... recipient) {
			send_mail([&](std::ostream& write_stream) {
				write_stream << subject;
			}, [&](std::ostream& write_stream) {
				write_stream << body;
			}, std::forward<TSender>(sender), std::forward<TRecipient>(recipient)...);
		}*/

		template <typename TEmailTag, typename TSubject, typename TBody, typename TSender, typename... TRecipient>
		std::enable_if_t<std::conjunction_v<std::is_base_of<EmailType::base_tag, TEmailTag>, std::is_assignable<std::string, TSubject>, std::is_assignable<std::string, TBody>>> send_mail(TEmailTag, TSubject&& subject, TBody&& body, TSender&& sender, TRecipient&&... recipient) {
			send_mail(TEmailTag{}, [&](std::ostream& write_stream) {
				write_stream << std::forward<TSubject>(subject);
			}, [&](std::ostream& write_stream) {
				if (std::is_same<std::decay_t<TEmailTag>, EmailType::html_tag>::value) {
					// https://gist.github.com/jprobinson/69a97de73f4a7b0445d2
					std::string body_str = std::forward<TBody>(body);
					int curr_line_length = 0;
					for (auto it = body_str.cbegin(); it != body_str.cend(); ++it) {
						const char& ch = *it;
						if (curr_line_length > 72) {
							// insert '=' if prev char exists and is not a space
							if (it != body_str.cbegin() && *(it - 1) != ' ') {
								write_stream << '=';
							}
							write_stream << "\r\n";
							curr_line_length = 0;
						}
						if ((ch >= static_cast<char>(0x20)) && (ch <= static_cast<char>(0x7E)) && (ch != '=')) {
							write_stream << ch;
							// double escape newline periods
							// http://tools.ietf.org/html/rfc5321#section-4.5.2
							if (curr_line_length == 0 && ch == '.') {
								write_stream << ".";
								++curr_line_length;
							}
						}
						else
						{
							write_stream << '=';
							write_stream << uppercase << hex << ((static_cast<int>(ch) >> 4) & 0x0F);
							write_stream << uppercase << hex << (static_cast<int>(ch) & 0x0F);
							// 2 more chars bc hex and equals
							curr_line_length += 2;
						}
						++curr_line_length;
					}
					write_stream << "\r\n";
				}
				else {
					std::string body_str = std::forward<TBody>(body);
					if (body_str.empty() || body_str.back() != '\n')body_str.push_back('\n');
					for (auto it = body_str.cbegin(); it != body_str.cend(); ++it) {
						const char& ch = *it;
						if (ch == '\n' && (it == body_str.cbegin() || *(it - 1) != '\r')) {
							write_stream << '\r';
						}
						else if (ch == '.' && (it == body_str.cbegin() || *(it - 1) == '\n')) {
							write_stream << '.';
						}
						write_stream << ch;
					}
				}
			}, std::forward<TSender>(sender), std::forward<TRecipient>(recipient)...);
		}

		/*template <typename TEmailType, typename TSender, typename... TRecipient>
		std::enable_if_t<std::is_base_of_v<EmailType::base_tag, TEmailTag>> send_mail(TEmailType email_type, std::string&& subject, std::string&& body, TSender&& sender, TRecipient&&... recipient) {
			send_mail([&](std::ostream& write_stream) {
				write_stream << std::move(subject);
			}, [&](std::ostream& write_stream) {
				write_stream << std::move(body);
			}, std::forward<TSender>(sender), std::forward<TRecipient>(recipient)...);
		}

		template <typename TEmailType, typename TSender, typename... TRecipient>
		std::enable_if_t<std::is_base_of_v<EmailType::base_tag, TEmailTag>> send_mail(TEmailType email_type, const std::string& subject, const std::string& body, TSender&& sender, TRecipient&&... recipient) {
			send_mail([&](std::ostream& write_stream) {
				write_stream << subject;
			}, [&](std::ostream& write_stream) {
				write_stream << body;
			}, std::forward<TSender>(sender), std::forward<TRecipient>(recipient)...);
		}*/

		template <typename TSubjectWriter, typename TBodyWriter, typename TSender, typename... TRecipient>
		inline std::void_t<decltype(&std::remove_reference_t<TSubjectWriter>::operator()), decltype(&std::remove_reference_t<TBodyWriter>::operator())> send_mail(TSubjectWriter&& subjectwriter, TBodyWriter&& mailwriter, TSender&& sender, TRecipient&&... recipient) {
			send_mail(EmailType::plain_tag{}, std::forward<TSubjectWriter>(subjectwriter), std::forward<TBodyWriter>(mailwriter), std::forward<TSender>(sender), std::forward<TRecipient>(recipient)...);
		}

		template <typename TSubject, typename TBody, typename TSender, typename... TRecipient>
		inline std::enable_if_t<std::conjunction_v<std::is_assignable<std::string, TSubject>, std::is_assignable<std::string, TBody>>> send_mail(TSubject&& subject, TBody&& body, TSender&& sender, TRecipient&&... recipient) {
			send_mail(EmailType::plain_tag{}, std::forward<TSubject>(subject), std::forward<TBody>(body), std::forward<TSender>(sender), std::forward<TRecipient>(recipient)...);
		}
		
		
		/*template <typename TFrom, typename TTo, typename TCc, typename TBcc>
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
		}*/
	};

	template <typename Config>
	using SMTPClient = SMTPProcessor<TCPClient<Config>>;

	typedef SMTPClient<DefaultSMTPConfig<>> DefaultSMTPClient;
}