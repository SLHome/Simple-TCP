#pragma once

#include <ostream>
#include <unordered_map>
#include <memory>

#include <boost/asio.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/functional/hash.hpp>

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
	
	template <typename Client>
	class HTTPProcessor {
	public:
		class Response {
			friend class HTTPProcessor<Client>;
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
		HTTPProcessor(Client client) :client(client) {}

		HTTPProcessor(const std::string& host_port, config_type config = config_type{}) :client(host_port, 80, std::move(config)) {}

		HTTPProcessor(std::string&& host_port, config_type config = config_type{}) :client(std::move(host_port), 80, std::move(config)) {}

		std::shared_ptr<Response> request(const std::string& request_type, const std::string& path = "/", const std::string& content = "", const std::map<std::string, std::string>& header = std::map<std::string, std::string>()) {
			std::string corrected_path = path;
			if (corrected_path == "")
				corrected_path = "/";
			if (get_config().proxy_server() != nullptr && std::is_same<socket_type, boost::asio::ip::tcp::socket>::value)
				corrected_path = "http://" + client.get_host() + ':' + std::to_string(client.get_port()) + corrected_path;

			boost::asio::streambuf write_buffer;
			std::ostream write_stream(&write_buffer);
			write_stream << request_type << " " << std::move(corrected_path) << " HTTP/1.1\r\n";
			write_stream << "Host: " << client.get_host() << "\r\n";
			for (auto& h : header) {
				write_stream << h.first << ": " << h.second << "\r\n";
			}
			if (content.size()>0)
				write_stream << "Content-Length: " << content.size() << "\r\n";
			write_stream << "\r\n";

			client.send(write_buffer);
			client.send(boost::asio::buffer(content.data(), content.size()));

			return request_read(client);
		}
	private:
		
		std::shared_ptr<Response> request_read(Client &client) {
			std::shared_ptr<Response> response(new Response()); // due to friend function, the raw pointer has to be exposed.

			size_t bytes_transferred = client.receive_until(response->content_buffer, "\r\n\r\n");

			size_t num_additional_bytes = response->content_buffer.size() - bytes_transferred;


			response->parse_header();

			auto header_it = response->header.find("Content-Length");
			if (header_it != response->header.end()) {
				auto content_length = stoull(header_it->second);
				if (content_length > num_additional_bytes) {
					client.receive_exactly(response->content_buffer, content_length - num_additional_bytes);
				}
			}
			else if ((header_it = response->header.find("Transfer-Encoding")) != response->header.end() && header_it->second == "chunked") {
				boost::asio::streambuf chunked_streambuf;
				request_read_chunked(response, chunked_streambuf);
			}
			else if (response->http_version < "1.1" || ((header_it = response->header.find("Connection")) != response->header.end() && header_it->second == "close")) {
				client.receive(response->content_buffer);
			}

			return std::move(response);
		}

		void request_read_chunked(const std::shared_ptr<Response> &response, boost::asio::streambuf &streambuf) {
			size_t bytes_transferred = client.receive_until(response->content_buffer, "\r\n");

			std::string line;
			getline(response->content, line);
			bytes_transferred -= line.size() + 1;
			line.pop_back();
			std::streamsize length = stol(line, 0, 16);

			auto num_additional_bytes = static_cast<std::streamsize>(response->content_buffer.size() - bytes_transferred);


			if ((2 + length) > num_additional_bytes) {
				client.receive_exactly(response->content_buffer, 2 + length - num_additional_bytes);
			}
			
			std::ostream stream(&streambuf);
			if (length>0) {
				std::vector<char> buffer(static_cast<size_t>(length));
				response->content.read(&buffer[0], length);
				stream.write(&buffer[0], length);
			}

			//Remove "\r\n"
			response->content.get();
			response->content.get();

			if (length>0)
				request_read_chunked(response, streambuf);
			else {
				std::ostream response_stream(&response->content_buffer);
				response_stream << stream.rdbuf();
			}
		}
	};

	template <typename Config>
	using HTTPClient = HTTPProcessor<TCPClient<Config>>;

	typedef HTTPClient<DefaultConfig> DefaultHTTPClient;
}