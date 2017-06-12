#pragma once

#include <utility>
#include <string>
#include <memory>
#include <cstdint>
#include <cstdlib>

namespace SimpleTCP {

	inline std::pair<std::string, std::uint16_t> parse_host_port(const std::string &host_port, std::uint16_t default_port) noexcept {
		std::pair<std::string, std::uint16_t> parsed_host_port;
		size_t host_end = host_port.find(':');
		if (host_end == std::string::npos) {
			parsed_host_port.first = host_port;
			parsed_host_port.second = default_port;
		}
		else {
			parsed_host_port.second = static_cast<std::uint16_t>(std::strtoul(host_port.c_str() + host_end + 1, nullptr, 10));
			parsed_host_port.first = host_port.substr(0, host_end);
		}
		return std::move(parsed_host_port);
	}

	inline std::pair<std::string, std::uint16_t> parse_host_port(std::string &&host_port, std::uint16_t default_port) noexcept {
		std::pair<std::string, std::uint16_t> parsed_host_port;
		size_t host_end = host_port.find(':');
		if (host_end == std::string::npos) {
			parsed_host_port.first = std::move(host_port);
			parsed_host_port.second = default_port;
		}
		else {
			parsed_host_port.second = static_cast<unsigned short>(std::strtoul(host_port.c_str() + host_end + 1, nullptr, 10));
			host_port.resize(host_end);
			parsed_host_port.first = std::move(host_port);
		}
		return std::move(parsed_host_port);
	}

	inline std::pair<std::string, std::uint16_t> parse_host_port(const char *const host_port, std::uint16_t default_port) {
		return parse_host_port(std::string(host_port), default_port);
	}


	template <typename Callback>
	inline void make_timeout_timer(boost::asio::deadline_timer& timer, size_t timeout, Callback&& callback) {
		//boost::asio::deadline_timer timer(io_service);
		timer.expires_from_now(boost::posix_time::seconds(timeout));
		timer.async_wait(std::forward<Callback>(callback));
	}
}