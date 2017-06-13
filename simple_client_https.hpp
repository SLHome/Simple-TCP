#pragma once

#include "simple_client_http.hpp"
#include "simple_client_tcp_tls.hpp"

namespace SimpleTCP {
	class SecureHTTPConfig : public SecureConfig {
	public:
		SecureHTTPConfig(const SecureHTTPConfig&) = default;
		SecureHTTPConfig(SecureHTTPConfig&&) = default;
		SecureHTTPConfig(bool verify_certificate = true, const std::string& cert_file = std::string(), const std::string& private_key_file = std::string(), const std::string& verify_file = std::string()) : SecureConfig(verify_certificate, cert_file, private_key_file, verify_file) {}
		std::uint16_t default_port() const noexcept {
			return 443;
		}
	};
	
	typedef HTTPClient<SecureHTTPConfig> SecureHTTPClient;
}