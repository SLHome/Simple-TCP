#pragma once

#include "simple_client_http.hpp"
#include "simple_client_tcp_tls.hpp"

namespace SimpleTCP {
	typedef HTTPClient<DefaultConfig> DefaultHTTPClient;
}