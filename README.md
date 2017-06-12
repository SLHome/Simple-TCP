Simple-TCP
=================

A simple, cross-platform HTTP and SMTP client library implemented using C++11 and Boost.Asio.

This project was forked from [eidheim/Simple-Web-Server](https://github.com/eidheim/Simple-Web-Server), and the HTTP client library was refractored to extract the underlying TCP protocol for use with SMTP.  The primary aim of this project is to make an SMTP client based on Boost.Asio.  As an added benefit, the SMTP and HTTP clients run on the same Boost.Asio and TCP client code, which may make maintenence and debugging easier.

Note: It would be possible to build upon the TCP client to make an FTP/FTPS client (feel free to send a PR if you have done that).

### Features (when complete)

* Platform independent
* SMTPS and HTTPS support
* HTTP persistent connection (for HTTP/1.1)
* Supports chunked transfer encoding
* Timeouts
* HTML emails

### Usage

See smtp_examples.cpp, smtps_examples.cpp, http_examples.cpp, https_examples.cpp for example usage.

Include the relavent file(s), e.g. simple_client_smtp.hpp for non-encrypted SMTP.

Note that you will need to replace the "To:" parameter with your own email to receive the messages.

### Dependencies

* Boost C++ libraries
* For SMTPS/HTTPS: OpenSSL libraries 

### Compile and run

Compile with a C++11 compliant compiler:
```sh
mkdir build
cd build
cmake ..
make
cd ..
```

*Everything below this sentence has not been updated.*

#### HTTP

Run the server and client examples: `./build/http_examples`

Direct your favorite browser to for instance http://localhost:8080/

#### HTTPS

Before running the server, an RSA private key (server.key) and an SSL certificate (server.crt) must be created. Follow, for instance, the instructions given here (for a self-signed certificate): http://www.akadia.com/services/ssh_test_certificate.html

Run the server and client examples: `./build/https_examples`

Direct your favorite browser to for instance https://localhost:8080/

