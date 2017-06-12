//#define BOOST_ASIO_ENABLE_HANDLER_TRACKING

#include "simple_client_smtp.hpp"

//Added for the json-example
#define BOOST_SPIRIT_THREADSAFE
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

//Added for the default_resource example
#include <algorithm>
#include <iostream>
#ifdef HAVE_OPENSSL
#include "crypto.hpp"
#endif

using namespace std;
//Added for the json-example:
using namespace boost::property_tree;

typedef SimpleTCP::SMTPClient<SimpleTCP::DefaultSMTPConfig> SmtpClient;
//typedef SimpleWeb::Client<SimpleWeb::HTTP> HttpClient;


int main() {
    
    
    //Client examples
	SmtpClient client("aspmx.l.google.com:25");
	client.send_mail("test@example.com", "recipient@gmail.com", "From: \"Bob Example\" <test@example.com>\r\nTo: Alice Example <recipient@gmail.com>\r\nSubject: Test message\r\n\r\nHello Alice.\r\nThis is a test message with 5 header fields and 4 lines in the message body.\r\nYour friend,\r\nBob\r\n.");
	int a;
	cin >> a;
    
    return 0;
}