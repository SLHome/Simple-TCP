//#define BOOST_ASIO_ENABLE_HANDLER_TRACKING
#define SIMPLE_TCP_PRINT_RECEIVED_RESPONSES_TO_STDERR

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

typedef SimpleTCP::DefaultSMTPClient SmtpClient;
//typedef SimpleWeb::Client<SimpleWeb::HTTP> HttpClient;


int main() {
    
    
    //Client examples
	SmtpClient client("aspmx.l.google.com:25");
	client._send_mail("Test message", "Hello Alice.\r\nThis is a test message with 5 header fields and 4 lines in the message body.\r\nYour friend,\r\nBob\r\n", SimpleTCP::Recipient(SimpleTCP::RecipientType::FROM, "Bob Example", "test@example.com"), SimpleTCP::Recipient(SimpleTCP::RecipientType::TO, "Alice Example", "recipient@example.com"));
	cerr << "Done Sending." << endl;
	int a;
	cin >> a;
    
    return 0;
}