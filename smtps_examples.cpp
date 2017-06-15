//#define BOOST_ASIO_ENABLE_HANDLER_TRACKING
#define SIMPLE_TCP_PRINT_RECEIVED_RESPONSES_TO_STDERR

#include "simple_client_smtps.hpp"

//Added for the json-example
#define BOOST_SPIRIT_THREADSAFE
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

//Added for the default_resource example
#include <algorithm>
#include <iostream>
#include <fstream>
#ifdef HAVE_OPENSSL
#include "crypto.hpp"
#endif

using namespace std;
//Added for the json-example:
using namespace boost::property_tree;

typedef SimpleTCP::SecureUsernamePasswordSMTPClient SmtpClient;
//typedef SimpleWeb::Client<SimpleWeb::HTTP> HttpClient;


int main() {


	//Client examples
	try {
		
		std::string server_endpoint, display_name, email_address, password;
		{
			std::ifstream in("D:\\Bernard\\Documents\\smtp_credentials.txt");
			getline(in, server_endpoint);
			getline(in, display_name);
			getline(in, email_address);
			getline(in, password);
		}
		
		SmtpClient client(server_endpoint, SimpleTCP::SecureSMTPConfig<SimpleTCP::UsernamePasswordAuthAgent>{ SimpleTCP::UsernamePasswordAuthAgent{ email_address,password }, false });
		// "From: \"Bob Example\" <test@example.com>\r\nTo: Alice Example <recipient@gmail.com>\r\nSubject: Test message\r\n\r\nHello Alice.\r\nThis is a test message with 5 header fields and 4 lines in the message body.\r\nYour friend,\r\nBob\r\n."
		client.send_mail("Test message", "Hello Alice.\r\nThis is a test message with 5 header fields and 4 lines in the message body.\r\nYour friend,\r\nBob\r\n.\r\n", SimpleTCP::Recipient(SimpleTCP::RecipientType::FROM, display_name, email_address), SimpleTCP::Recipient(SimpleTCP::RecipientType::TO, "Alice Example", "test@gmail.com"));
		cerr << "Done Sending." << endl;
	}
	catch (boost::system::system_error& e) {
		cerr << e.what() << endl;
	}
	int a;
	cin >> a;

	return 0;
}