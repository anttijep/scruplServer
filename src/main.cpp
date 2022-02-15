#include <boost/asio.hpp>

#include <openssl/bio.h>
#include <openssl/bioerr.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <iostream>
#include <string>
#include "server.h"


int main(int argc, char** argv)
{

	SSL_load_error_strings();
	ERR_load_BIO_strings();
	OpenSSL_add_all_algorithms();
	try
	{
		std::string arg;
		unsigned short port = 42715;
		if (argc >= 2)
		{
			arg.assign(argv[1]);
			try
			{
				port = std::stoi(arg);
			}
			catch (std::exception& ex)
			{
			}
		}
		Server s("", port);

		if (arg == "-setpw")
		{
			std::string pw;
			std::cout << "password: ";
			std::getline(std::cin, pw);
			std::cout << "\n";
			s.SetPassword(pw);
			return 0;
		}
		std::cout << "Running Server on port: " << port << "\n";
		boost::asio::io_context io_context;

		s.Run(io_context);
		io_context.run();

	}
	catch (std::exception& ex)
	{
		std::cerr << ex.what() << "\n";
		return -1;
	}
	return 0;
}



