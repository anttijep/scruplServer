#pragma once

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include <string>
#include <vector>
#include <memory>
#include <mutex>




class Server
{
	std::string hostname;
	std::vector<unsigned char> spassword;

	std::string salt = "dj9n9o242vsgj90h9wbni9";

	unsigned short port;
	std::vector<unsigned char> Digestpw(const std::string& password);
	std::unique_ptr<boost::asio::ip::tcp::acceptor> acceptor = nullptr;
	boost::asio::ssl::context sslcontext;

	std::string publicurl;
	std::string savedir;

	void DoAccept();

	std::string RandomName();

public:
	bool ValidatePassword(const std::string& password);
	Server(std::string hostname, unsigned short port);
	void Run(boost::asio::io_context& io_context);
	void SetPassword(const std::string& password);
	std::string SaveFile(const std::string& name, const std::vector<unsigned char>& data);
};


