#pragma once

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include <string>
#include <vector>
#include <memory>

#include "server.h"
#include <functional>

using boost::asio::ip::tcp;


enum class Connection
{
	AUTH,
	GETNAME,
	GETFILE,
	END,
	INVALIDPASSWORD
};


class Session : public std::enable_shared_from_this<Session>
{
	std::unique_ptr<boost::asio::ssl::stream<tcp::socket>> sock;
	std::function<bool(std::string&)> verifypw = nullptr;
	std::function<std::string(std::string&, std::vector<unsigned char>&)> writefile = nullptr;

	Connection state;
	std::vector<unsigned char> msg;

	const static int BUFFER_SIZE = 1024;
	const static int MIN_PW_LENGTH = 5;
	std::array<unsigned char, BUFFER_SIZE> buffer;
	std::string fnameout;
	uint32_t datalength = 0;


public:
	Session(std::unique_ptr<boost::asio::ssl::stream<tcp::socket>> socket, std::function<bool(std::string&)> verifypw,
			std::function<std::string(std::string&, std::vector<unsigned char>&)> writefile); 

	void Run();
	void Write(std::string to);
	void Read();
};





