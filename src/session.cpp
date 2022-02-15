
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include <openssl/x509.h>
#include <string>
#include <vector>
#include <memory>
#include "session.h"
#include "server.h"
#include <functional>
#include <iostream>


Session::Session(std::unique_ptr<boost::asio::ssl::stream<tcp::socket>> socket, std::function<bool(std::string&)> verifypw,
		std::function<std::string(std::string&, std::vector<unsigned char>&)> writefile) : sock(std::move(socket)), verifypw(verifypw) ,writefile(writefile)
{

}

void Session::Run()
{
	auto self = shared_from_this();
	sock->async_handshake(boost::asio::ssl::stream_base::server,
		[this, self](const boost::system::error_code& e)
		{
		if (!e)
		{
		    state = Connection::AUTH;
			Read();
		}});
}

void Session::Write(std::string to)
{
	auto self = shared_from_this();
	boost::asio::async_write(*sock, boost::asio::buffer(to), 
			[self](const boost::system::error_code e, std::size_t)
			{
			if (!e)
			{
			}
			});
}

void Session::Read()
{
	auto self = shared_from_this();


	switch (state)
	{
		case Connection::AUTH:
			sock->async_read_some(boost::asio::buffer(this->buffer), [this,self](const boost::system::error_code& e, std::size_t length)
			{
			if (!e)
			{
				msg.insert(msg.end(), buffer.begin(), buffer.begin() + length);
				unsigned char pwlength = msg[0];


				if (pwlength < MIN_PW_LENGTH)
				{
					state = Connection::END;
					Write("NO");
					return;
				}

				if (msg.size() < pwlength - 1u)
				{
					Read();
					return;
				}

				std::string password;
				password.resize(pwlength);
				memcpy(&password[0], &msg[1], pwlength);
				if (!verifypw(password))
				{
					state = Connection::INVALIDPASSWORD;
					Write("NO");
					return;
				}
				volatile unsigned char* p = &msg[0]; 
				for (size_t i = 0; i < msg.size(); ++i)
				{
					*(p + i) = 0;
				}
				msg.resize(0);
				state = Connection::GETNAME;
				Write("OK");
				Read();
			}

			});
			break;
		case Connection::GETNAME:
			sock->async_read_some(boost::asio::buffer(this->buffer), [this, self](const boost::system::error_code& e, std::size_t length)
			{
			if (!e)
			{
				msg.insert(msg.end(), buffer.begin(), buffer.begin() + length);
				if (msg.size() >= 3u)
				{
					unsigned char fnamelength = msg[0];

					if (msg.size() >= sizeof(unsigned char) + sizeof(uint32_t)  + fnamelength) 
					{
						uint32_t ln = 0;
						auto index = sizeof(unsigned char) + fnamelength;
						memcpy(&ln, &msg[index], sizeof(uint32_t));
						datalength = ntohl(ln);
						if (fnamelength > 0)
						{
							fnameout.assign(&msg[1], &msg[1] + fnamelength);
						}

						auto offset = fnamelength + sizeof(unsigned char) + sizeof(uint32_t);
						size_t i = 0;
						for (; offset < msg.size(); ++offset, ++i)
						{
							msg[i] = msg[offset];
						}
						msg.resize(i);
						state = Connection::GETFILE;
					}
				}
				Read();
			}
			});
			break;
		case Connection::GETFILE:
		{
			if (msg.size() >= datalength)
			{
				state = Connection::END;
				std::string url =  writefile(fnameout, msg);
				std::string resp;
				uint16_t ln = htons(url.size() & 0xffffu);
				resp.resize(sizeof(uint16_t));
				memcpy(&resp[0], &ln, sizeof(uint16_t));
				resp.insert(resp.end(), url.begin(), url.end());
				Write(resp);
				break;
			}
			sock->async_read_some(boost::asio::buffer(this->buffer), [this, self](const boost::system::error_code& e, std::size_t length)
			{
			if (!e)
			{
				msg.insert(msg.end(), buffer.begin(), buffer.begin() + length);
				Read();
			}
			});
		}
			break;
		case Connection::END:
			break;
		case Connection::INVALIDPASSWORD:
			std::cout << "Invalid password\n";
			break;
	}

}



