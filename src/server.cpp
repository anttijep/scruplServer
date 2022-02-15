#include <boost/asio.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ssl.hpp>
#include <stdexcept>
#include <string>
#include <filesystem>
#include <fstream>
#include <openssl/evp.h>
#include <iostream>
#include <sstream>
#include <assert.h>
#include <vector>
#include <memory>
#include <random>
#include <mutex>

#include "server.h"
#include "session.h"
using boost::asio::ip::tcp;

constexpr size_t length(const char* c)
{
	size_t i = 0;
	while (*(c++)) {++i;}
	return i;
}

std::string Server::RandomName()
{
	constexpr const char* chars = "ABCDEFGHIJKLMNOPQRSTUWVXYZabcdefghijklmnopqrstuwvxyz0123456789";
	constexpr size_t len = length(chars) - 1;
	const int fnameln = 10;
	thread_local std::mt19937 gen(std::random_device{}());

	std::uniform_int_distribution<size_t> dist(0, len);
	std::string out;
	for (size_t i = 0; i < fnameln; ++i)
	{
		out.push_back(chars[dist(gen)]);
	}
	return out + ".png";
}

std::vector<unsigned char> Server::Digestpw(const std::string& password)
{
	EVP_MD_CTX* mdctx;
	const EVP_MD* md = EVP_sha256();
	unsigned char md_value[EVP_MAX_MD_SIZE];
	unsigned int md_len;
	if (!md)
	{
		throw std::runtime_error("Unknown digest");
	}
	mdctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(mdctx, md, NULL);
	EVP_DigestUpdate(mdctx, password.c_str(), password.size());
	EVP_DigestUpdate(mdctx, this->salt.c_str(), this->salt.size());
	EVP_DigestFinal_ex(mdctx, md_value, &md_len);
	EVP_MD_CTX_free(mdctx);

	std::vector<unsigned char> out;
	for (unsigned int i = 0; i < md_len; ++i)
	{
		out.push_back(md_value[i]);
	}

	return out;
}

Server::Server(std::string hostname, unsigned short port) : hostname(std::move(hostname)), port(port), sslcontext(boost::asio::ssl::context::tls_server)
{
}

std::string Server::SaveFile(const std::string& name, const std::vector<unsigned char>& data)
{
	if (data.size() < 8)
	{
		return "Invalid file";
	}
	if (data[0] != 0x89u || data[1] != 0x50u
			|| data[2] != 0x4Eu || data[3] != 0x47u
			|| data[4] != 0x0Du || data[5] != 0x0Au
			|| data[6] != 0x1Au || data[7] != 0x0Au)
	{
		return "Invalid file format";
	}
	namespace fs = std::filesystem;
	fs::path realpath(savedir);

	if (!name.empty())
	{
		fs::path path(name);
		std::string fn(path.stem().c_str());
		if (fn.empty() || fn[0] == '.')
		{
			realpath.append(RandomName());
		}
		else
		{
			realpath.append(fn + ".png");
		}
	}
	else
	{
		realpath.append(RandomName());
	}

	if (fs::exists(realpath))
	{
		realpath.assign(savedir);
		realpath.append(RandomName());
	}

	std::ofstream stream(realpath, std::ofstream::binary);

	stream.write((char*)&data[0], data.size());

	stream.close();
	std::string urlout(publicurl);

	urlout.append(realpath.filename());
	return urlout;
}

void Server::DoAccept()
{
	acceptor->async_accept([this](const boost::system::error_code& err,
				tcp::socket sock)
			{
			if (!err)
			{
			auto ptr = std::make_unique<boost::asio::ssl::stream<tcp::socket>>(std::move(sock), sslcontext);
				std::make_shared<Session>(std::move(ptr),[this](const std::string& s) -> bool{
						try
						{
							return this->ValidatePassword(s);
						}
						catch (std::exception& ex)
						{
							std::cerr << ex.what() << "\n";
						}
						return false;

						},
						[this](const std::string& name, const std::vector<unsigned char>& data) -> std::string
						{
						try
						{
						return this->SaveFile(name, data);
						}
						catch (std::exception& ex)
						{
							std::cerr << ex.what() << "\n";
						}
						return "";
						})->Run();
			}
			DoAccept();
		});
}

void Server::Run(boost::asio::io_context& io_context)
{
	namespace fs = std::filesystem;
	if (!fs::exists(".sconfig"))
	{
		std::ofstream file(".sconfig");
		file << "/path/to/certchain\n";
		file << "/path/to/privkey\n";
		file << "/path/to/dhfile\n";
		file << "/save/file/dir/\n";
		file << "/public/url/\n";

		file.close();
		throw std::runtime_error("invalid .sconfig file");
	}

	if (!fs::exists(".pass"))
	{
		throw std::runtime_error(".pass file missing. Run with -setpw");
	}

	std::ifstream file(".sconfig");
	std::string certfile, privkey, dhfile;
	if (!std::getline(file,certfile))
	{
		throw std::runtime_error("error reading .sconfig");
	}
	if (!std::getline(file,privkey))
	{
		throw std::runtime_error("error reading .sconfig");
	}

	if (!std::getline(file,dhfile))
	{
		throw std::runtime_error("error reading .sconfig");
	}
	if (!std::getline(file,savedir))
	{
		throw std::runtime_error("error reading .sconfig");
	}
	std::getline(file, publicurl);
	if (certfile.empty() || privkey.empty() || dhfile.empty() || savedir.empty() || publicurl.empty())
	{
		throw std::runtime_error("error reading .sconfig");
	}


	file.close();

	std::ifstream pwfile(".pass",std::ios::binary);

	this->spassword.assign(std::istreambuf_iterator<char>(pwfile), std::istreambuf_iterator<char>());
	pwfile.close();

	if (this->spassword.size() != 32)
	{
		throw std::runtime_error("invalid .pass file");
	}

	sslcontext.set_options(boost::asio::ssl::context::default_workarounds
		   | boost::asio::ssl::context::no_sslv2 | boost::asio::ssl::context::no_sslv3
		   | boost::asio::ssl::context::single_dh_use);

	sslcontext.use_certificate_chain_file(certfile);
	sslcontext.use_private_key_file(privkey, boost::asio::ssl::context::pem);
	sslcontext.use_tmp_dh_file(dhfile);

	acceptor = std::make_unique<tcp::acceptor>(io_context, tcp::endpoint(tcp::v4(), port));
	DoAccept();
}

void Server::SetPassword(const std::string& password)
{
	std::ofstream pwfile(".pass", std::ios::binary);

	auto pw = Digestpw(password);

	for (size_t i = 0; i < pw.size(); ++i)
		pwfile << pw[i];

	pwfile.close();
}

bool Server::ValidatePassword(const std::string& password)
{
	auto pw = Digestpw(password);
	bool isSame = pw.size() == this->spassword.size();
	for (unsigned int i = 0; i < pw.size(); ++i)
	{
		if (this->spassword[i] != pw[i])
		{
			isSame = false;
		}
	}
	return isSame;
}




