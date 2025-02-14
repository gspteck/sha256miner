#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <iomanip>
#include <cmath>

#include <boost/asio.hpp>
#include <boost/asio/ts/buffer.hpp>
#include <boost/asio/ts/internet.hpp>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>

using json = nlohmann::json;

using boost::asio::ip::tcp;
using boost::asio::io_context;
using boost::system::error_code;


std::vector<std::string> sub_details;
std::string extranonce1;
int extranonce2_size;

std::string job_id;
std::string prevhash;
std::string coinb1;
std::string coinb2;
std::vector<std::string> merkle_branch;
std::string version;
std::string nbits;
std::string ntime;
bool clean_jobs;

std::string target;
std::string extranonce2;

int hash_count = 0;

std::string address = "bitcoincash:qzhpcr6w28uq3hr29c86nq5c9tdltawszgmz3r447z";
std::string password = "x";
std::string workerName = "MainTesting";

std::string poolHost = "bch.2miners.com";
std::string poolPort = "7070";

std::string sendJsonRPC(tcp::socket& socket, const json& request) {
    	std::string requestStr = request.dump() + "\n";
	std::cout << "Sending: " << requestStr << std::endl;

	error_code write_error;
	boost::asio::write(socket, boost::asio::buffer(requestStr), write_error);
	if (write_error) {
		std::cerr << "Write error: " << write_error.message() << std::endl;
		return "";
	}

	boost::asio::streambuf response_buf;
	error_code read_error;
	boost::asio::read_until(socket, response_buf, "\n", read_error);
	if (read_error && read_error != boost::asio::error::eof) {
		std::cerr << "Read error: " << read_error.message() << std::endl;
		return "";
	}
	
	std::string responseStr(boost::asio::buffers_begin(response_buf.data()),
			boost::asio::buffers_end(response_buf.data()));
	response_buf.consume(response_buf.data().size());
	std::cout << "Received: " << responseStr << std::endl;

	return responseStr;
}

tcp::socket connectToServer() {
	std::cout << "Connecting to mining server at: " << poolHost << ":" << poolPort << std::endl;

	io_context io_context;
	tcp::resolver resolver(io_context);

	error_code resolve_error;
	tcp::resolver::results_type endpoints = resolver.resolve(poolHost, poolPort, resolve_error);
	if (resolve_error) {
		std::cerr << "Error resolving hostname: " << resolve_error.message() << std::endl;
	}

	tcp::socket socket(io_context);
	error_code connect_error;
	connect(socket, endpoints, connect_error);
	if (connect_error) {
		std::cerr << "Error connecting to server: " << connect_error.message() << std::endl;
		return tcp::socket(io_context);
	}

	std::cout << "Successfully connected to " << poolHost << ":" << poolPort << std::endl;
	
	return socket;
    	
}

std::string subscribeForWork(tcp::socket& socket) {
	json request = {
		{"jsonrpc", "2.0"},
		{"method", "mining.subscribe"},
		{"params", {}},
		{"id", 1}
	};
	std::string subscribeResponse = sendJsonRPC(socket, request);
	json jsonResponse = json::parse(subscribeResponse);
	if (!jsonResponse["error"].is_null()) {
		for (int i = 0; i < jsonResponse["result"][0].size(); i++) {
			sub_details.push_back(jsonResponse["result"][i]);
		}
		extranonce1 = jsonResponse["result"][1];
		extranonce2_size = jsonResponse["result"][2];
	}
	
	return subscribeResponse;	
}

std::string authorizeForWork(tcp::socket& socket) {
	json request = {
		{"jsonrpc", "2.0"},
		{"method", "mining.authorize"},
		{"params", {address, password, workerName}},
		{"id", 2}
	};
	std::string authorizeResponse = sendJsonRPC(socket, request);
	
	return authorizeResponse;	
}

// Helper function to convert a hex string to a vector of bytes
std::vector<unsigned char> hex_to_bytes(std::string hex) {
    std::vector<unsigned char> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byte_str = hex.substr(i, 2);
        unsigned char byte = (unsigned char)std::stoul(byte_str, nullptr, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

// Helper function to convert a vector of bytes to a hex string (optional, for debugging)
std::string bytes_to_hex(std::vector<unsigned char>& bytes) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (unsigned char byte : bytes) {
        ss << std::setw(2) << (int)byte;
    }
    return ss.str();
}

// Helper function for little endian conversion of a hex string
std::string little_endian(std::string& hex) {
    std::string little_endian_hex;
    for (size_t i = 0; i < hex.length(); i += 2) {
        little_endian_hex = hex.substr(i, 2) + little_endian_hex;
    }
    return little_endian_hex;
}

// Function to perform SHA-256 hashing
std::vector<unsigned char> sha256(std::vector<unsigned char>& data) {
   	EVP_MD_CTX* context = EVP_MD_CTX_new();
    	if (context == nullptr) {
	    	return std::vector<unsigned char>();
    	}
    	if (EVP_DigestInit_ex(context, EVP_sha256(), NULL) != 1) {
        	EVP_MD_CTX_free(context);
        	return std::vector<unsigned char>();
    	}
    	unsigned int length = data.size();
    	if (EVP_DigestUpdate(context, data.data(), length) != 1) {
        	EVP_MD_CTX_free(context);
        	return std::vector<unsigned char>();
    	}
    	unsigned int hash_len = EVP_MD_size(EVP_sha256());
    	std::vector<unsigned char> hash(hash_len);
    	if (EVP_DigestFinal_ex(context, hash.data(), &hash_len) != 1) {
        	EVP_MD_CTX_free(context);
        	return std::vector<unsigned char>();
    	}
    	EVP_MD_CTX_free(context);
    	return hash; 
}

void submitValidHash(tcp::socket& socket, uint32_t& nonce, std::string& hash) {
    	json request;
    	request["jsonrpc"] = "2.0";
    	request["id"] = 1;
    	request["method"] = "mining.submit";
	request["params"] = {address, job_id, extranonce2, ntime, nonce};

    	std::string response = sendJsonRPC(socket, request);

    	if (!response.empty()) {
		json responseJson = json::parse(response);
        	if (responseJson.contains("result") && responseJson["result"].is_boolean()) {
            		if (responseJson["result"]) {
                		std::cout << "Hash submitted successfully!" << std::endl;
            		} else {
                		std::cout << "Failed to submit the hash." << std::endl;
            	}
        }
    }
}

void hashing(tcp::socket& socket) {
	// Get Target
	int exponent = std::stoi(nbits.substr(0, 2), nullptr, 16);
	int trailing_zeros_count = exponent - 3;
    	std::string trailing_zeros(trailing_zeros_count * 2, '0');
    	std::string hex_part = nbits.substr(2);

    	target.insert(target.begin(), 64 - hex_part.length(), '0');
    	target += hex_part;
    	target += trailing_zeros;
	std::cout << "Job target: " << target << std::endl;

	// Get extranonce2
	extranonce2 = std::string(extranonce2_size, '0');
	std::cout << "Extranonce2: " << extranonce2 << std::endl;
	
	// Get coinbase hash bin 
	std::string coinbase = coinb1 + extranonce1 + extranonce2 + coinb2;
	std::vector<unsigned char> coinbase_bytes = hex_to_bytes(coinbase);
	std::vector<unsigned char> first_hash = sha256(coinbase_bytes);
	std::vector<unsigned char> coinbase_hash_bin = sha256(first_hash);
	std::cout << "Double SHA-256 Hash: " << bytes_to_hex(coinbase_hash_bin) << std::endl;

	// Get merkle
	std::vector<unsigned char> merkle_root = coinbase_hash_bin;
	for (const std::string& h : merkle_branch) {
                std::vector<unsigned char> h_bytes = hex_to_bytes(h);
        	std::vector<unsigned char> data_to_hash = merkle_root;
        	data_to_hash.insert(data_to_hash.end(), h_bytes.begin(), h_bytes.end());
        	std::vector<unsigned char> first_hash = sha256(data_to_hash);
        	merkle_root = sha256(first_hash);
    	}
	std::string merkle_root_hex = bytes_to_hex(merkle_root);
    	std::string merkle_root_little_endian = little_endian(merkle_root_hex);
    	std::cout << "Merkle_root: " << merkle_root_little_endian << std::endl;

	auto start_time = std::chrono::high_resolution_clock::now();
	for (uint32_t nonce = 0; nonce <= 0xFFFFFFFF; nonce++) {
		std::stringstream ss;
        	ss << std::hex << std::setw(8) << std::setfill('0') << nonce;
		std::string nonce_hex = ss.str();

  		// Get block header
		std::string blockheader = version + prevhash + bytes_to_hex(merkle_root) + nbits + ntime + nonce_hex + "000000800000000000000000000000000000000000000000000000000000000000000000000000000000000080020000";

		// Get Hash
		std::vector<unsigned char> blockheader_bytes = hex_to_bytes(blockheader);
		std::vector<unsigned char> first_hash = sha256(blockheader_bytes);
		std::vector<unsigned char> second_hash = sha256(first_hash);
		std::string hash = bytes_to_hex(second_hash);
		
		hash_count++;
		auto end_time = std::chrono::high_resolution_clock::now();
		auto elapsed_time = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time).count();
		int hashrate = static_cast<int>(std::round((double)hash_count / (elapsed_time / 1000000.0)));
		
		std::cout << "\rHashrate: " << hashrate << " H/s" << std::flush;

		if (hash < target) {
			std::cout << "\n\nHashrate: " << hashrate << " H/s | Calculated Hashes: " << nonce << "\n" << "Found a valid hash: " << hash << "\n\n" << std::endl;
			submitValidHash(socket, nonce, hash);
			break;
		}	
	}
}

void handleServerResponse(tcp::socket& socket) {
	boost::asio::streambuf response_buf;
	error_code read_error;
	boost::asio::read_until(socket, response_buf, "\n", read_error);
	if (read_error && read_error != boost::asio::error::eof) {
		std::cerr << "Read error: " << read_error.message() << std::endl;
		return;
	}
	
	std::string responseStr(boost::asio::buffers_begin(response_buf.data()),
			boost::asio::buffers_end(response_buf.data()));
	response_buf.consume(response_buf.data().size());
	std::cout << "Received: " << responseStr << std::endl;
	
	try {
		json responseJson = json::parse(responseStr);
		if (responseJson.contains("method") && responseJson["method"] == "mining.notify") {
			// Extract job parameters
			auto params = responseJson["params"];
		        job_id = params[0];
		        prevhash = params[1];
		        coinb1 = params[2];
		        coinb2 = params[3];
			merkle_branch.clear();
		        for (auto& element : params[4]) {
			        merkle_branch.push_back(element.get<std::string>());
		        }
		        version = params[5];
		        nbits = params[6];
		        ntime = params[7];
		        clean_jobs = params[8];
			// Print the job details
			std::cout << "New Job Received!" << std::endl;
            		std::cout << "Job ID: " << job_id << std::endl;
			std::cout << "Prevhash: " << prevhash << std::endl;
            		std::cout << "Coinb1: " << coinb1 << std::endl;
            		std::cout << "Coinb2: " << coinb2 << std::endl;
            		std::cout << "Merkle Branch: " << std::endl;
            		for (const auto& branch : merkle_branch) {
                		std::cout << "  " << branch << std::endl;
            		}
            		std::cout << "Version: " << version << std::endl;
            		std::cout << "Nbits: " << nbits << std::endl;
            		std::cout << "Ntime: " << ntime << std::endl;
            		std::cout << "Clean Jobs: " << (clean_jobs ? "true" : "false") << std::endl;

			hashing(socket);	
		} else {
			std::cout << "Received a non-mining.notify message." << std::endl;
		}
	} catch (const std::exception& e) {
		std::cerr << "Error parsing JSON: " << e.what() << std::endl;
	}

}

int main() {
	try {
		//  Connect to pool server
		tcp::socket socket = connectToServer();
		if (socket.is_open()) {
			std::cout << "Socket is open and connected." << std::endl;

			std::string subscribeResponse = subscribeForWork(socket);
					
			std::string authorizeResponse = authorizeForWork(socket);
			while (socket.is_open()) {
				handleServerResponse(socket);
			}

			
			socket.close();
		} else {
			std::cout << "Failed to connect to the server." << std::endl;
		}
	} catch (std::exception& e) {
		std::cerr << "Exception: " << e.what() << std::endl;
	}

	return 0;
}
