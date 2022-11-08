#include <iostream>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <string>

#include <openssl/sha.h>
#include <openssl/evp.h>
#include <format>

template< typename T >
std::string int_to_hex(T i)
{
    std::stringstream stream;
    stream << std::setfill('0') << std::setw(8) << std::hex << i;
    return stream.str();
}

std::string sha256(const std::string str)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
	
    auto sha256 = EVP_MD_CTX_create();
    EVP_DigestInit_ex(sha256, EVP_sha256(), NULL);
    EVP_DigestUpdate(sha256, str.c_str(), str.size());
    EVP_DigestFinal_ex(sha256, hash, NULL);

    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

int main() 
{	
    std::uint32_t current = 67602058;
    std::string currentHex = int_to_hex(current);
    std::string bestDigest = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    std::string bestHex = "0";

    std::ifstream t("SGSSI-22.CB.04.txt");
    std::stringstream buffer;
    buffer << t.rdbuf();
    std::string content = buffer.str();
    //4294967296
    while (current < 268435456) //current == 268435456 change to uintptr_t and ++ to increase value instead of int_to_hex call
    {
        std::string newDigest = sha256(content + currentHex + " " + "G04");
        if (newDigest.compare(bestDigest) < 0)
        {
			bestDigest = newDigest;
			bestHex = currentHex;
			std::cout << "New best digest: " << newDigest << " with hex: " << currentHex << '\n';
        }
        currentHex = int_to_hex(++current);
    }
	
    std::string line;
    std::ifstream ini_file{ "SGSSI-22.CB.04.txt" };
    std::ofstream out_file{ "SGSSI-22.CB.04.txt", std::ios_base::binary | std::ios_base::out };
    if (ini_file && out_file)
    {
        while (getline(ini_file, line))
            out_file << line << "\n";
        out_file << bestHex << " " << "G04";
    }
    ini_file.close();
    out_file.close();

    return 0;
}