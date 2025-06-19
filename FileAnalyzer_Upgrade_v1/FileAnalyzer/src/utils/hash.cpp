#include "hash.h"
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <fstream>
#include <sstream>
#include <iomanip>

static std::string toHex(const unsigned char* hash, int length) {
    std::ostringstream oss;
    for (int i = 0; i < length; ++i)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    return oss.str();
}

std::map<std::string, std::string> computeHashes(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    std::vector<unsigned char> buffer(std::istreambuf_iterator<char>(file), {});

    unsigned char md5[MD5_DIGEST_LENGTH], sha1[SHA_DIGEST_LENGTH], sha256[SHA256_DIGEST_LENGTH];
    MD5(buffer.data(), buffer.size(), md5);
    SHA1(buffer.data(), buffer.size(), sha1);
    SHA256(buffer.data(), buffer.size(), sha256);

    return {
        {"MD5", toHex(md5, MD5_DIGEST_LENGTH)},
        {"SHA1", toHex(sha1, SHA_DIGEST_LENGTH)},
        {"SHA256", toHex(sha256, SHA256_DIGEST_LENGTH)},
    };
}
