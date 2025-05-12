#ifndef ANALYZER_H
#define ANALYZER_H

#include <string>
#include <vector>

enum class FileFormat {
    ELF,
    PE,
    UNKNOWN
};

FileFormat detectFileFormat(const std::string& filePath);
void parseELF(const std::string& filePath);
void parsePE(const std::string& filePath);
double calculateEntropy(const std::vector<uint8_t>& data);

#endif 

