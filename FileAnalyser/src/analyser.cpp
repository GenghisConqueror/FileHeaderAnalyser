#include "analyzer.h"
#include <iostream>
#include <fstream>
#include <cmath>
#include <array>
#include <LIEF/LIEF.hpp>

FileFormat detectFileFormat(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open file!");
    }

    char magic[4] = {0};
    file.read(magic, 4);

    if (magic[0] == 0x7F && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F') {
        return FileFormat::ELF;
    } else if (magic[0] == 'M' && magic[1] == 'Z') {
        return FileFormat::PE;
    }
    return FileFormat::UNKNOWN;
}

void parseELF(const std::string& filePath) {
    auto elf = LIEF::ELF::Parser::parse(filePath);

    std::cout << "File Type: " << to_string(elf->header().file_type()) << std::endl;
    std::cout << "Entry Point: 0x" << std::hex << elf->entrypoint() << std::endl;

    std::cout << "Sections:\n";
    for (const auto& section : elf->sections()) {
        std::cout << " - " << section.name() << " (" << section.size() << " bytes)\n";
        double entropy = calculateEntropy(section.content());
        std::cout << "   [Entropy: " << entropy << "] " << (entropy > 7.0 ? "[SUSPICIOUS]" : "") << "\n";
    }
}

void parsePE(const std::string& filePath) {
    auto pe = LIEF::PE::Parser::parse(filePath);

    std::cout << "Machine: " << to_string(pe->header().machine()) << std::endl;
    std::cout << "Entry Point: 0x" << std::hex << pe->optional_header().addressof_entrypoint() << std::endl;

    std::cout << "Sections:\n";
    for (const auto& section : pe->sections()) {
        std::cout << " - " << section.name() << " (" << section.size() << " bytes)\n";
        double entropy = calculateEntropy(section.content());
        std::cout << "   [Entropy: " << entropy << "] " << (entropy > 7.0 ? "[SUSPICIOUS]" : "") << "\n";
    }
}

double calculateEntropy(const std::vector<uint8_t>& data) {
    std::array<int, 256> frequencies = {0};
    for (uint8_t byte : data) {
        frequencies[byte]++;
    }

    double entropy = 0.0;
    for (int freq : frequencies) {
        if (freq > 0) {
            double p = static_cast<double>(freq) / data.size();
            entropy -= p * std::log2(p);
        }
    }
    return entropy;
}

