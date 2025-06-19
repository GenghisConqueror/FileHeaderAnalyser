#include "analyzer.h"
#include "utils/hash.h"
#include <LIEF/LIEF.hpp>
#include <fstream>
#include <array>
#include <cmath>

static double calculateEntropy(const std::vector<uint8_t>& data) {
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

static FileFormat detectFileFormat(const std::string& filePath) {
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

AnalysisResult analyzeFile(const std::string& filePath) {
    AnalysisResult result;
    result.file_path = filePath;
    result.hashes = computeHashes(filePath);

    FileFormat format = detectFileFormat(filePath);
    result.format = format;

    if (format == FileFormat::ELF) {
        auto elf = LIEF::ELF::Parser::parse(filePath);
        for (const auto& section : elf->sections()) {
            SectionInfo si;
            si.name = section.name();
            si.size = section.size();
            si.entropy = calculateEntropy(section.content());
            result.sections.push_back(si);
        }
    } else if (format == FileFormat::PE) {
        auto pe = LIEF::PE::Parser::parse(filePath);
        for (const auto& section : pe->sections()) {
            SectionInfo si;
            si.name = section.name();
            si.size = section.size();
            si.entropy = calculateEntropy(section.content());
            result.sections.push_back(si);
        }
    }

    return result;
}
