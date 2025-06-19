#ifndef ANALYZER_H
#define ANALYZER_H

#include <string>
#include <vector>
#include <map>

enum class FileFormat {
    ELF,
    PE,
    UNKNOWN
};

struct SectionInfo {
    std::string name;
    size_t size;
    double entropy;
};

struct AnalysisResult {
    std::string file_path;
    FileFormat format;
    std::map<std::string, std::string> hashes;
    std::vector<SectionInfo> sections;
};

AnalysisResult analyzeFile(const std::string& filePath);

#endif
