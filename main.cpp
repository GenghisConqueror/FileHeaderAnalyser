#include "analyzer.h"

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <file>" << std::endl;
        return 1;
    }

    std::string filePath = argv[1];

    try {
        FileFormat format = detectFileFormat(filePath);
        if (format == FileFormat::ELF) {
            parseELF(filePath);
        } else if (format == FileFormat::PE) {
            parsePE(filePath);
        } else {
            std::cerr << "Unknown file format!" << std::endl;
        }
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
        return 1;
    }

    return 0;
}
