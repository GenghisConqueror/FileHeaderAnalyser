#include "json_output.h"
#include <nlohmann/json.hpp>

using json = nlohmann::json;

std::string generateJSONReport(const AnalysisResult& result) {
    json j;
    j["file_path"] = result.file_path;
    j["format"] = (result.format == FileFormat::ELF) ? "ELF" :
                  (result.format == FileFormat::PE) ? "PE" : "UNKNOWN";
    j["hashes"] = result.hashes;

    for (const auto& sec : result.sections) {
        j["sections"].push_back({
            {"name", sec.name},
            {"size", sec.size},
            {"entropy", sec.entropy},
            {"suspicious", sec.entropy > 7.0}
        });
    }

    return j.dump(4);
}
