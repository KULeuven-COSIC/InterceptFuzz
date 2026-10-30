#pragma once

#include <nlohmann/json.hpp>

#include <string>
#include <vector>

class FuzzConfig {
public:
    enum class FuzzMode {
        FUZZ,
        SAVE_SEEDS,
    };

public:
    FuzzMode fuzz_mode = FuzzMode::FUZZ;
    std::string seeds_path;
    std::string state_db_path;
};

NLOHMANN_JSON_SERIALIZE_ENUM( FuzzConfig::FuzzMode, {
    {FuzzConfig::FuzzMode::FUZZ, "FUZZ"},
    {FuzzConfig::FuzzMode::SAVE_SEEDS, "SAVE_SEEDS"}
})

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE_WITH_DEFAULT(
    FuzzConfig,
    fuzz_mode,
    seeds_path,
    state_db_path
)