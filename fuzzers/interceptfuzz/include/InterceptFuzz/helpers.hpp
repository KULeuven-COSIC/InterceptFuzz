#pragma once

#include <filesystem>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>

template <typename C>
inline bool
parse_json_file_into_class_instance(const std::filesystem::path &json_file_path,
                                    C &class_instance) noexcept {
  std::ifstream json_file(json_file_path);
  if (!json_file.is_open()) {
    std::cerr << "Could not open the file: " << json_file_path << std::endl;
    return false;
  }
  nlohmann::json json_obj;
  try {
    json_file >> json_obj;
    class_instance = json_obj.get<C>();
  } catch (std::exception &ex) {
    std::cerr << "Caught an exception during json parsing: " << ex.what()
              << std::endl;
    return false;
  }
  return true;
}

template <typename C>
inline bool
write_class_instance_to_json_file(C &class_instance,
                                  const std::filesystem::path &json_file_path) {
  std::ofstream json_file(json_file_path);
  if (!json_file.is_open()) {
    std::cerr << "Could not open the file: " << json_file_path << std::endl;
    return false;
  }
  try {
    nlohmann::json j = class_instance;
    json_file << std::setw(4) << j;
  } catch (std::exception &ex) {
    std::cerr << "Caught an exception during json loading: " << ex.what()
              << std::endl;
    return false;
  }
  return true;
}

inline
bool write_buffer_to_file(const void* buffer, std::size_t length, const std::filesystem::path& filename) {
    std::ofstream out(filename, std::ios::binary);
    if (!out) {
        return false; // failed to open file
    }
    out.write(static_cast<const char*>(buffer), static_cast<std::streamsize>(length));
    return out.good();
}

inline
bool check_if_path_exists(const std::filesystem::path &path)
{
    try {
        if (!std::filesystem::exists(path)) return false;
    } catch (std::exception& ex) {
        std::cerr << "Caught exception during check_if_path_exists(): " << ex.what() << std::endl;
        return false;
    }
    return true;
}

inline
bool create_directories_if_not_exist(const std::filesystem::path& path) {
    try {
        /* If path is empty, return false. */
        if (path.empty()) return false;
        /* First check if the directories exist */
        if (check_if_path_exists(path)) return true;
        /* If doesn't exist, try to create the directory */
        if (!std::filesystem::create_directories(path)) return false;
        /* Set the permissions */
        std::filesystem::permissions(path, std::filesystem::perms::all);
    } catch(std::exception& ex) {
        std::cerr << "Caught exception during create_directories_if_not_exist: " << ex.what() << std::endl;
        return false;
    }
    return true;
}