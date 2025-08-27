cmake_minimum_required(VERSION 3.16)
project(SecureMessaging VERSION 1.0.0 LANGUAGES CXX)

# ---- C++ standardı ----
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ---- Build Type ----
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# ---- Compiler flags ----
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -Wall -Wextra -Wpedantic")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG -Wall")

# ---- Platform-specific ayarlar ----
if(WIN32)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
endif()

# ---- Kütüphane Bağımlılıkları ----
find_package(PkgConfig REQUIRED)

# OpenSSL
find_package(OpenSSL REQUIRED)
if(NOT OPENSSL_FOUND)
    message(FATAL_ERROR "OpenSSL bulunamadı! Lütfen gerekli paketi yükleyin.")
endif()

# PostgreSQL
find_package(PostgreSQL REQUIRED)

# Hiredis
find_library(HIREDIS_LIB hiredis)
set(HIREDIS_INCLUDE_DIR /usr/local/include)

# libsodium
pkg_check_modules(SODIUM REQUIRED libsodium)
if(NOT SODIUM_FOUND)
    find_path(SODIUM_INCLUDE_DIR sodium.h)
    find_library(SODIUM_LIBRARY sodium)
    if(SODIUM_INCLUDE_DIR AND SODIUM_LIBRARY)
        set(SODIUM_FOUND TRUE)
        set(SODIUM_INCLUDE_DIRS ${SODIUM_INCLUDE_DIR})
        set(SODIUM_LIBRARIES ${SODIUM_LIBRARY})
    else()
        message(FATAL_ERROR "libsodium bulunamadı! Lütfen libsodium-dev paketini yükleyin.")
    endif()
endif()

# nlohmann/json
find_package(nlohmann_json QUIET)
if(NOT nlohmann_json_FOUND)
    find_path(NLOHMANN_JSON_INCLUDE_DIR nlohmann/json.hpp)
    if(NLOHMANN_JSON_INCLUDE_DIR)
        add_library(nlohmann_json INTERFACE)
        target_include_directories(nlohmann_json INTERFACE ${NLOHMANN_JSON_INCLUDE_DIR})
    else()
        include(FetchContent)
        FetchContent_Declare(
                nlohmann_json
                GIT_REPOSITORY https://github.com/nlohmann/json.git
                GIT_TAG v3.11.3
        )
        FetchContent_MakeAvailable(nlohmann_json)
    endif()
endif()

# ---- Executable ----
set(SOURCES test_secure_messaging.cpp db_utils.cpp redis_utils.cpp
        test_secure_messaging.cpp
        redis_utils.cpp
        redis_utils.h
        db_utils.cpp
        db_utils.h
        cryptology.cpp
        cryptology.h)
add_executable(cryptology_project_main ${SOURCES})

# OpenSSL
target_include_directories(cryptology_project_main PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(cryptology_project_main PRIVATE ${OPENSSL_LIBRARIES})

# libsodium
target_include_directories(cryptology_project_main PRIVATE ${SODIUM_INCLUDE_DIRS})
target_link_libraries(cryptology_project_main PRIVATE ${SODIUM_LIBRARIES})

# PostgreSQL
target_include_directories(cryptology_project_main PRIVATE ${PostgreSQL_INCLUDE_DIRS})
target_link_libraries(cryptology_project_main PRIVATE ${PostgreSQL_LIBRARIES})

# Hiredis
target_include_directories(cryptology_project_main PRIVATE ${HIREDIS_INCLUDE_DIR})
target_link_libraries(cryptology_project_main PRIVATE ${HIREDIS_LIB})

# nlohmann/json
target_link_libraries(cryptology_project_main PRIVATE nlohmann_json::nlohmann_json)

# macOS için ek ayarlar
if(APPLE)
    target_link_directories(cryptology_project_main PRIVATE ${SODIUM_LIBRARY_DIRS})
    target_link_directories(cryptology_project_main PRIVATE /opt/homebrew/lib)
    target_include_directories(cryptology_project_main PRIVATE /opt/homebrew/include)
endif()

# ---- Compiler-specific optimizasyonlar ----
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_compile_options(cryptology_project_main PRIVATE -march=native)
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    target_compile_options(cryptology_project_main PRIVATE -march=native)
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    target_compile_options(cryptology_project_main PRIVATE /arch:AVX2)
endif()

# ---- Install ----
install(TARGETS cryptology_project_main
        RUNTIME DESTINATION bin
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib
)

# ---- Build bilgileri ----
message(STATUS "Build Type: ${CMAKE_BUILD_TYPE}")
message(STATUS "C++ Compiler: ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "libsodium Include: ${SODIUM_INCLUDE_DIRS}")
message(STATUS "libsodium Libraries: ${SODIUM_LIBRARIES}")

# ---- Platform-specific RPATH ----
if(APPLE)
    set_target_properties(cryptology_project_main PROPERTIES
            MACOSX_RPATH TRUE
            INSTALL_RPATH "@executable_path"
    )
elseif(UNIX AND NOT APPLE)
    set_target_properties(cryptology_project_main PROPERTIES
            INSTALL_RPATH "$ORIGIN"
    )
endif()

# ---- Packaging ----
set(CPACK_PACKAGE_NAME "SecureMessaging")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_PACKAGE_DESCRIPTION "Güvenli mesajlaşma sistemi")
set(CPACK_PACKAGE_CONTACT "developer@example.com")

if(WIN32)
    set(CPACK_GENERATOR "ZIP")
elseif(APPLE)
    set(CPACK_GENERATOR "TGZ")
else()
    set(CPACK_GENERATOR "DEB;RPM;TGZ")
endif()

include(CPack)
