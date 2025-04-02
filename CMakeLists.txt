cmake_minimum_required(VERSION 3.10)
project(HIDS VERSION 1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -pedantic")

# Найти необходимые зависимости
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)
find_package(Boost REQUIRED COMPONENTS system filesystem regex)

# Включить каталоги заголовочных файлов
include_directories(${PROJECT_SOURCE_DIR}/include)

# Собрать все исходные файлы
file(GLOB_RECURSE SOURCES "${PROJECT_SOURCE_DIR}/src/*.cpp")

# Создать исполняемый файл
add_executable(hids ${SOURCES})

# Связать библиотеки
target_link_libraries(hids
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
    Boost::system
    Boost::filesystem
    Boost::regex
)

# Установка
install(TARGETS hids DESTINATION bin)
