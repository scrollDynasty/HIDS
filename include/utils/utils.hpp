#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <functional>
#include <iostream>
#include <fstream>
#include <sstream>
#include <ctime>
#include <thread>
#include <regex>

namespace hids {
namespace utils {

// Функция для блокировки IP-адреса через iptables
bool blockIP(const std::string& ip, const std::string& reason = "");

// Функция для разблокировки IP-адреса
bool unblockIP(const std::string& ip);

// Проверка, заблокирован ли IP-адрес
bool isIPBlocked(const std::string& ip);

// Функция для запуска пользовательского скрипта в ответ на инцидент
bool executeScript(const std::string& script_path, const std::vector<std::string>& args);

// Функция для парсинга строки с IP-адресом
bool isValidIPv4(const std::string& ip);

// Функция для форматирования времени
std::string formatTime(const std::time_t& time, const std::string& format = "%Y-%m-%d %H:%M:%S");

// Функция для чтения файла конфигурации в формате key=value
std::unordered_map<std::string, std::string> readConfigFile(const std::string& path);

// Функция для отправки email
bool sendEmail(const std::string& smtp_server, const std::string& from, 
               const std::string& to, const std::string& subject, 
               const std::string& body);

// Функция для записи в syslog
void writeSyslog(const std::string& message, int priority = 4 /* warning */);

// Функция для проверки, запущен ли HIDS от имени root
bool isRunningAsRoot();

// Функция для анализа использования CPU и памяти
struct SystemResourceUsage {
    double cpu_usage;          // В процентах
    double memory_usage;       // В процентах
    double memory_total;       // В байтах
    double memory_used;        // В байтах
};
SystemResourceUsage getSystemResourceUsage();

// Функция для получения данных о процессе
struct ProcessInfo {
    int pid;
    std::string command;
    std::string user;
    double cpu_usage;
    double memory_usage;
};
std::vector<ProcessInfo> getTopProcesses(int count = 5);

// Функция для расчета хеша строки
std::string calculateHash(const std::string& data);

} // namespace utils
} // namespace hids
