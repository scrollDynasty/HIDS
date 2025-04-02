#include "../../include/utils/utils.hpp"
#include <cstdlib>
#include <array>
#include <memory>
#include <iomanip>
#include <syslog.h>
#include <unistd.h>
#include <sys/types.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

namespace hids {
namespace utils {

// Выполнение команды и получение вывода
std::string exec(const char* cmd) {
    std::array<char, 128> buffer;
    std::string result;
    std::shared_ptr<FILE> pipe(popen(cmd, "r"), pclose);
    if (!pipe) {
        return "";
    }
    while (!feof(pipe.get())) {
        if (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
            result += buffer.data();
        }
    }
    return result;
}

bool blockIP(const std::string& ip, const std::string& reason) {
    if (!isValidIPv4(ip)) {
        return false;
    }
    
    std::string comment = reason.empty() ? "Blocked by HIDS" : "Blocked by HIDS: " + reason;
    
    // Формируем команду для iptables
    std::stringstream cmd;
    cmd << "iptables -A INPUT -s " << ip << " -j DROP -m comment --comment \"" << comment << "\"";
    
    // Выполняем команду
    int result = std::system(cmd.str().c_str());
    
    return (result == 0);
}

bool unblockIP(const std::string& ip) {
    if (!isValidIPv4(ip)) {
        return false;
    }
    
    // Формируем команду для iptables
    std::string cmd = "iptables -D INPUT -s " + ip + " -j DROP";
    
    // Выполняем команду
    int result = std::system(cmd.c_str());
    
    return (result == 0);
}

bool isIPBlocked(const std::string& ip) {
    if (!isValidIPv4(ip)) {
        return false;
    }
    
    // Проверяем, есть ли IP в правилах iptables
    std::string cmd = "iptables -L INPUT -n | grep -q " + ip;
    int result = std::system(cmd.c_str());
    
    return (result == 0);
}

bool executeScript(const std::string& script_path, const std::vector<std::string>& args) {
    // Проверяем, существует ли скрипт и может ли быть выполнен
    if (access(script_path.c_str(), X_OK) != 0) {
        return false;
    }
    
    // Формируем команду с аргументами
    std::stringstream cmd;
    cmd << script_path;
    
    for (const auto& arg : args) {
        cmd << " " << "\"" << arg << "\"";
    }
    
    // Выполняем скрипт
    int result = std::system(cmd.str().c_str());
    
    return (result == 0);
}

bool isValidIPv4(const std::string& ip) {
    std::regex ipv4_regex("^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\."
                          "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\."
                          "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\."
                          "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$");
    
    return std::regex_match(ip, ipv4_regex);
}

std::string formatTime(const std::time_t& time, const std::string& format) {
    std::tm* timeinfo = std::localtime(&time);
    char buffer[80];
    std::strftime(buffer, 80, format.c_str(), timeinfo);
    return std::string(buffer);
}

std::unordered_map<std::string, std::string> readConfigFile(const std::string& path) {
    std::unordered_map<std::string, std::string> config;
    std::ifstream file(path);
    
    if (!file) {
        return config;
    }
    
    std::string line;
    while (std::getline(file, line)) {
        // Пропускаем комментарии и пустые строки
        if (line.empty() || line[0] == '#' || line[0] == ';') {
            continue;
        }
        
        // Разделяем строку на ключ и значение
        auto pos = line.find('=');
        if (pos != std::string::npos) {
            std::string key = line.substr(0, pos);
            std::string value = line.substr(pos + 1);
            
            // Обрезаем пробелы
            key.erase(0, key.find_first_not_of(" \t"));
            key.erase(key.find_last_not_of(" \t") + 1);
            value.erase(0, value.find_first_not_of(" \t"));
            value.erase(value.find_last_not_of(" \t") + 1);
            
            config[key] = value;
        }
    }
    
    return config;
}

bool sendEmail(const std::string& /*smtp_server*/, const std::string& from, 
               const std::string& to, const std::string& subject, 
               const std::string& body) {
    // Простая реализация через команду mail
    // В реальном приложении лучше использовать библиотеку для отправки почты
    
    std::stringstream cmd;
    cmd << "echo \"" << body << "\" | mail -s \"" << subject 
        << "\" -r \"" << from << "\" \"" << to << "\"";
    
    int result = std::system(cmd.str().c_str());
    
    return (result == 0);
}

void writeSyslog(const std::string& message, int priority) {
    // Открываем соединение с системным журналом
    openlog("hids", LOG_PID, LOG_AUTH);
    
    // Записываем сообщение
    syslog(priority, "%s", message.c_str());
    
    // Закрываем соединение
    closelog();
}

bool isRunningAsRoot() {
    return (geteuid() == 0);
}

SystemResourceUsage getSystemResourceUsage() {
    SystemResourceUsage usage;
    
    // Получаем информацию о CPU
    std::string cpu_info = exec("top -bn1 | grep '%Cpu(s)' | awk '{print $2 + $4}'");
    usage.cpu_usage = std::stod(cpu_info);
    
    // Получаем информацию о памяти
    std::string mem_info = exec("free -b | grep 'Mem:' | awk '{print $2, $3}'");
    std::istringstream iss(mem_info);
    iss >> usage.memory_total >> usage.memory_used;
    
    usage.memory_usage = (usage.memory_used / usage.memory_total) * 100.0;
    
    return usage;
}

std::vector<ProcessInfo> getTopProcesses(int count) {
    std::vector<ProcessInfo> processes;
    
    // Формируем команду для получения топ-процессов
    std::stringstream cmd;
    cmd << "ps aux --sort=-%cpu | head -n " << (count + 1);
    
    std::string output = exec(cmd.str().c_str());
    std::istringstream stream(output);
    
    std::string line;
    // Пропускаем заголовок
    std::getline(stream, line);
    
    // Парсим результаты
    while (std::getline(stream, line) && processes.size() < static_cast<size_t>(count)) {
        std::istringstream iss(line);
        
        ProcessInfo process;
        std::string pid_str;
        
        iss >> process.user >> pid_str >> process.cpu_usage >> process.memory_usage;
        process.pid = std::stoi(pid_str);
        
        // Остаток строки - команда
        std::getline(iss, process.command);
        process.command = process.command.substr(process.command.find_first_not_of(" \t"));
        
        processes.push_back(process);
    }
    
    return processes;
}

std::string calculateHash(const std::string& data) {
    // Используем новый EVP API вместо устаревших функций
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    
    // Создаем контекст дайджеста
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return "";
    }
    
    // Инициализируем дайджест для SHA-256
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        return "";
    }
    
    // Обновляем данные
    if (EVP_DigestUpdate(ctx, data.c_str(), data.size()) != 1) {
        EVP_MD_CTX_free(ctx);
        return "";
    }
    
    // Финализируем вычисление хеша
    if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return "";
    }
    
    // Освобождаем контекст
    EVP_MD_CTX_free(ctx);
    
    // Преобразуем бинарный хеш в шестнадцатеричную строку
    std::stringstream ss;
    for (unsigned int i = 0; i < hash_len; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    
    return ss.str();
}

} // namespace utils
} // namespace hids
