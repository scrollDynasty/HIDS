#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <regex>
#include <memory>
#include <mutex>
#include <fstream>
#include <thread>
#include <atomic>
#include <functional>

#include "../alert/alert_system.hpp"

namespace hids {

// Структура для хранения информации о SSH событии
struct SSHEvent {
    enum class Type {
        FAILED_LOGIN,
        SUCCESSFUL_LOGIN,
        LOGOUT,
        INVALID_USER,
        BRUTEFORCE_ATTEMPT,
        UNKNOWN
    };

    std::string timestamp;
    std::string username;
    std::string source_ip;
    Type event_type;
    std::string raw_message;
    
    SSHEvent() : event_type(Type::UNKNOWN) {}
};

// Класс для мониторинга логов SSH
class LogMonitor {
public:
    LogMonitor(const std::string& log_file_path, std::shared_ptr<AlertSystem> alert_system);
    ~LogMonitor();

    // Запуск мониторинга в отдельном потоке
    void start();
    
    // Остановка мониторинга
    void stop();
    
    // Установка порога для обнаружения брутфорса
    void setBruteForceThreshold(int failed_attempts, int time_window_seconds);
    
    // Задание регулярных выражений для парсинга логов
    void setRegexPatterns(const std::unordered_map<std::string, std::string>& patterns);

private:
    // Основной метод для парсинга и анализа логов
    void monitorLogFile();
    
    // Метод для парсинга строки лога
    SSHEvent parseLogLine(const std::string& line);
    
    // Анализ на брутфорс атаки
    bool checkBruteForceAttempt(const SSHEvent& event);
    
    // Путь к мониторируемому файлу лога
    std::string m_log_file_path;
    
    // Система оповещений
    std::shared_ptr<AlertSystem> m_alert_system;
    
    // Словарь с регулярными выражениями для разных типов событий
    std::unordered_map<std::string, std::regex> m_regex_patterns;
    
    // Хранение информации о недавних неудачных попытках входа (IP -> список времени)
    std::unordered_map<std::string, std::vector<time_t>> m_failed_attempts;
    
    // Параметры для обнаружения брутфорса
    int m_bruteforce_threshold;
    int m_bruteforce_time_window;
    
    // Поток для мониторинга
    std::unique_ptr<std::thread> m_monitor_thread;
    
    // Флаг для остановки мониторинга
    std::atomic<bool> m_should_stop;
    
    // Мьютекс для защиты данных
    std::mutex m_mutex;
};

} // namespace hids
