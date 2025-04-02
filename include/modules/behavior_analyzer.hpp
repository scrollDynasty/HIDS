#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <mutex>
#include <thread>
#include <atomic>
#include <functional>
#include <chrono>
#include <ctime>

#include "../alert/alert_system.hpp"

namespace hids {

// Информация о пользовательской сессии
struct UserSession {
    std::string username;           // Имя пользователя
    std::string source_ip;          // IP-адрес источника
    std::time_t login_time;         // Время входа
    std::time_t last_activity_time; // Время последней активности
    std::vector<std::string> commands; // История выполненных команд
    
    UserSession() : login_time(0), last_activity_time(0) {}
};

// Класс для анализа пользовательского поведения
class BehaviorAnalyzer {
public:
    BehaviorAnalyzer(std::shared_ptr<AlertSystem> alert_system);
    ~BehaviorAnalyzer();
    
    // Регистрирует новую пользовательскую сессию
    void registerLogin(const std::string& username, const std::string& source_ip);
    
    // Регистрирует выход пользователя
    void registerLogout(const std::string& username, const std::string& source_ip);
    
    // Регистрирует команду, выполненную пользователем
    void registerCommand(const std::string& username, const std::string& command);
    
    // Запускает фоновый анализ поведения
    void start();
    
    // Останавливает анализ поведения
    void stop();
    
    // Добавляет подозрительную команду или шаблон команды
    void addSuspiciousCommand(const std::string& command_pattern);
    
    // Удаляет подозрительную команду или шаблон
    void removeSuspiciousCommand(const std::string& command_pattern);
    
    // Устанавливает список привилегированных команд
    void setPrivilegedCommands(const std::vector<std::string>& commands);
    
    // Устанавливает временные рамки для нормальной активности
    void setActiveTimeWindow(int start_hour, int end_hour);
    
    // Устанавливает разрешенные IP-адреса для пользователя
    void setAllowedSourceIPs(const std::string& username, const std::vector<std::string>& allowed_ips);
    
    // Вручную запускает проверку поведения для активных сессий
    void checkBehavior();
    
private:
    // Метод для фонового анализа поведения
    void analyzeBehavior();
    
    // Проверяет сессию на аномалии
    void checkSession(const std::string& username, const UserSession& session);
    
    // Проверяет подозрительные команды
    bool checkSuspiciousCommands(const UserSession& session);
    
    // Проверяет необычное время активности
    bool checkUnusualTime(const UserSession& session);
    
    // Проверяет необычный источник подключения
    bool checkUnusualSource(const UserSession& session);
    
    // Система оповещений
    std::shared_ptr<AlertSystem> m_alert_system;
    
    // Активные пользовательские сессии (username_ip -> session)
    std::unordered_map<std::string, UserSession> m_active_sessions;
    
    // Подозрительные команды или шаблоны команд
    std::unordered_set<std::string> m_suspicious_commands;
    
    // Привилегированные команды
    std::unordered_set<std::string> m_privileged_commands;
    
    // Допустимые IP-адреса для пользователей (username -> allowed_ips)
    std::unordered_map<std::string, std::unordered_set<std::string>> m_allowed_ips;
    
    // Временное окно нормальной активности
    int m_active_time_start_hour;
    int m_active_time_end_hour;
    
    // Поток для анализа поведения
    std::unique_ptr<std::thread> m_analyzer_thread;
    
    // Флаг для остановки анализа
    std::atomic<bool> m_should_stop;
    
    // Мьютекс для защиты данных
    std::mutex m_mutex;
};

} // namespace hids
