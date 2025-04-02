#include "../../include/modules/behavior_analyzer.hpp"
#include <sstream>
#include <iostream>
#include <algorithm>
#include <regex>
#include <iomanip>

namespace hids {

BehaviorAnalyzer::BehaviorAnalyzer(std::shared_ptr<AlertSystem> alert_system)
    : m_alert_system(alert_system)
    , m_active_time_start_hour(8)  // По умолчанию: 8:00 - 20:00
    , m_active_time_end_hour(20)
    , m_should_stop(false)
{
    // Настройка подозрительных команд по умолчанию
    m_suspicious_commands = {
        "wget", "curl", "nc", "netcat", "ncat", "telnet",
        "ssh-keygen", "chmod 777", "rm -rf /*", "dd if=/dev/zero",
        ":(){ :|:& };:", // Fork bomb
        "/dev/tcp", ">&",
        "\\.\\./\\.\\./", // Path traversal
        "base64 --decode", "eval", "exec"
    };

    // Настройка привилегированных команд по умолчанию
    m_privileged_commands = {
        "sudo", "su", "passwd", "chown", "chmod", "visudo",
        "usermod", "groupmod", "useradd", "userdel", "adduser",
        "mount", "umount", "fdisk", "mkfs", "systemctl",
        "iptables", "firewall-cmd", "tcpdump", "wireshark"
    };
}

BehaviorAnalyzer::~BehaviorAnalyzer() {
    stop();
}

void BehaviorAnalyzer::registerLogin(const std::string& username, const std::string& source_ip) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Создаем ключ сессии из имени пользователя и IP
    std::string session_key = username + "_" + source_ip;
    
    // Создаем новую сессию
    UserSession session;
    session.username = username;
    session.source_ip = source_ip;
    session.login_time = std::time(nullptr);
    session.last_activity_time = session.login_time;
    
    // Сохраняем сессию
    m_active_sessions[session_key] = session;
    
    // Проверяем необычный источник подключения
    if (checkUnusualSource(session)) {
        std::stringstream ss;
        ss << "Обнаружен вход с необычного IP-адреса: пользователь=" 
           << username << ", IP=" << source_ip;
        m_alert_system->triggerAlert("UNUSUAL_SOURCE", ss.str());
    }
    
    // Проверяем необычное время подключения
    if (checkUnusualTime(session)) {
        std::stringstream ss;
        ss << "Обнаружен вход в необычное время: пользователь=" 
           << username << ", IP=" << source_ip;
        m_alert_system->triggerAlert("UNUSUAL_TIME", ss.str());
    }
}

void BehaviorAnalyzer::registerLogout(const std::string& username, const std::string& source_ip) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Удаляем сессию
    std::string session_key = username + "_" + source_ip;
    m_active_sessions.erase(session_key);
}

void BehaviorAnalyzer::registerCommand(const std::string& username, const std::string& command) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Находим все активные сессии для этого пользователя
    bool session_found = false;
    
    for (auto& [key, session] : m_active_sessions) {
        if (session.username == username) {
            // Добавляем команду и обновляем время активности
            session.commands.push_back(command);
            session.last_activity_time = std::time(nullptr);
            session_found = true;
            
            // Проверяем выполненную команду на подозрительность
            for (const auto& pattern : m_suspicious_commands) {
                // Используем regex для гибкого сопоставления
                std::regex pattern_regex(pattern);
                if (std::regex_search(command, pattern_regex)) {
                    std::stringstream ss;
                    ss << "Обнаружена подозрительная команда: пользователь=" 
                       << username << ", IP=" << session.source_ip 
                       << ", команда=\"" << command << "\"";
                    m_alert_system->triggerAlert("SUSPICIOUS_COMMAND", ss.str());
                    break;
                }
            }
            
            // Проверяем на привилегированные команды
            for (const auto& priv_cmd : m_privileged_commands) {
                // Ищем команду в начале строки с возможным пробелом после
                std::regex cmd_regex("^" + priv_cmd + "(\\s|$)");
                if (std::regex_search(command, cmd_regex)) {
                    std::stringstream ss;
                    ss << "Обнаружена привилегированная команда: пользователь=" 
                       << username << ", IP=" << session.source_ip 
                       << ", команда=\"" << command << "\"";
                    m_alert_system->triggerAlert("PRIVILEGED_COMMAND", ss.str());
                    break;
                }
            }
        }
    }
    
    if (!session_found) {
        std::stringstream ss;
        ss << "Команда от пользователя без активной сессии: пользователь=" 
           << username << ", команда=\"" << command << "\"";
        m_alert_system->triggerAlert("NO_SESSION", ss.str());
    }
}

void BehaviorAnalyzer::start() {
    if (m_analyzer_thread && m_analyzer_thread->joinable()) {
        return; // Уже запущен
    }
    
    m_should_stop = false;
    m_analyzer_thread = std::make_unique<std::thread>(&BehaviorAnalyzer::analyzeBehavior, this);
    
    m_alert_system->triggerAlert("INFO", "Анализатор поведения запущен");
}

void BehaviorAnalyzer::stop() {
    m_should_stop = true;
    
    if (m_analyzer_thread && m_analyzer_thread->joinable()) {
        m_analyzer_thread->join();
        m_alert_system->triggerAlert("INFO", "Анализатор поведения остановлен");
    }
}

void BehaviorAnalyzer::addSuspiciousCommand(const std::string& command_pattern) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_suspicious_commands.insert(command_pattern);
}

void BehaviorAnalyzer::removeSuspiciousCommand(const std::string& command_pattern) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_suspicious_commands.erase(command_pattern);
}

void BehaviorAnalyzer::setPrivilegedCommands(const std::vector<std::string>& commands) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_privileged_commands.clear();
    for (const auto& cmd : commands) {
        m_privileged_commands.insert(cmd);
    }
}

void BehaviorAnalyzer::setActiveTimeWindow(int start_hour, int end_hour) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Проверяем допустимые значения
    if (start_hour < 0) start_hour = 0;
    if (start_hour > 23) start_hour = 23;
    if (end_hour < 0) end_hour = 0;
    if (end_hour > 23) end_hour = 23;
    
    m_active_time_start_hour = start_hour;
    m_active_time_end_hour = end_hour;
}

void BehaviorAnalyzer::setAllowedSourceIPs(const std::string& username, const std::vector<std::string>& allowed_ips) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Очищаем старые значения и добавляем новые
    m_allowed_ips[username].clear();
    for (const auto& ip : allowed_ips) {
        m_allowed_ips[username].insert(ip);
    }
}

void BehaviorAnalyzer::checkBehavior() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    for (const auto& [key, session] : m_active_sessions) {
        checkSession(session.username, session);
    }
}

void BehaviorAnalyzer::analyzeBehavior() {
    while (!m_should_stop) {
        checkBehavior();
        
        // Проверяем каждые 60 секунд
        for (int i = 0; i < 60 && !m_should_stop; i++) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
}

void BehaviorAnalyzer::checkSession(const std::string& username, const UserSession& session) {
    // Проверяем, не слишком ли долго пользователь неактивен
    std::time_t current_time = std::time(nullptr);
    std::time_t inactive_time = current_time - session.last_activity_time;
    
    if (inactive_time > 3600) { // Более часа неактивности
        std::stringstream ss;
        ss << "Длительная неактивность в сессии: пользователь=" 
           << username << ", IP=" << session.source_ip 
           << ", время неактивности=" << inactive_time << " секунд";
        m_alert_system->triggerAlert("INACTIVE_SESSION", ss.str());
    }
    
    // Проверяем на необычные шаблоны выполнения команд
    if (session.commands.size() >= 5) {
        // Пример: слишком много команд за короткий промежуток времени
        std::time_t session_duration = current_time - session.login_time;
        double commands_per_minute = static_cast<double>(session.commands.size()) / (session_duration / 60.0);
        
        if (commands_per_minute > 20) { // Более 20 команд в минуту
            std::stringstream ss;
            ss << "Обнаружена необычно высокая активность: пользователь=" 
               << username << ", IP=" << session.source_ip 
               << ", команд в минуту=" << std::fixed << std::setprecision(2) << commands_per_minute;
            m_alert_system->triggerAlert("HIGH_ACTIVITY", ss.str());
        }
    }
}

bool BehaviorAnalyzer::checkSuspiciousCommands(const UserSession& /*session*/) {
    // Проверка уже выполняется в методе registerCommand
    return false;
}

bool BehaviorAnalyzer::checkUnusualTime(const UserSession& session) {
    // Получаем текущий час
    std::time_t login_time = session.login_time;
    std::tm* time_info = std::localtime(&login_time);
    int current_hour = time_info->tm_hour;
    
    // Проверяем, находится ли время в пределах активного окна
    bool is_unusual = false;
    
    if (m_active_time_start_hour < m_active_time_end_hour) {
        // Обычный случай, например, 8:00 - 20:00
        is_unusual = (current_hour < m_active_time_start_hour || current_hour >= m_active_time_end_hour);
    } else {
        // Случай ночной смены, например, 20:00 - 8:00
        is_unusual = (current_hour < m_active_time_start_hour && current_hour >= m_active_time_end_hour);
    }
    
    return is_unusual;
}

bool BehaviorAnalyzer::checkUnusualSource(const UserSession& session) {
    // Если для пользователя заданы разрешенные IP-адреса
    auto it = m_allowed_ips.find(session.username);
    if (it != m_allowed_ips.end() && !it->second.empty()) {
        // Проверяем, есть ли IP-адрес в списке разрешенных
        return (it->second.find(session.source_ip) == it->second.end());
    }
    
    return false; // Не можем определить, является ли источник необычным
}

} // namespace hids
