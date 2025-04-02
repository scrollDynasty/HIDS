#include "../../include/modules/log_monitor.hpp"
#include <chrono>
#include <iostream>
#include <algorithm>
#include <ctime>
#include <iomanip>
#include <sstream>

namespace hids {

LogMonitor::LogMonitor(const std::string& log_file_path, std::shared_ptr<AlertSystem> alert_system)
    : m_log_file_path(log_file_path)
    , m_alert_system(alert_system)
    , m_bruteforce_threshold(5)
    , m_bruteforce_time_window(300) // 5 минут по умолчанию
    , m_should_stop(false)
{
    // Инициализация регулярных выражений по умолчанию
    std::unordered_map<std::string, std::string> default_patterns = {
        {"failed_login", R"((\w+\s+\d+\s+\d+:\d+:\d+).*sshd\[\d+\]: Failed password for (.*) from (\d+\.\d+\.\d+\.\d+) port \d+)"},
        {"invalid_user", R"((\w+\s+\d+\s+\d+:\d+:\d+).*sshd\[\d+\]: Failed password for invalid user (.*) from (\d+\.\d+\.\d+\.\d+) port \d+)"},
        {"successful_login", R"((\w+\s+\d+\s+\d+:\d+:\d+).*sshd\[\d+\]: Accepted password for (.*) from (\d+\.\d+\.\d+\.\d+) port \d+)"},
        {"logout", R"((\w+\s+\d+\s+\d+:\d+:\d+).*sshd\[\d+\]: pam_unix\(sshd:session\): session closed for user (.*))"}
    };
    setRegexPatterns(default_patterns);
}

LogMonitor::~LogMonitor() {
    stop();
}

void LogMonitor::start() {
    if (m_monitor_thread && m_monitor_thread->joinable()) {
        return; // Уже запущен
    }
    
    m_should_stop = false;
    m_monitor_thread = std::make_unique<std::thread>(&LogMonitor::monitorLogFile, this);
}

void LogMonitor::stop() {
    m_should_stop = true;
    if (m_monitor_thread && m_monitor_thread->joinable()) {
        m_monitor_thread->join();
    }
}

void LogMonitor::setBruteForceThreshold(int failed_attempts, int time_window_seconds) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_bruteforce_threshold = failed_attempts;
    m_bruteforce_time_window = time_window_seconds;
}

void LogMonitor::setRegexPatterns(const std::unordered_map<std::string, std::string>& patterns) {
    std::lock_guard<std::mutex> lock(m_mutex);
    for (const auto& [key, pattern] : patterns) {
        m_regex_patterns[key] = std::regex(pattern);
    }
}

void LogMonitor::monitorLogFile() {
    std::ifstream log_file(m_log_file_path);
    
    if (!log_file) {
        m_alert_system->triggerAlert("ERROR", "Cannot open log file: " + m_log_file_path);
        return;
    }
    
    // Перемещаемся в конец файла, чтобы наблюдать только за новыми записями
    log_file.seekg(0, std::ios::end);
    
    std::string line;
    while (!m_should_stop) {
        if (std::getline(log_file, line)) {
            if (!line.empty()) {
                SSHEvent event = parseLogLine(line);
                
                // Обрабатываем событие в зависимости от его типа
                switch (event.event_type) {
                    case SSHEvent::Type::FAILED_LOGIN:
                    case SSHEvent::Type::INVALID_USER:
                        if (checkBruteForceAttempt(event)) {
                            // Преобразуем в событие брутфорса
                            event.event_type = SSHEvent::Type::BRUTEFORCE_ATTEMPT;
                            
                            std::stringstream ss;
                            ss << "Брутфорс атака от IP " << event.source_ip << " с " 
                               << m_failed_attempts[event.source_ip].size() 
                               << " неудачными попытками за последние " 
                               << m_bruteforce_time_window << " секунд";
                               
                            m_alert_system->triggerAlert("BRUTE_FORCE", ss.str());
                        } else {
                            std::stringstream ss;
                            ss << "Неудачная попытка входа: пользователь=" 
                               << event.username << ", IP=" << event.source_ip;
                               
                            m_alert_system->triggerAlert("FAILED_LOGIN", ss.str());
                        }
                        break;
                    
                    case SSHEvent::Type::SUCCESSFUL_LOGIN:
                        {
                            std::stringstream ss;
                            ss << "Успешный вход в систему: пользователь=" 
                               << event.username << ", IP=" << event.source_ip;
                               
                            m_alert_system->triggerAlert("SUCCESS_LOGIN", ss.str());
                        }
                        break;
                    
                    case SSHEvent::Type::LOGOUT:
                        // Для отладки можно добавить оповещение о выходе
                        // m_alert_system->triggerAlert("LOGOUT", "User " + event.username + " logged out");
                        break;
                    
                    default:
                        break;
                }
            }
        } else {
            // Если достигнут конец файла, ждем новых записей
            log_file.clear(); // Очистка флагов ошибок
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
    }
}

SSHEvent LogMonitor::parseLogLine(const std::string& line) {
    SSHEvent event;
    event.raw_message = line;
    
    std::smatch matches;
    
    // Проверяем различные шаблоны
    if (std::regex_search(line, matches, m_regex_patterns["invalid_user"])) {
        event.event_type = SSHEvent::Type::INVALID_USER;
        event.timestamp = matches[1].str();
        event.username = matches[2].str();
        event.source_ip = matches[3].str();
    }
    else if (std::regex_search(line, matches, m_regex_patterns["failed_login"])) {
        event.event_type = SSHEvent::Type::FAILED_LOGIN;
        event.timestamp = matches[1].str();
        event.username = matches[2].str();
        event.source_ip = matches[3].str();
    }
    else if (std::regex_search(line, matches, m_regex_patterns["successful_login"])) {
        event.event_type = SSHEvent::Type::SUCCESSFUL_LOGIN;
        event.timestamp = matches[1].str();
        event.username = matches[2].str();
        event.source_ip = matches[3].str();
    }
    else if (std::regex_search(line, matches, m_regex_patterns["logout"])) {
        event.event_type = SSHEvent::Type::LOGOUT;
        event.timestamp = matches[1].str();
        event.username = matches[2].str();
        // source_ip недоступен при выходе из системы
    }
    
    return event;
}

bool LogMonitor::checkBruteForceAttempt(const SSHEvent& event) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (event.event_type != SSHEvent::Type::FAILED_LOGIN && 
        event.event_type != SSHEvent::Type::INVALID_USER) {
        return false;
    }
    
    // Текущее время
    time_t current_time = std::time(nullptr);
    
    // Добавляем новую неудачную попытку
    m_failed_attempts[event.source_ip].push_back(current_time);
    
    // Удаляем устаревшие попытки из окна времени
    auto& attempts = m_failed_attempts[event.source_ip];
    attempts.erase(
        std::remove_if(
            attempts.begin(), 
            attempts.end(),
            [this, current_time](time_t timestamp) {
                return current_time - timestamp > m_bruteforce_time_window;
            }
        ),
        attempts.end()
    );
    
    // Проверяем, превышен ли порог
    return attempts.size() >= static_cast<size_t>(m_bruteforce_threshold);
}

} // namespace hids
