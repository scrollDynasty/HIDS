#include "../../include/alert/alert_system.hpp"
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <iostream>

namespace hids {

// FileAlertMethod implementation
FileAlertMethod::FileAlertMethod(const std::string& log_path) : m_log_path(log_path) {
    std::lock_guard<std::mutex> lock(m_file_mutex);
    m_log_file.open(log_path, std::ios::app);
    
    if (!m_log_file) {
        std::cerr << "Не удалось открыть файл журнала оповещений: " << log_path << std::endl;
    }
}

void FileAlertMethod::sendAlert(const Alert& alert) {
    std::lock_guard<std::mutex> lock(m_file_mutex);
    
    if (m_log_file) {
        m_log_file << "[" << alert.timestamp << "] [Severity: " << alert.severity 
                   << "] [Type: " << alert.type << "] " << alert.message << std::endl;
        m_log_file.flush();
    }
}

// EmailAlertMethod implementation
EmailAlertMethod::EmailAlertMethod(const std::string& smtp_server, 
                                  const std::string& from_email, 
                                  const std::string& to_email, 
                                  const std::string& subject_prefix)
    : m_smtp_server(smtp_server)
    , m_from_email(from_email)
    , m_to_email(to_email)
    , m_subject_prefix(subject_prefix)
{
    // Здесь можно выполнить инициализацию почтового клиента
    // Для реального использования рекомендуется использовать библиотеку (например, libcurl)
}

void EmailAlertMethod::sendAlert(const Alert& alert) {
    std::lock_guard<std::mutex> lock(m_email_mutex);
    
    // Заглушка для отправки электронной почты
    // В реальной реализации здесь должен быть код для отправки email
    
    // Пример использования libcurl или другой библиотеки для отправки почты:
    /*
    std::string subject = m_subject_prefix + " - " + alert.type;
    std::string body = "[" + alert.timestamp + "] [Severity: " + 
                      std::to_string(alert.severity) + "] " + alert.message;
    
    // Вызов API для отправки почты
    */
    
    // Вместо этого выводим в стандартный вывод (для демонстрации)
    std::cout << "Отправка email оповещения на " << m_to_email << ":\n"
              << "Тема: " << m_subject_prefix << " - " << alert.type << "\n"
              << "Сообщение: [" << alert.timestamp << "] [Severity: " << alert.severity 
              << "] " << alert.message << std::endl;
}

// AlertSystem implementation
AlertSystem::AlertSystem() {
    // Настройка уровней серьезности по умолчанию
    m_alert_severity["BRUTE_FORCE"] = 5; // Высокий
    m_alert_severity["FAILED_LOGIN"] = 2; // Низкий
    m_alert_severity["SUCCESS_LOGIN"] = 1; // Информационный
    m_alert_severity["ERROR"] = 4; // Высокий
    
    // Включаем все типы оповещений по умолчанию
    m_alert_enabled["BRUTE_FORCE"] = true;
    m_alert_enabled["FAILED_LOGIN"] = true;
    m_alert_enabled["SUCCESS_LOGIN"] = true;
    m_alert_enabled["ERROR"] = true;
}

void AlertSystem::addAlertMethod(const std::string& name, std::shared_ptr<AlertMethod> method) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_alert_methods[name] = method;
}

void AlertSystem::removeAlertMethod(const std::string& name) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_alert_methods.erase(name);
}

void AlertSystem::enableAlertType(const std::string& type, bool enabled) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_alert_enabled[type] = enabled;
}

void AlertSystem::setAlertSeverity(const std::string& type, int severity) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Проверка диапазона
    if (severity < 1) severity = 1;
    if (severity > 5) severity = 5;
    
    m_alert_severity[type] = severity;
}

void AlertSystem::triggerAlert(const std::string& type, const std::string& message) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Проверяем, включено ли оповещение этого типа
    auto it_enabled = m_alert_enabled.find(type);
    if (it_enabled != m_alert_enabled.end() && !it_enabled->second) {
        return; // Оповещение отключено
    }
    
    // Получаем уровень серьезности
    int severity = 1; // По умолчанию
    auto it_severity = m_alert_severity.find(type);
    if (it_severity != m_alert_severity.end()) {
        severity = it_severity->second;
    }
    
    // Создаем оповещение
    Alert alert;
    alert.type = type;
    alert.message = message;
    alert.severity = severity;
    
    // Добавляем временную метку
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S");
    alert.timestamp = ss.str();
    
    // Отправляем оповещение через все зарегистрированные методы
    for (const auto& [name, method] : m_alert_methods) {
        method->sendAlert(alert);
    }
}

} // namespace hids
