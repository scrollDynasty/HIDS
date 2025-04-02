#pragma once

#include <string>
#include <vector>
#include <functional>
#include <unordered_map>
#include <mutex>
#include <memory>
#include <fstream>

namespace hids {

// Структура для хранения информации об оповещении
struct Alert {
    std::string type;     // Тип оповещения (BRUTE_FORCE, FAILED_LOGIN, и т.д.)
    std::string message;  // Сообщение оповещения
    std::string timestamp;// Временная метка
    int severity;         // Уровень серьезности (1-5)
};

// Интерфейс для различных методов оповещения
class AlertMethod {
public:
    virtual ~AlertMethod() = default;
    virtual void sendAlert(const Alert& alert) = 0;
};

// Реализация оповещения через лог-файл
class FileAlertMethod : public AlertMethod {
public:
    FileAlertMethod(const std::string& log_path);
    void sendAlert(const Alert& alert) override;
private:
    std::string m_log_path;
    std::ofstream m_log_file;
    std::mutex m_file_mutex;
};

// Реализация оповещения через почту
class EmailAlertMethod : public AlertMethod {
public:
    EmailAlertMethod(const std::string& smtp_server, const std::string& from_email, 
                    const std::string& to_email, const std::string& subject_prefix);
    void sendAlert(const Alert& alert) override;
private:
    std::string m_smtp_server;
    std::string m_from_email;
    std::string m_to_email;
    std::string m_subject_prefix;
    std::mutex m_email_mutex;
};

// Основной класс системы оповещений
class AlertSystem {
public:
    AlertSystem();
    
    // Добавить метод оповещения
    void addAlertMethod(const std::string& name, std::shared_ptr<AlertMethod> method);
    
    // Удалить метод оповещения
    void removeAlertMethod(const std::string& name);
    
    // Включить/отключить тип оповещения
    void enableAlertType(const std::string& type, bool enabled = true);
    
    // Установить уровень серьезности для типа оповещения
    void setAlertSeverity(const std::string& type, int severity);
    
    // Вызвать оповещение с указанным типом и сообщением
    void triggerAlert(const std::string& type, const std::string& message);
    
private:
    // Хранение методов оповещения
    std::unordered_map<std::string, std::shared_ptr<AlertMethod>> m_alert_methods;
    
    // Хранение конфигурации оповещений (тип -> включено)
    std::unordered_map<std::string, bool> m_alert_enabled;
    
    // Хранение уровней серьезности (тип -> уровень)
    std::unordered_map<std::string, int> m_alert_severity;
    
    // Мьютекс для защиты данных
    std::mutex m_mutex;
};

} // namespace hids
