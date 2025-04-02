#include <iostream>
#include <memory>
#include <csignal>
#include <thread>
#include <atomic>
#include <filesystem>
#include <vector>
#include <unordered_map>
#include <syslog.h>

#include "../include/modules/log_monitor.hpp"
#include "../include/modules/file_integrity.hpp"
#include "../include/modules/behavior_analyzer.hpp"
#include "../include/alert/alert_system.hpp"
#include "../include/utils/utils.hpp"

namespace fs = std::filesystem;

// Глобальная переменная для обработки сигналов
std::atomic<bool> g_running(true);

// Обработчик сигналов
void signalHandler(int signal) {
    std::cout << "Получен сигнал: " << signal << std::endl;
    g_running = false;
}

int main(int /*argc*/, char* /*argv*/[]) {
    // Настройка обработчиков сигналов
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);
    
    // Вывод приветствия
    std::cout << "=== HIDS (Система обнаружения вторжений на хосте) ===" << std::endl;
    std::cout << "Версия: 1.0" << std::endl;
    std::cout << "Запуск..." << std::endl;
    
    // Проверка прав root
    if (!hids::utils::isRunningAsRoot()) {
        std::cerr << "ПРЕДУПРЕЖДЕНИЕ: HIDS запущен без прав root. Некоторые функции могут быть недоступны." << std::endl;
    }
    
    // Пути к файлам для мониторинга
    std::string auth_log_path = "/var/log/auth.log";
    
    // Если auth.log не существует, пробуем secure
    if (!fs::exists(auth_log_path)) {
        auth_log_path = "/var/log/secure";
        
        // Если и этот файл не существует, выводим ошибку
        if (!fs::exists(auth_log_path)) {
            std::cerr << "ОШИБКА: Не найден файл лога аутентификации." << std::endl;
            return 1;
        }
    }
    
    // Инициализация системы оповещений
    auto alert_system = std::make_shared<hids::AlertSystem>();
    
    // Настройка методов оповещения
    auto file_alert = std::make_shared<hids::FileAlertMethod>("hids_alerts.log");
    alert_system->addAlertMethod("file", file_alert);
    
    // Дополнительные методы оповещения можно добавить здесь:
    // auto email_alert = std::make_shared<hids::EmailAlertMethod>("smtp.example.com", "hids@example.com", "admin@example.com", "HIDS Alert");
    // alert_system->addAlertMethod("email", email_alert);
    
    // Инициализация модулей
    auto log_monitor = std::make_shared<hids::LogMonitor>(auth_log_path, alert_system);
    auto file_integrity = std::make_shared<hids::FileIntegrityMonitor>(alert_system);
    auto behavior_analyzer = std::make_shared<hids::BehaviorAnalyzer>(alert_system);
    
    // Настройка модуля file_integrity
    file_integrity->addFile("/etc/ssh/sshd_config");
    file_integrity->addFile("/etc/pam.d/sshd");
    file_integrity->addFile("/etc/pam.d/common-auth");
    file_integrity->addFile("/etc/hosts.allow");
    file_integrity->addFile("/etc/hosts.deny");
    
    // Установка обработчика изменений файлов
    file_integrity->setFileChangeHandler([&alert_system](
        const std::string& path, 
        const hids::FileInfo& /*old_info*/, 
        const hids::FileInfo& /*new_info*/) {
            // Дополнительная логика обработки изменений файлов
            std::stringstream ss;
            ss << "Изменен критичный файл: " << path;
            hids::utils::writeSyslog(ss.str(), LOG_WARNING);
    });
    
    // Настройка модуля behavior_analyzer
    behavior_analyzer->setActiveTimeWindow(8, 20); // Рабочее время: 8:00 - 20:00
    
    // Запуск всех модулей
    std::cout << "Запуск модуля мониторинга логов..." << std::endl;
    log_monitor->start();
    
    std::cout << "Запуск модуля контроля целостности файлов..." << std::endl;
    file_integrity->start(300); // Проверка каждые 5 минут
    
    std::cout << "Запуск анализатора поведения..." << std::endl;
    behavior_analyzer->start();
    
    std::cout << "HIDS успешно запущен." << std::endl;
    
    // Основной цикл программы
    while (g_running) {
        // Здесь можно добавить интерактивное взаимодействие или другую логику
        
        // Проверка использования ресурсов системы
        auto resources = hids::utils::getSystemResourceUsage();
        if (resources.cpu_usage > 90.0) {
            std::stringstream ss;
            ss << "Высокое использование CPU: " << resources.cpu_usage << "%";
            alert_system->triggerAlert("HIGH_CPU", ss.str());
        }
        
        // Пауза для снижения нагрузки
        std::this_thread::sleep_for(std::chrono::seconds(10));
    }
    
    // Остановка модулей
    std::cout << "Остановка HIDS..." << std::endl;
    
    log_monitor->stop();
    file_integrity->stop();
    behavior_analyzer->stop();
    
    std::cout << "HIDS остановлен." << std::endl;
    
    return 0;
}
