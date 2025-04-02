#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <mutex>
#include <thread>
#include <atomic>
#include <functional>
#include <filesystem>

#include "../alert/alert_system.hpp"

namespace hids {

// Структура для хранения информации о файле
struct FileInfo {
    std::string path;                 // Путь к файлу
    std::string hash;                 // Хеш содержимого файла
    std::filesystem::file_time_type last_modified; // Время последнего изменения
    std::uintmax_t size;             // Размер файла в байтах
    
    bool operator==(const FileInfo& other) const {
        return hash == other.hash && 
               last_modified == other.last_modified && 
               size == other.size;
    }
    
    bool operator!=(const FileInfo& other) const {
        return !(*this == other);
    }
};

// Класс для контроля целостности файлов
class FileIntegrityMonitor {
public:
    FileIntegrityMonitor(std::shared_ptr<AlertSystem> alert_system);
    ~FileIntegrityMonitor();
    
    // Добавить файл для мониторинга
    void addFile(const std::string& path);
    
    // Добавить директорию для мониторинга
    void addDirectory(const std::string& dir_path, bool recursive = false);
    
    // Удалить файл из мониторинга
    void removeFile(const std::string& path);
    
    // Запустить мониторинг в отдельном потоке
    void start(int check_interval_seconds = 60);
    
    // Остановить мониторинг
    void stop();
    
    // Ручная проверка целостности всех файлов
    void checkIntegrity();
    
    // Обновить базовые хеши всех мониторируемых файлов
    void updateBaselines();
    
    // Установить пользовательский обработчик для измененных файлов
    void setFileChangeHandler(std::function<void(const std::string&, const FileInfo&, const FileInfo&)> handler);

private:
    // Вычислить хеш файла
    std::string calculateFileHash(const std::string& path);
    
    // Получить информацию о файле
    FileInfo getFileInfo(const std::string& path);
    
    // Процесс регулярной проверки файлов
    void monitorFiles();
    
    // Проверка отдельного файла
    bool checkFile(const std::string& path);
    
    // Система оповещений
    std::shared_ptr<AlertSystem> m_alert_system;
    
    // Базовая информация о файлах (путь -> информация)
    std::unordered_map<std::string, FileInfo> m_baseline_info;
    
    // Пользовательский обработчик
    std::function<void(const std::string&, const FileInfo&, const FileInfo&)> m_change_handler;
    
    // Поток для мониторинга
    std::unique_ptr<std::thread> m_monitor_thread;
    
    // Флаг для остановки мониторинга
    std::atomic<bool> m_should_stop;
    
    // Интервал проверки в секундах
    int m_check_interval;
    
    // Мьютекс для защиты данных
    std::mutex m_mutex;
};

} // namespace hids
