#include "../../include/modules/file_integrity.hpp"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <iostream>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <filesystem>
#include <chrono>

namespace fs = std::filesystem;

namespace hids {

FileIntegrityMonitor::FileIntegrityMonitor(std::shared_ptr<AlertSystem> alert_system)
    : m_alert_system(alert_system)
    , m_should_stop(false)
    , m_check_interval(60)
{
    // Устанавливаем пустой обработчик по умолчанию
    m_change_handler = [](const std::string&, const FileInfo&, const FileInfo&) {};
}

FileIntegrityMonitor::~FileIntegrityMonitor() {
    stop();
}

void FileIntegrityMonitor::addFile(const std::string& path) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Проверяем, существует ли файл
    if (!fs::exists(path) || !fs::is_regular_file(path)) {
        std::stringstream ss;
        ss << "Невозможно добавить файл для мониторинга: " << path << " (не существует или не обычный файл)";
        m_alert_system->triggerAlert("ERROR", ss.str());
        return;
    }
    
    try {
        // Получаем базовую информацию о файле
        FileInfo info = getFileInfo(path);
        m_baseline_info[path] = info;
        
        std::stringstream ss;
        ss << "Добавлен файл для мониторинга: " << path 
           << " (хеш: " << info.hash.substr(0, 10) << "...)";
        m_alert_system->triggerAlert("INFO", ss.str());
    }
    catch (const std::exception& e) {
        std::stringstream ss;
        ss << "Ошибка при добавлении файла для мониторинга: " << path 
           << " - " << e.what();
        m_alert_system->triggerAlert("ERROR", ss.str());
    }
}

void FileIntegrityMonitor::addDirectory(const std::string& dir_path, bool recursive) {
    if (!fs::exists(dir_path) || !fs::is_directory(dir_path)) {
        std::stringstream ss;
        ss << "Невозможно добавить директорию для мониторинга: " << dir_path << " (не существует или не директория)";
        m_alert_system->triggerAlert("ERROR", ss.str());
        return;
    }
    
    try {
        if (recursive) {
            for (const auto& entry : fs::recursive_directory_iterator(dir_path)) {
                if (fs::is_regular_file(entry)) {
                    addFile(entry.path().string());
                }
            }
        } else {
            for (const auto& entry : fs::directory_iterator(dir_path)) {
                if (fs::is_regular_file(entry)) {
                    addFile(entry.path().string());
                }
            }
        }
    }
    catch (const std::exception& e) {
        std::stringstream ss;
        ss << "Ошибка при сканировании директории: " << dir_path 
           << " - " << e.what();
        m_alert_system->triggerAlert("ERROR", ss.str());
    }
}

void FileIntegrityMonitor::removeFile(const std::string& path) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto it = m_baseline_info.find(path);
    if (it != m_baseline_info.end()) {
        m_baseline_info.erase(it);
        
        std::stringstream ss;
        ss << "Файл удален из мониторинга: " << path;
        m_alert_system->triggerAlert("INFO", ss.str());
    }
}

void FileIntegrityMonitor::start(int check_interval_seconds) {
    if (m_monitor_thread && m_monitor_thread->joinable()) {
        return; // Уже запущен
    }
    
    m_check_interval = check_interval_seconds;
    m_should_stop = false;
    m_monitor_thread = std::make_unique<std::thread>(&FileIntegrityMonitor::monitorFiles, this);
    
    std::stringstream ss;
    ss << "Мониторинг целостности файлов запущен с интервалом " 
       << m_check_interval << " секунд для " << m_baseline_info.size() << " файлов";
    m_alert_system->triggerAlert("INFO", ss.str());
}

void FileIntegrityMonitor::stop() {
    m_should_stop = true;
    
    if (m_monitor_thread && m_monitor_thread->joinable()) {
        m_monitor_thread->join();
        m_alert_system->triggerAlert("INFO", "Мониторинг целостности файлов остановлен");
    }
}

void FileIntegrityMonitor::checkIntegrity() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    for (const auto& [path, baseline] : m_baseline_info) {
        checkFile(path);
    }
}

void FileIntegrityMonitor::updateBaselines() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    for (auto& [path, info] : m_baseline_info) {
        try {
            if (fs::exists(path) && fs::is_regular_file(path)) {
                info = getFileInfo(path);
                
                std::stringstream ss;
                ss << "Обновлена базовая информация для файла: " << path 
                   << " (хеш: " << info.hash.substr(0, 10) << "...)";
                m_alert_system->triggerAlert("INFO", ss.str());
            }
            else {
                std::stringstream ss;
                ss << "Невозможно обновить базовую информацию для файла: " << path 
                   << " (не существует или не обычный файл)";
                m_alert_system->triggerAlert("WARNING", ss.str());
            }
        }
        catch (const std::exception& e) {
            std::stringstream ss;
            ss << "Ошибка при обновлении информации о файле: " << path 
               << " - " << e.what();
            m_alert_system->triggerAlert("ERROR", ss.str());
        }
    }
}

void FileIntegrityMonitor::setFileChangeHandler(
    std::function<void(const std::string&, const FileInfo&, const FileInfo&)> handler
) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_change_handler = handler;
}

std::string FileIntegrityMonitor::calculateFileHash(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Не удалось открыть файл для хеширования: " + path);
    }
    
    // Используем новый EVP API вместо устаревших функций
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    
    // Создаем контекст дайджеста
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Ошибка создания контекста OpenSSL");
    }
    
    // Инициализируем дайджест для SHA-256
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Ошибка инициализации SHA-256");
    }
    
    // Считываем файл блоками для эффективности
    constexpr size_t buffer_size = 8192;
    char buffer[buffer_size];
    
    while (file) {
        file.read(buffer, buffer_size);
        size_t bytes_read = file.gcount();
        
        if (bytes_read > 0) {
            if (EVP_DigestUpdate(ctx, buffer, bytes_read) != 1) {
                EVP_MD_CTX_free(ctx);
                throw std::runtime_error("Ошибка обновления SHA-256");
            }
        }
    }
    
    // Финализируем вычисление хеша
    if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Ошибка финализации SHA-256");
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

FileInfo FileIntegrityMonitor::getFileInfo(const std::string& path) {
    if (!fs::exists(path) || !fs::is_regular_file(path)) {
        throw std::runtime_error("Файл не существует или не является обычным файлом: " + path);
    }
    
    FileInfo info;
    info.path = path;
    info.hash = calculateFileHash(path);
    info.last_modified = fs::last_write_time(path);
    info.size = fs::file_size(path);
    
    return info;
}

void FileIntegrityMonitor::monitorFiles() {
    while (!m_should_stop) {
        checkIntegrity();
        
        // Ожидаем указанный интервал времени
        for (int i = 0; i < m_check_interval && !m_should_stop; i++) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    }
}

bool FileIntegrityMonitor::checkFile(const std::string& path) {
    auto it = m_baseline_info.find(path);
    if (it == m_baseline_info.end()) {
        return false; // Файл не найден в базе
    }
    
    const FileInfo& baseline = it->second;
    
    try {
        // Проверяем, существует ли файл
        if (!fs::exists(path)) {
            std::stringstream ss;
            ss << "Файл удален: " << path;
            m_alert_system->triggerAlert("FILE_DELETED", ss.str());
            return false;
        }
        
        // Получаем текущую информацию о файле
        FileInfo current = getFileInfo(path);
        
        // Если файл изменился
        if (baseline != current) {
            std::stringstream ss;
            
            if (baseline.hash != current.hash) {
                ss << "Обнаружено изменение содержимого файла: " << path;
                m_alert_system->triggerAlert("FILE_MODIFIED", ss.str());
            }
            else if (baseline.size != current.size) {
                ss << "Обнаружено изменение размера файла: " << path 
                   << " (было: " << baseline.size << ", стало: " << current.size << ")";
                m_alert_system->triggerAlert("FILE_SIZE_CHANGED", ss.str());
            }
            else if (baseline.last_modified != current.last_modified) {
                ss << "Обнаружено изменение времени модификации файла: " << path;
                m_alert_system->triggerAlert("FILE_TIME_CHANGED", ss.str());
            }
            
            // Вызываем пользовательский обработчик
            m_change_handler(path, baseline, current);
            
            return false;
        }
        
        return true; // Файл не изменился
    }
    catch (const std::exception& e) {
        std::stringstream ss;
        ss << "Ошибка при проверке целостности файла: " << path 
           << " - " << e.what();
        m_alert_system->triggerAlert("ERROR", ss.str());
        return false;
    }
}

} // namespace hids
