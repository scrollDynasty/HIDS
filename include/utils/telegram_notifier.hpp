#pragma once

#include <string>

namespace hids {
namespace telegram {

/**
 * Класс для отправки оповещений в Telegram-бот через UNIX-сокет
 */
class TelegramNotifier {
public:
    /**
     * Конструктор
     * 
     * @param socket_path Путь к UNIX-сокету
     */
    TelegramNotifier(const std::string& socket_path = "/var/run/hids/alert.sock");

    /**
     * Отправляет оповещение о событии
     * 
     * @param ip IP-адрес события
     * @param reason Причина/описание события
     * @return true если оповещение отправлено успешно
     */
    bool sendAlert(const std::string& ip, const std::string& reason) const;

private:
    std::string m_socket_path;
    
    /**
     * Отправляет данные через UNIX-сокет
     * 
     * @param data Данные для отправки
     * @return true если отправка успешна
     */
    bool sendToSocket(const std::string& data) const;
};

} // namespace telegram
} // namespace hids 