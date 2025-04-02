#include "../../include/utils/telegram_notifier.hpp"
#include "../../include/utils/utils.hpp"

#include <string>
#include <sstream>
#include <cstring>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <iostream>
#include <fcntl.h>
#include <json/json.h>  // Требуется libjsoncpp-dev

namespace hids {
namespace telegram {

TelegramNotifier::TelegramNotifier(const std::string& socket_path)
    : m_socket_path(socket_path)
{
}

bool TelegramNotifier::sendAlert(const std::string& ip, const std::string& reason) const {
    // Создаем JSON-объект с информацией о событии
    Json::Value alert;
    alert["ip"] = ip;
    alert["reason"] = reason;
    alert["timestamp"] = utils::formatTime(std::time(nullptr));
    
    // Сериализуем JSON в строку
    Json::StreamWriterBuilder writer;
    std::string json_data = Json::writeString(writer, alert);
    
    // Отправляем данные через сокет
    return sendToSocket(json_data);
}

bool TelegramNotifier::sendToSocket(const std::string& data) const {
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock == -1) {
        std::cerr << "Ошибка при создании сокета: " << strerror(errno) << std::endl;
        return false;
    }
    
    // Устанавливаем неблокирующий режим для сокета
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    
    // Настраиваем адрес сокета
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, m_socket_path.c_str(), sizeof(addr.sun_path) - 1);
    
    // Устанавливаем таймаут
    struct timeval tv;
    tv.tv_sec = 2;  // 2 секунды таймаут
    tv.tv_usec = 0;
    
    // Пытаемся подключиться
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        if (errno != EINPROGRESS) {
            std::cerr << "Ошибка подключения к сокету: " << strerror(errno) << std::endl;
            close(sock);
            return false;
        }
        
        // Ожидаем завершения подключения с таймаутом
        fd_set write_fds;
        FD_ZERO(&write_fds);
        FD_SET(sock, &write_fds);
        
        int result = select(sock + 1, NULL, &write_fds, NULL, &tv);
        if (result <= 0) {
            std::cerr << "Таймаут подключения к сокету" << std::endl;
            close(sock);
            return false;
        }
    }
    
    // Отправляем данные
    ssize_t bytes_sent = send(sock, data.c_str(), data.length(), 0);
    close(sock);
    
    if (bytes_sent != static_cast<ssize_t>(data.length())) {
        std::cerr << "Ошибка отправки данных через сокет: " << strerror(errno) << std::endl;
        return false;
    }
    
    return true;
}

} // namespace telegram
} // namespace hids