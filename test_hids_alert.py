#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Скрипт для тестирования уведомлений HIDS через сокет
"""

import os
import sys
import socket
import json
import argparse
from datetime import datetime

def send_test_alert(ip, reason, socket_path="/var/run/hids/alert.sock"):
    """
    Отправляет тестовое уведомление через UNIX-сокет
    
    Args:
        ip: IP-адрес "нарушителя"
        reason: Причина уведомления
        socket_path: Путь к UNIX-сокету
    """
    # Создаем сообщение
    alert = {
        "ip": ip,
        "reason": reason,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    # Преобразуем в JSON
    json_data = json.dumps(alert).encode('utf-8')
    
    # Проверяем существование сокета
    if not os.path.exists(socket_path):
        print(f"Ошибка: Сокет {socket_path} не существует")
        print("Убедитесь, что бот запущен и сокет создан")
        return False
    
    # Отправляем сообщение
    try:
        # Создаем UNIX-сокет
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(socket_path)
        
        # Отправляем данные
        sock.sendall(json_data)
        sock.close()
        
        print(f"Уведомление успешно отправлено:")
        print(f"  IP: {ip}")
        print(f"  Причина: {reason}")
        print(f"  Время: {alert['timestamp']}")
        return True
    
    except Exception as e:
        print(f"Ошибка при отправке уведомления: {str(e)}")
        return False

def main():
    # Создаем парсер аргументов
    parser = argparse.ArgumentParser(description="Отправка тестовых уведомлений HIDS")
    parser.add_argument("--ip", type=str, required=True, help="IP-адрес для уведомления")
    parser.add_argument("--reason", type=str, required=True, help="Причина уведомления")
    parser.add_argument("--socket", type=str, default="/var/run/hids/alert.sock", 
                        help="Путь к UNIX-сокету (по умолчанию: /var/run/hids/alert.sock)")
    
    # Парсим аргументы
    args = parser.parse_args()
    
    # Отправляем тестовое уведомление
    success = send_test_alert(args.ip, args.reason, args.socket)
    
    # Возвращаем код завершения
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main() 