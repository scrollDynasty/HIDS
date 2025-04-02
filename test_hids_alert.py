#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import socket
import json
import time
import argparse
import random
from datetime import datetime

def send_alert(socket_path, ip, reason):
    """
    Отправляет тестовое уведомление через UNIX-сокет
    
    :param socket_path: Путь к сокету
    :param ip: IP-адрес источника
    :param reason: Причина уведомления
    :return: True если успешно, False в противном случае
    """
    # Проверяем существование сокета
    if not os.path.exists(socket_path):
        print(f"Ошибка: Сокет {socket_path} не существует")
        return False
    
    # Формируем JSON с данными уведомления
    alert_data = {
        "ip": ip,
        "reason": reason,
        "timestamp": int(time.time())
    }
    
    try:
        # Создаем сокет
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        
        # Подключаемся к сокету
        client.connect(socket_path)
        
        # Отправляем данные
        client.sendall(json.dumps(alert_data).encode('utf-8'))
        
        # Закрываем соединение
        client.close()
        
        print(f"Уведомление успешно отправлено: {json.dumps(alert_data)}")
        return True
    
    except Exception as e:
        print(f"Ошибка при отправке уведомления: {e}")
        return False

def generate_random_ip():
    """Генерирует случайный IP-адрес"""
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

def generate_random_reason():
    """Генерирует случайную причину уведомления"""
    reasons = [
        "Неудачная попытка входа через SSH",
        "Подозрительное сканирование портов",
        "Обнаружена попытка брутфорс-атаки",
        "Изменение критичного системного файла",
        "Подозрительный сетевой трафик",
        "Обнаружен потенциальный руткит",
        "Аномальное поведение процесса",
        "Несанкционированное изменение пользователя",
        "Попытка эксплуатации уязвимости"
    ]
    return random.choice(reasons)

def main():
    """Основная функция программы"""
    # Парсинг аргументов командной строки
    parser = argparse.ArgumentParser(description="Утилита для тестирования уведомлений HIDS")
    parser.add_argument("--socket", "-s", default="/var/run/hids/alert.sock", 
                        help="Путь к UNIX-сокету (по умолчанию: /var/run/hids/alert.sock)")
    parser.add_argument("--ip", "-i", help="IP-адрес источника (по умолчанию: случайный)")
    parser.add_argument("--reason", "-r", help="Причина уведомления (по умолчанию: случайная)")
    parser.add_argument("--count", "-c", type=int, default=1, 
                        help="Количество уведомлений для отправки (по умолчанию: 1)")
    parser.add_argument("--delay", "-d", type=float, default=1.0, 
                        help="Задержка между уведомлениями в секундах (по умолчанию: 1)")
    
    args = parser.parse_args()
    
    # Выводим информацию о сокете
    print(f"Используется сокет: {args.socket}")
    
    # Отправляем указанное количество уведомлений
    for i in range(args.count):
        # Определяем IP и причину
        ip = args.ip if args.ip else generate_random_ip()
        reason = args.reason if args.reason else generate_random_reason()
        
        print(f"\nОтправка уведомления {i+1}/{args.count}:")
        if send_alert(args.socket, ip, reason):
            print(f"✅ Успешно отправлено в {datetime.now().strftime('%H:%M:%S')}")
        else:
            print(f"❌ Не удалось отправить")
        
        # Пауза между уведомлениями
        if i < args.count - 1:
            time.sleep(args.delay)
    
    print("\nЗавершено!")

if __name__ == "__main__":
    main() 