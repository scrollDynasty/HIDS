#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Модуль для прослушивания уведомлений от HIDS через UNIX-сокет.
"""

import os
import json
import socket
import threading
import logging
import asyncio
import time
from typing import Callable, Dict, Any, Optional

# Настройка логирования
logger = logging.getLogger(__name__)

class HIDSListener:
    """
    Класс для прослушивания уведомлений от HIDS через UNIX-сокет.
    
    Атрибуты:
        socket_path: Путь к UNIX-сокету
        db_manager: Объект для работы с базой данных
        callback: Асинхронная функция для обработки уведомлений
    """
    
    def __init__(self, socket_path: str, db_manager, callback: Callable = None):
        """
        Инициализация слушателя HIDS.
        
        Args:
            socket_path: Путь к UNIX-сокету
            db_manager: Объект для работы с базой данных
            callback: Асинхронная функция для обработки уведомлений
        """
        self.socket_path = socket_path
        self.db_manager = db_manager
        self.callback = callback
        self.running = False
        self.thread = None
        self.loop = None
        
    def start(self):
        """Запускает прослушивание в отдельном потоке."""
        if self.running:
            logger.warning("Слушатель HIDS уже запущен")
            return
        
        self.running = True
        self.thread = threading.Thread(target=self._run_listener)
        self.thread.daemon = True
        self.thread.start()
        logger.info("Слушатель HIDS запущен")
        
    def stop(self):
        """Останавливает прослушивание."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=1.0)
            self.thread = None
        
        # Удаляем сокет, если он существует
        if os.path.exists(self.socket_path):
            try:
                os.unlink(self.socket_path)
                logger.info(f"Сокет удален: {self.socket_path}")
            except OSError as e:
                logger.error(f"Ошибка при удалении сокета: {e}")
        
        logger.info("Слушатель HIDS остановлен")
        
    def _run_listener(self):
        """Основной метод прослушивания (запускается в отдельном потоке)."""
        # Создаем директорию для сокета, если она не существует
        socket_dir = os.path.dirname(self.socket_path)
        if not os.path.exists(socket_dir):
            try:
                os.makedirs(socket_dir, exist_ok=True)
                logger.info(f"Создана директория для сокета: {socket_dir}")
            except OSError as e:
                logger.error(f"Не удалось создать директорию для сокета: {e}")
                return
        
        # Удаляем старый сокет, если он существует
        if os.path.exists(self.socket_path):
            try:
                os.unlink(self.socket_path)
            except OSError as e:
                logger.error(f"Не удалось удалить существующий сокет: {e}")
                return
                
        # Создаем и настраиваем сокет
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.bind(self.socket_path)
        server.listen(5)
        
        # Устанавливаем неблокирующий режим
        server.setblocking(False)
        os.chmod(self.socket_path, 0o777)  # Разрешаем доступ всем пользователям
        
        logger.info(f"Сокет создан и прослушивается: {self.socket_path}")
        
        # Создаем событийный цикл для этого потока
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        
        # Основной цикл прослушивания
        while self.running:
            try:
                # Пытаемся принять подключение
                readable, _, _ = select.select([server], [], [], 1.0)
                
                if server in readable:
                    client, _ = server.accept()
                    
                    # Принимаем данные
                    data = b""
                    client.settimeout(1.0)
                    
                    while True:
                        try:
                            chunk = client.recv(4096)
                            if not chunk:
                                break
                            data += chunk
                        except socket.timeout:
                            break
                        
                    client.close()
                    
                    if data:
                        # Обрабатываем полученные данные
                        self._process_data(data)
            
            except Exception as e:
                logger.error(f"Ошибка при прослушивании сокета: {e}")
                time.sleep(1.0)  # Чтобы избежать высокой загрузки CPU в случае ошибки
        
        # Закрываем сокет
        server.close()
        
        # Закрываем событийный цикл
        if self.loop:
            self.loop.close()
            
    def _process_data(self, data: bytes):
        """
        Обрабатывает полученные данные.
        
        Args:
            data: Полученные двоичные данные
        """
        try:
            # Декодируем JSON
            alert_info = json.loads(data.decode('utf-8'))
            
            # Проверяем наличие необходимых полей
            if not all(key in alert_info for key in ['ip', 'reason']):
                logger.error(f"Получены некорректные данные: {alert_info}")
                return
            
            # Логируем уведомление
            logger.info(f"Получено уведомление от HIDS: IP={alert_info['ip']}, причина={alert_info['reason']}")
            
            # Добавляем уведомление в базу данных
            self.db_manager.add_incident(alert_info['ip'], alert_info['reason'])
            
            # Вызываем callback-функцию, если она задана
            if self.callback:
                asyncio.run_coroutine_threadsafe(self.callback(alert_info), self.loop)
        
        except json.JSONDecodeError as e:
            logger.error(f"Не удалось декодировать JSON: {e}")
        
        except Exception as e:
            logger.error(f"Ошибка при обработке данных: {e}")

# Добавляем import select для работы с сокетами неблокирующего режима
import select 