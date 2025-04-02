#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Модуль для получения уведомлений от HIDS через UNIX-сокет.
"""

import os
import json
import socket
import logging
import asyncio
import configparser
from pathlib import Path
from typing import Dict, Any, Optional, Callable

# Настройка логирования
logger = logging.getLogger(__name__)

# Получаем путь к UNIX-сокету из конфигурации
config_path = Path('config.ini')
if config_path.exists():
    config = configparser.ConfigParser()
    config.read('config.ini')
    SOCKET_PATH = config.get('HIDS', 'socket_path', fallback='/var/run/hids/alert.sock')
else:
    SOCKET_PATH = '/var/run/hids/alert.sock'

class HIDSListener:
    """Класс для прослушивания уведомлений от HIDS через UNIX-сокет."""
    
    def __init__(self, socket_path: str = SOCKET_PATH):
        """
        Инициализирует слушатель HIDS.
        
        Args:
            socket_path: Путь к UNIX-сокету
        """
        self.socket_path = socket_path
        self.running = False
        self.callback = None
        self._task = None
    
    def set_callback(self, callback: Callable[[str, str], None]) -> None:
        """
        Устанавливает функцию обратного вызова для обработки уведомлений.
        
        Args:
            callback: Функция для обработки уведомлений (ip, reason)
        """
        self.callback = callback
    
    async def start(self) -> None:
        """Запускает слушатель в асинхронном режиме."""
        if self.running:
            return
        
        self.running = True
        self._task = asyncio.create_task(self._listen())
    
    async def stop(self) -> None:
        """Останавливает слушатель."""
        self.running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None
    
    async def _listen(self) -> None:
        """Основной цикл прослушивания сокета."""
        # Проверяем наличие сокета
        if not os.path.exists(self.socket_path):
            logger.error(f"UNIX-сокет не существует: {self.socket_path}")
            # Создаем директорию для сокета, если она не существует
            os.makedirs(os.path.dirname(self.socket_path), exist_ok=True)
        
        # Удаляем существующий сокет, если он есть
        try:
            if os.path.exists(self.socket_path):
                os.unlink(self.socket_path)
        except OSError as e:
            logger.error(f"Ошибка при удалении существующего сокета: {e}")
            return
        
        # Создаем сокет
        try:
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            server.bind(self.socket_path)
            os.chmod(self.socket_path, 0o666)  # Устанавливаем права доступа
            server.listen(5)
            server.setblocking(False)
            
            logger.info(f"Слушатель HIDS запущен на сокете: {self.socket_path}")
            
            while self.running:
                # Асинхронно принимаем соединения
                conn, _ = await asyncio.get_event_loop().sock_accept(server)
                
                # Обрабатываем соединение
                asyncio.create_task(self._handle_connection(conn))
        
        except Exception as e:
            logger.error(f"Ошибка в слушателе HIDS: {e}")
        
        finally:
            # Закрываем сокет и удаляем файл
            try:
                if server:
                    server.close()
                if os.path.exists(self.socket_path):
                    os.unlink(self.socket_path)
            except Exception as e:
                logger.error(f"Ошибка при очистке сокета: {e}")
    
    async def _handle_connection(self, conn: socket.socket) -> None:
        """
        Обрабатывает входящее соединение от HIDS.
        
        Args:
            conn: Объект соединения
        """
        try:
            data = b""
            conn.setblocking(False)
            
            # Читаем данные из сокета
            while True:
                try:
                    chunk = await asyncio.get_event_loop().sock_recv(conn, 4096)
                    if not chunk:
                        break
                    data += chunk
                except (BlockingIOError, ConnectionResetError):
                    break
            
            if data:
                # Обрабатываем полученные данные
                try:
                    alert_data = json.loads(data.decode('utf-8'))
                    self._process_alert(alert_data)
                except json.JSONDecodeError:
                    logger.error(f"Получены некорректные данные от HIDS: {data}")
        
        except Exception as e:
            logger.error(f"Ошибка при обработке соединения HIDS: {e}")
        
        finally:
            # Закрываем соединение
            try:
                conn.close()
            except Exception:
                pass
    
    def _process_alert(self, alert_data: Dict[str, Any]) -> None:
        """
        Обрабатывает данные оповещения от HIDS.
        
        Args:
            alert_data: Данные оповещения
        """
        # Проверяем наличие необходимых полей
        if 'ip' not in alert_data or 'reason' not in alert_data:
            logger.error(f"Неполные данные оповещения от HIDS: {alert_data}")
            return
        
        ip = alert_data['ip']
        reason = alert_data['reason']
        
        logger.info(f"Получено оповещение от HIDS: IP={ip}, причина={reason}")
        
        # Вызываем функцию обратного вызова, если она установлена
        if self.callback:
            asyncio.create_task(self.callback(ip, reason))

# Функция для создания и настройки слушателя
async def setup_hids_listener(callback: Callable[[str, str], None]) -> HIDSListener:
    """
    Создает и настраивает слушатель HIDS.
    
    Args:
        callback: Функция для обработки уведомлений
        
    Returns:
        Настроенный экземпляр HIDSListener
    """
    listener = HIDSListener()
    listener.set_callback(callback)
    await listener.start()
    return listener 