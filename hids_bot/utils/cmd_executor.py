#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Утилита для безопасного выполнения системных команд.
"""

import subprocess
import logging
import shlex
import os
from typing import List, Optional, Tuple, Union

# Настройка логирования
logger = logging.getLogger(__name__)

class CommandExecutor:
    """Класс для безопасного выполнения системных команд."""
    
    def __init__(self, timeout: int = 10):
        """
        Инициализация экземпляра.
        
        :param timeout: Таймаут выполнения команды в секундах
        """
        self.timeout = timeout
    
    def execute_command(self, command: str) -> str:
        """
        Выполняет команду в системе и возвращает ее вывод.
        
        :param command: Команда для выполнения
        :return: Вывод команды (stdout или stderr)
        """
        try:
            # Разбиваем команду на аргументы
            args = shlex.split(command)
            
            # Проверка на запрещенные команды
            if not self._is_command_allowed(args[0]):
                logger.warning(f"Попытка выполнить запрещенную команду: {command}")
                return "Ошибка: команда не разрешена к выполнению."
            
            # Выполняем команду
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False
            )
            
            # Проверяем результат
            if result.returncode == 0:
                return result.stdout
            else:
                logger.error(f"Ошибка при выполнении команды '{command}': {result.stderr}")
                return f"Ошибка: {result.stderr}"
        
        except subprocess.TimeoutExpired:
            logger.error(f"Тайм-аут при выполнении команды: {command}")
            return "Ошибка: превышено время выполнения команды."
        
        except Exception as e:
            logger.error(f"Исключение при выполнении команды '{command}': {e}")
            return f"Ошибка: {str(e)}"
    
    def execute_with_status(self, command: str) -> Tuple[bool, str]:
        """
        Выполняет команду и возвращает статус и вывод.
        
        :param command: Команда для выполнения
        :return: Кортеж (успех, вывод)
        """
        try:
            args = shlex.split(command)
            
            if not self._is_command_allowed(args[0]):
                return False, "Ошибка: команда не разрешена к выполнению."
            
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False
            )
            
            if result.returncode == 0:
                return True, result.stdout
            else:
                return False, result.stderr
        
        except Exception as e:
            return False, str(e)
    
    def _is_command_allowed(self, command: str) -> bool:
        """
        Проверяет, разрешена ли команда к выполнению.
        
        :param command: Имя команды
        :return: True если команда разрешена, иначе False
        """
        # Список разрешенных команд
        allowed_commands = {
            'ping', 'traceroute', 'dig', 'nslookup', 'whois', 'netstat', 'ss',
            'ps', 'top', 'systemctl', 'journalctl', 'cat', 'grep', 'head', 'tail',
            'ls', 'find', 'df', 'du', 'free', 'uptime', 'uname', 'hostname',
            'iptables', 'ip', 'ifconfig', 'route', 'geoiplookup', 'lsof', 'sudo'
        }
        
        # Извлекаем базовое имя команды (без пути)
        base_command = os.path.basename(command)
        
        return base_command in allowed_commands
    
    def check_service_status(self, service_name: str) -> Tuple[bool, str]:
        """
        Проверяет статус сервиса.
        
        :param service_name: Имя сервиса
        :return: Кортеж (работает, статус)
        """
        command = f"systemctl is-active {shlex.quote(service_name)}"
        is_active, output = self.execute_with_status(command)
        
        if is_active and output.strip() == "active":
            return True, "active"
        else:
            return False, output.strip()
    
    def get_file_content(self, file_path: str, lines: int = 20) -> str:
        """
        Безопасно получает содержимое файла.
        
        :param file_path: Путь к файлу
        :param lines: Количество строк для чтения (-1 для всего файла)
        :return: Содержимое файла
        """
        if not os.path.isfile(file_path):
            return f"Ошибка: файл не существует: {file_path}"
        
        if not os.access(file_path, os.R_OK):
            return f"Ошибка: нет доступа к файлу: {file_path}"
        
        if lines > 0:
            command = f"head -n {lines} {shlex.quote(file_path)}"
        else:
            command = f"cat {shlex.quote(file_path)}"
        
        return self.execute_command(command) 