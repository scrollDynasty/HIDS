#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Модуль для выполнения системных команд для взаимодействия с HIDS.
"""

import os
import signal
import logging
import subprocess
import configparser
from pathlib import Path
from typing import Optional, Tuple, List

# Получаем путь к конфигурационному файлу
config_path = Path('config.ini')
if config_path.exists():
    config = configparser.ConfigParser()
    config.read('config.ini')
    IPTABLES_PATH = config.get('HIDS', 'iptables_path', fallback='/sbin/iptables')
else:
    IPTABLES_PATH = '/sbin/iptables'

logger = logging.getLogger(__name__)

def execute_command(command: List[str]) -> Tuple[bool, str]:
    """
    Безопасно выполняет команду в системе.
    
    Args:
        command: Список строк с командой и аргументами
        
    Returns:
        Кортеж (успех, вывод)
    """
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=10
        )
        
        if result.returncode == 0:
            return True, result.stdout.strip()
        else:
            logger.error(f"Ошибка при выполнении команды: {' '.join(command)}")
            logger.error(f"Код ошибки: {result.returncode}, Сообщение: {result.stderr}")
            return False, result.stderr.strip()
    
    except subprocess.TimeoutExpired:
        logger.error(f"Тайм-аут при выполнении команды: {' '.join(command)}")
        return False, "Тайм-аут выполнения команды"
    
    except Exception as e:
        logger.error(f"Исключение при выполнении команды {' '.join(command)}: {e}")
        return False, str(e)

def block_ip(ip: str, reason: str = "Заблокировано HIDS") -> bool:
    """
    Блокирует IP-адрес с помощью iptables.
    
    Args:
        ip: IP-адрес для блокировки
        reason: Причина блокировки (для комментария)
        
    Returns:
        True если блокировка успешна, иначе False
    """
    # Проверяем, не заблокирован ли уже этот IP
    if is_ip_blocked(ip):
        return True
    
    # Формируем команду для iptables
    command = [
        IPTABLES_PATH,
        '-A', 'INPUT',
        '-s', ip,
        '-j', 'DROP',
        '-m', 'comment',
        '--comment', f"HIDS: {reason}"
    ]
    
    success, _ = execute_command(command)
    return success

def unblock_ip(ip: str) -> bool:
    """
    Разблокирует IP-адрес, удаляя правило iptables.
    
    Args:
        ip: IP-адрес для разблокировки
        
    Returns:
        True если разблокировка успешна, иначе False
    """
    if not is_ip_blocked(ip):
        return True
    
    # Формируем команду для удаления всех правил, блокирующих указанный IP
    command = [
        IPTABLES_PATH,
        '-D', 'INPUT',
        '-s', ip,
        '-j', 'DROP'
    ]
    
    success, _ = execute_command(command)
    
    # Если правило не найдено, считаем это успехом (IP уже разблокирован)
    return success

def is_ip_blocked(ip: str) -> bool:
    """
    Проверяет, заблокирован ли IP-адрес в iptables.
    
    Args:
        ip: IP-адрес для проверки
        
    Returns:
        True если IP заблокирован, иначе False
    """
    # Команда для проверки наличия правила
    command = [
        IPTABLES_PATH,
        '-C', 'INPUT',
        '-s', ip,
        '-j', 'DROP'
    ]
    
    success, _ = execute_command(command)
    return success

def get_hids_pid() -> Optional[int]:
    """
    Возвращает PID процесса HIDS.
    
    Returns:
        PID процесса HIDS или None, если процесс не найден
    """
    try:
        # Пытаемся найти процесс HIDS с помощью pgrep
        command = ['pgrep', '-f', 'hids']
        success, output = execute_command(command)
        
        if success and output:
            # Возвращаем первый найденный PID
            return int(output.split()[0])
        
        return None
    
    except (ValueError, IndexError) as e:
        logger.error(f"Ошибка при получении PID процесса HIDS: {e}")
        return None

def check_hids_status() -> str:
    """
    Проверяет текущий статус сервиса HIDS.
    
    Returns:
        Строка с описанием статуса
    """
    pid = get_hids_pid()
    
    if pid is None:
        return "⚠️ HIDS не запущен"
    
    # Проверяем, что процесс действительно работает
    try:
        os.kill(pid, 0)  # Проверка существования процесса
        
        # Дополнительно проверим время работы процесса
        command = ['ps', '-p', str(pid), '-o', 'etime=']
        success, uptime = execute_command(command)
        
        if success:
            return f"✅ HIDS запущен (PID: {pid}, время работы: {uptime.strip()})"
        else:
            return f"✅ HIDS запущен (PID: {pid})"
    
    except OSError:
        return "⚠️ HIDS не запущен (процесс не отвечает)"

def restart_hids() -> bool:
    """
    Перезапускает сервис HIDS.
    
    Returns:
        True если перезапуск успешен, иначе False
    """
    # Сначала пытаемся найти PID процесса
    pid = get_hids_pid()
    
    if pid is not None:
        # Посылаем сигнал SIGTERM для корректного завершения
        try:
            os.kill(pid, signal.SIGTERM)
            logger.info(f"Отправлен сигнал SIGTERM процессу HIDS (PID: {pid})")
        except OSError as e:
            logger.error(f"Ошибка при отправке сигнала завершения процессу HIDS: {e}")
            return False
    
    # Затем запускаем HIDS снова
    # Путь к исполняемому файлу HIDS нужно настроить в конфигурации
    hids_executable = config.get('HIDS', 'executable_path', fallback='/usr/bin/hids')
    
    command = [hids_executable]
    success, _ = execute_command(command)
    
    if success:
        logger.info("HIDS успешно перезапущен")
    else:
        logger.error("Не удалось перезапустить HIDS")
    
    return success 