#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Модуль для работы с системными командами через Telegram-бот.
"""

import logging
import platform
import psutil
import os
from datetime import datetime
from aiogram import Router, types
from aiogram.filters import Command

from utils.cmd_executor import CommandExecutor
from utils.system_commands import check_hids_status

# Настройка логирования
logger = logging.getLogger(__name__)

# Создаем роутер
router = Router(name="system_router")

@router.message(Command("system"))
async def cmd_system(message: types.Message):
    """Показывает общую информацию о системе"""
    try:
        # Получаем системную информацию
        system_info = {
            "os": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "hostname": platform.node()
        }
        
        # Получаем данные о CPU и памяти
        try:
            system_info["cpu_usage"] = psutil.cpu_percent(interval=1)
            system_info["memory"] = psutil.virtual_memory()
        except Exception:
            system_info["cpu_usage"] = "Н/Д"
            system_info["memory"] = None
        
        # Получаем время работы системы
        system_info["uptime"] = get_uptime()
        
        # Проверяем статус HIDS
        hids_status = check_hids_status()
        
        # Формируем сообщение
        response = (
            "🖥 <b>Информация о системе</b>\n\n"
            f"<b>Хост:</b> {system_info['hostname']}\n"
            f"<b>ОС:</b> {system_info['os']} {system_info['release']}\n"
            f"<b>Версия:</b> {system_info['version']}\n"
            f"<b>Время работы:</b> {system_info['uptime']}\n\n"
        )
        
        # Добавляем информацию о CPU и памяти, если доступна
        if isinstance(system_info["cpu_usage"], (int, float)):
            response += f"<b>CPU:</b> {system_info['cpu_usage']}%\n"
        else:
            response += "<b>CPU:</b> Не удалось получить информацию\n"
        
        if system_info["memory"]:
            response += (
                f"<b>Память:</b> {system_info['memory'].percent}% использовано\n"
                f"<b>Всего памяти:</b> {format_bytes(system_info['memory'].total)}\n"
                f"<b>Доступно памяти:</b> {format_bytes(system_info['memory'].available)}\n\n"
            )
        else:
            response += "<b>Память:</b> Не удалось получить информацию\n\n"
        
        response += f"<b>Статус HIDS:</b> {hids_status}\n"
        
        # Добавляем кнопки
        keyboard = types.InlineKeyboardMarkup(inline_keyboard=[
            [
                types.InlineKeyboardButton(text="📊 Сетевые соединения", callback_data="system:network"),
                types.InlineKeyboardButton(text="📋 Запущенные процессы", callback_data="system:processes")
            ],
            [
                types.InlineKeyboardButton(text="🔄 Обновить", callback_data="system:refresh"),
                types.InlineKeyboardButton(text="📜 Логи", callback_data="system:logs")
            ]
        ])
        
        await message.answer(response, parse_mode="HTML", reply_markup=keyboard)
        logger.info(f"Пользователь {message.from_user.id} запросил информацию о системе")
    except Exception as e:
        error_msg = f"❌ <b>Ошибка при получении системной информации:</b> {str(e)}"
        await message.answer(error_msg, parse_mode="HTML")
        logger.error(f"Ошибка при выполнении команды /system: {e}")

@router.message(Command("services"))
async def cmd_services(message: types.Message):
    """Показывает статус важных сервисов"""
    cmd_executor = CommandExecutor()
    
    # Список важных сервисов для проверки
    services = ["sshd", "firewalld", "iptables", "fail2ban"]
    
    response = "🔍 <b>Статус сервисов:</b>\n\n"
    
    for service in services:
        try:
            # Проверяем статус с помощью systemctl или service
            result = cmd_executor.execute_command(f"systemctl is-active {service} 2>/dev/null || service {service} status 2>/dev/null || echo 'не найден'")
            status = "✅ активен" if "active" in result.strip() or "running" in result.strip() else "❌ неактивен"
            
            response += f"<b>{service}:</b> {status}\n"
        except Exception as e:
            response += f"<b>{service}:</b> ❌ ошибка проверки\n"
    
    # Проверяем, есть ли правила iptables
    try:
        iptables_rules = cmd_executor.execute_command("iptables -L -n 2>/dev/null || echo 'Ошибка доступа к iptables'")
        
        # Считаем количество правил
        rule_count = 0
        for line in iptables_rules.splitlines():
            if line.startswith("ACCEPT") or line.startswith("DROP") or line.startswith("REJECT"):
                rule_count += 1
        
        response += f"\n<b>Правила iptables:</b> {rule_count} активных правил\n"
    except Exception:
        response += f"\n<b>Правила iptables:</b> Не удалось получить\n"
    
    # Проверяем открытые порты
    try:
        open_ports = cmd_executor.execute_command("netstat -tuln 2>/dev/null || ss -tuln 2>/dev/null || echo 'Не удалось получить информацию'")
        response += "\n<b>Открытые порты:</b>\n"
        
        port_count = 0
        for line in open_ports.splitlines():
            if "LISTEN" in line and ":" in line:
                parts = line.split()
                for part in parts:
                    if ":" in part:
                        address = part
                        response += f"• {address}\n"
                        port_count += 1
                        if port_count >= 10:  # Ограничиваем вывод 10 портами
                            break
                if port_count >= 10:
                    break
                            
        if port_count == 0:
            response += "Открытых портов не обнаружено или недостаточно прав\n"
    except Exception:
        response += "\n<b>Открытые порты:</b> Не удалось получить информацию\n"
    
    await message.answer(response, parse_mode="HTML")
    logger.info(f"Пользователь {message.from_user.id} запросил статус сервисов")

@router.message(Command("logs"))
async def cmd_logs(message: types.Message):
    """Показывает последние записи в системном журнале"""
    cmd_executor = CommandExecutor()
    
    # Пытаемся получить логи из разных источников
    try:
        # Пробуем journalctl, если не работает, пробуем /var/log/syslog или messages
        journal = cmd_executor.execute_command(
            "journalctl -n 10 --no-pager 2>/dev/null || " +
            "tail -n 10 /var/log/syslog 2>/dev/null || " +
            "tail -n 10 /var/log/messages 2>/dev/null || " +
            "echo 'Не удалось получить системные логи. Недостаточно прав или логи отсутствуют.'"
        )
        
        response = "📜 <b>Последние записи в журнале:</b>\n\n<pre>"
        response += journal
        response += "</pre>"
        
        # Если ответ слишком длинный, обрезаем его
        if len(response) > 4000:
            response = response[:3900] + "...</pre>\n\n[Сообщение обрезано]"
    except Exception as e:
        response = f"❌ <b>Ошибка при получении логов:</b> {str(e)}"
    
    await message.answer(response, parse_mode="HTML")
    logger.info(f"Пользователь {message.from_user.id} запросил системные логи")

@router.message(Command("network"))
async def cmd_network(message: types.Message):
    """Показывает сетевые соединения"""
    cmd_executor = CommandExecutor()
    
    try:
        # Пытаемся получить информацию о сетевых соединениях из разных источников
        netstat = cmd_executor.execute_command(
            "netstat -tunapl 2>/dev/null | grep -v 'TIME_WAIT' | head -20 2>/dev/null || " +
            "ss -tunapl 2>/dev/null | head -20 2>/dev/null || " +
            "echo 'Не удалось получить информацию о сетевых соединениях. Недостаточно прав или утилиты отсутствуют.'"
        )
        
        # Получаем информацию о сетевых интерфейсах
        interfaces = cmd_executor.execute_command(
            "ip addr 2>/dev/null || ifconfig 2>/dev/null || echo 'Не удалось получить информацию о сетевых интерфейсах.'"
        )
        
        # Извлекаем только IP-адреса из вывода
        ip_addresses = []
        for line in interfaces.splitlines():
            if "inet " in line:
                parts = line.strip().split()
                # Ищем значение после "inet"
                for i, part in enumerate(parts):
                    if part == "inet" and i + 1 < len(parts):
                        ip_addresses.append(parts[i + 1])
        
        response = "🌐 <b>Сетевая информация</b>\n\n"
        
        if ip_addresses:
            response += "<b>IP-адреса:</b>\n"
            for ip in ip_addresses:
                response += f"• {ip}\n"
            response += "\n"
        
        response += "<b>Активные сетевые соединения:</b>\n\n<pre>"
        response += netstat
        response += "</pre>"
        
        # Если ответ слишком длинный, обрезаем его
        if len(response) > 4000:
            response = response[:3900] + "...</pre>\n\n[Сообщение обрезано]"
    except Exception as e:
        response = f"❌ <b>Ошибка при получении сетевой информации:</b> {str(e)}"
    
    await message.answer(response, parse_mode="HTML")
    logger.info(f"Пользователь {message.from_user.id} запросил информацию о сетевых соединениях")

@router.callback_query(lambda c: c.data.startswith("system:"))
async def callback_system(callback: types.CallbackQuery):
    """Обрабатывает нажатия на кнопки системной информации"""
    action = callback.data.split(":", 1)[1]
    
    if action == "refresh":
        # Вызываем команду system заново
        await cmd_system(callback.message)
    elif action == "network":
        # Вызываем команду network
        await cmd_network(callback.message)
    elif action == "logs":
        # Вызываем команду logs
        await cmd_logs(callback.message)
    elif action == "processes":
        # Получаем список процессов
        cmd_executor = CommandExecutor()
        processes = cmd_executor.execute_command("ps aux | head -10")
        
        response = "📋 <b>Запущенные процессы (TOP 10):</b>\n\n<pre>"
        response += processes
        response += "</pre>"
        
        await callback.message.answer(response, parse_mode="HTML")
    
    await callback.answer()

def get_uptime():
    """Возвращает время работы системы в человекочитаемом формате"""
    try:
        with open("/proc/uptime", "r") as f:
            uptime_seconds = float(f.readline().split()[0])
            
        days, remainder = divmod(uptime_seconds, 86400)
        hours, remainder = divmod(remainder, 3600)
        minutes, seconds = divmod(remainder, 60)
        
        return f"{int(days)}д {int(hours)}ч {int(minutes)}м {int(seconds)}с"
    except Exception as e:
        logger.error(f"Ошибка при получении времени работы: {e}")
        return "Неизвестно"

def format_bytes(size):
    """Форматирует байты в человекочитаемый формат"""
    power = 2**10  # 1024
    n = 0
    power_labels = {0: '', 1: 'K', 2: 'M', 3: 'G', 4: 'T'}
    
    while size > power:
        size /= power
        n += 1
    
    return f"{size:.2f} {power_labels[n]}B" 