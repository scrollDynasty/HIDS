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
    # Получаем системную информацию
    system_info = {
        "os": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "cpu_usage": psutil.cpu_percent(interval=1),
        "memory": psutil.virtual_memory(),
        "uptime": get_uptime(),
        "hostname": platform.node()
    }
    
    # Проверяем статус HIDS
    hids_status = check_hids_status()
    
    # Формируем сообщение
    response = (
        "🖥 <b>Информация о системе</b>\n\n"
        f"<b>Хост:</b> {system_info['hostname']}\n"
        f"<b>ОС:</b> {system_info['os']} {system_info['release']}\n"
        f"<b>Версия:</b> {system_info['version']}\n"
        f"<b>Время работы:</b> {system_info['uptime']}\n\n"
        
        f"<b>CPU:</b> {system_info['cpu_usage']}%\n"
        f"<b>Память:</b> {system_info['memory'].percent}% использовано\n"
        f"<b>Всего памяти:</b> {format_bytes(system_info['memory'].total)}\n"
        f"<b>Доступно памяти:</b> {format_bytes(system_info['memory'].available)}\n\n"
        
        f"<b>Статус HIDS:</b> {hids_status}\n"
    )
    
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

@router.message(Command("services"))
async def cmd_services(message: types.Message):
    """Показывает статус важных сервисов"""
    cmd_executor = CommandExecutor()
    
    # Список важных сервисов для проверки
    services = ["sshd", "firewalld", "iptables", "fail2ban"]
    
    response = "🔍 <b>Статус сервисов:</b>\n\n"
    
    for service in services:
        # Проверяем статус с помощью systemctl
        result = cmd_executor.execute_command(f"systemctl is-active {service}")
        status = "✅ активен" if result.strip() == "active" else "❌ неактивен"
        
        response += f"<b>{service}:</b> {status}\n"
    
    # Проверяем, есть ли правила iptables
    iptables_rules = cmd_executor.execute_command("iptables -L -n")
    
    # Считаем количество правил
    rule_count = 0
    for line in iptables_rules.splitlines():
        if line.startswith("ACCEPT") or line.startswith("DROP") or line.startswith("REJECT"):
            rule_count += 1
    
    response += f"\n<b>Правила iptables:</b> {rule_count} активных правил\n"
    
    # Проверяем открытые порты
    open_ports = cmd_executor.execute_command("netstat -tuln | grep LISTEN")
    response += "\n<b>Открытые порты:</b>\n"
    
    for line in open_ports.splitlines()[:10]:  # Ограничиваем вывод 10 строками
        if ":" in line:
            parts = line.split()
            for part in parts:
                if ":" in part:
                    address = part
                    response += f"• {address}\n"
                    break
    
    await message.answer(response, parse_mode="HTML")
    logger.info(f"Пользователь {message.from_user.id} запросил статус сервисов")

@router.message(Command("logs"))
async def cmd_logs(message: types.Message):
    """Показывает последние записи в системном журнале"""
    cmd_executor = CommandExecutor()
    
    # Получаем последние 10 строк журнала
    journal = cmd_executor.execute_command("journalctl -n 10 --no-pager")
    
    response = "📜 <b>Последние записи в журнале:</b>\n\n<pre>"
    response += journal
    response += "</pre>"
    
    # Если ответ слишком длинный, обрезаем его
    if len(response) > 4000:
        response = response[:3900] + "...</pre>\n\n[Сообщение обрезано]"
    
    await message.answer(response, parse_mode="HTML")
    logger.info(f"Пользователь {message.from_user.id} запросил системные логи")

@router.message(Command("network"))
async def cmd_network(message: types.Message):
    """Показывает сетевые соединения"""
    cmd_executor = CommandExecutor()
    
    # Получаем открытые сетевые соединения
    netstat = cmd_executor.execute_command("netstat -tunapl | grep -v 'TIME_WAIT' | head -20")
    
    response = "🌐 <b>Активные сетевые соединения:</b>\n\n<pre>"
    response += netstat
    response += "</pre>"
    
    # Если ответ слишком длинный, обрезаем его
    if len(response) > 4000:
        response = response[:3900] + "...</pre>\n\n[Сообщение обрезано]"
    
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