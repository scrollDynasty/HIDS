#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import asyncio
from datetime import datetime, timedelta
from aiogram import types, Router, F
from aiogram.filters import Command
from aiogram.fsm.context import FSMContext

from database.db_manager import DatabaseManager
from utils.cmd_executor import CommandExecutor
from utils.ip_validator import IPValidator

# Создаем роутер для обработки уведомлений
router = Router(name="alert_router")
logger = logging.getLogger("alert_handler")

# Словарь для хранения состояний IP-адресов
ip_states = {}

# Период блокировки по умолчанию (в часах)
DEFAULT_BAN_PERIOD = 24

@router.message(Command("alerts"))
async def cmd_alerts(message: types.Message, db_manager: DatabaseManager):
    """Получить список последних уведомлений"""
    user_id = message.from_user.id
    
    # Получаем последние 10 уведомлений
    alerts = db_manager.get_recent_incidents(limit=10)
    
    if not alerts:
        await message.answer("Нет недавних уведомлений о вторжениях.")
        return
    
    # Формируем сообщение с уведомлениями
    response = "📋 <b>Последние уведомления:</b>\n\n"
    
    for idx, incident in enumerate(alerts, 1):
        ip = incident[0]
        reason = incident[1]
        alert_time = incident[2]
        is_blocked = bool(incident[3])
        
        # Добавляем статус IP (заблокирован/не заблокирован)
        status = "🔴 заблокирован" if is_blocked else "🟢 не заблокирован"
        
        response += f"{idx}. <b>IP:</b> {ip} ({status})\n"
        response += f"   <b>Причина:</b> {reason}\n"
        response += f"   <b>Время:</b> {alert_time}\n\n"
    
    await message.answer(response, parse_mode="HTML")

@router.message(Command("alert_detail"))
async def cmd_alert_detail(message: types.Message, db_manager: DatabaseManager):
    """Получить детальную информацию об IP-адресе"""
    args = message.text.split()
    if len(args) < 2:
        await message.answer("Использование: /alert_detail <IP-адрес>")
        return
    
    ip = args[1]
    ip_validator = IPValidator()
    
    # Проверяем валидность IP
    if not ip_validator.is_valid_ip(ip):
        await message.answer(f"❌ Неверный формат IP-адреса: {ip}")
        return
    
    # Получаем историю уведомлений для данного IP
    alerts = db_manager.get_incidents_by_ip(ip)
    
    if not alerts:
        await message.answer(f"Нет уведомлений для IP-адреса {ip}.")
        return
    
    # Формируем сообщение с детальной информацией
    response = f"🔍 <b>Детальная информация по IP {ip}:</b>\n\n"
    
    # Проверяем, заблокирован ли IP
    if ip in ip_states and ip_states[ip].get("blocked", False):
        unblock_time = ip_states[ip].get("unblock_time")
        if unblock_time:
            time_left = unblock_time - datetime.now()
            hours_left = time_left.total_seconds() / 3600
            response += f"🔴 <b>Статус:</b> Заблокирован\n"
            response += f"⏱ <b>Осталось до разблокировки:</b> {hours_left:.1f} часов\n\n"
        else:
            response += f"🔴 <b>Статус:</b> Заблокирован навсегда\n\n"
    else:
        response += f"🟢 <b>Статус:</b> Не заблокирован\n\n"
    
    # Добавляем список уведомлений
    response += "<b>История уведомлений:</b>\n"
    for idx, alert in enumerate(alerts, 1):
        alert_time = alert.get("timestamp", datetime.now()).strftime("%Y-%m-%d %H:%M:%S")
        reason = alert.get("reason", "Неизвестная причина")
        response += f"{idx}. <b>Время:</b> {alert_time}\n"
        response += f"   <b>Причина:</b> {reason}\n\n"
    
    # Геолокация IP (упрощенно)
    cmd_executor = CommandExecutor()
    geo_info = cmd_executor.execute_command(f"geoiplookup {ip}").strip()
    
    if geo_info and "IP Address not found" not in geo_info:
        response += f"🌐 <b>Геолокация:</b>\n{geo_info}\n\n"
    
    # Добавляем кнопки действий
    keyboard = types.InlineKeyboardMarkup(inline_keyboard=[
        [
            types.InlineKeyboardButton(text="🚫 Заблокировать", callback_data=f"block:{ip}"),
            types.InlineKeyboardButton(text="✅ Разблокировать", callback_data=f"unblock:{ip}")
        ],
        [
            types.InlineKeyboardButton(text="🔍 Whois", callback_data=f"whois:{ip}"),
            types.InlineKeyboardButton(text="📊 Трассировка", callback_data=f"trace:{ip}")
        ]
    ])
    
    await message.answer(response, parse_mode="HTML", reply_markup=keyboard)

@router.callback_query(F.data.startswith("block:"))
async def callback_block_ip(callback: types.CallbackQuery, state: FSMContext):
    """Обработчик блокировки IP-адреса"""
    ip = callback.data.split(":", 1)[1]
    
    # Запрашиваем период блокировки
    await callback.message.answer(
        f"На какой период заблокировать IP {ip}?\n"
        f"Укажите количество часов (0 для постоянной блокировки):"
    )
    
    # Сохраняем IP для дальнейшей обработки
    await state.update_data(action="block", ip=ip)
    await callback.answer()

@router.callback_query(F.data.startswith("unblock:"))
async def callback_unblock_ip(callback: types.CallbackQuery):
    """Обработчик разблокировки IP-адреса"""
    ip = callback.data.split(":", 1)[1]
    
    # Выполняем разблокировку
    cmd_executor = CommandExecutor()
    result = cmd_executor.execute_command(f"sudo iptables -D INPUT -s {ip} -j DROP")
    
    if result.strip():
        await callback.message.answer(f"❌ Ошибка при разблокировке IP {ip}:\n{result}")
    else:
        # Обновляем статус IP
        if ip in ip_states:
            ip_states[ip]["blocked"] = False
            ip_states[ip]["unblock_time"] = None
        
        await callback.message.answer(f"✅ IP-адрес {ip} разблокирован")
    
    await callback.answer()

@router.callback_query(F.data.startswith("whois:"))
async def callback_whois_ip(callback: types.CallbackQuery):
    """Обработчик запроса whois для IP-адреса"""
    ip = callback.data.split(":", 1)[1]
    
    # Выполняем whois запрос
    cmd_executor = CommandExecutor()
    result = cmd_executor.execute_command(f"whois {ip}")
    
    # Ограничиваем размер ответа
    if len(result) > 4000:
        result = result[:4000] + "...\n[Текст слишком длинный, показана только часть]"
    
    await callback.message.answer(f"🔍 <b>Whois для {ip}:</b>\n\n<pre>{result}</pre>", parse_mode="HTML")
    await callback.answer()

@router.callback_query(F.data.startswith("trace:"))
async def callback_trace_ip(callback: types.CallbackQuery):
    """Обработчик трассировки до IP-адреса"""
    ip = callback.data.split(":", 1)[1]
    
    # Уведомляем о начале трассировки
    await callback.message.answer(f"⏳ Запущена трассировка до {ip}. Это может занять некоторое время...")
    
    # Выполняем трассировку
    cmd_executor = CommandExecutor()
    result = cmd_executor.execute_command(f"traceroute -m 15 {ip}")
    
    await callback.message.answer(f"📊 <b>Трассировка до {ip}:</b>\n\n<pre>{result}</pre>", parse_mode="HTML")
    await callback.answer()

@router.message(F.text)
async def handle_ban_period(message: types.Message, state: FSMContext):
    """Обработчик периода блокировки"""
    # Получаем сохраненные данные
    data = await state.get_data()
    
    if not data or "action" not in data or data["action"] != "block":
        return
    
    try:
        hours = int(message.text.strip())
        ip = data["ip"]
        
        # Выполняем блокировку
        cmd_executor = CommandExecutor()
        result = cmd_executor.execute_command(f"sudo iptables -A INPUT -s {ip} -j DROP")
        
        if result.strip():
            await message.answer(f"❌ Ошибка при блокировке IP {ip}:\n{result}")
            await state.clear()
            return
        
        # Обновляем статус IP
        unblock_time = None
        if hours > 0:
            unblock_time = datetime.now() + timedelta(hours=hours)
            
            # Запускаем таймер разблокировки
            asyncio.create_task(schedule_unblock(ip, hours))
            
            status_msg = f"на {hours} часов (до {unblock_time.strftime('%Y-%m-%d %H:%M:%S')})"
        else:
            status_msg = "навсегда"
        
        ip_states[ip] = {
            "blocked": True,
            "unblock_time": unblock_time
        }
        
        await message.answer(f"✅ IP-адрес {ip} заблокирован {status_msg}")
        
        # Очищаем состояние
        await state.clear()
    
    except ValueError:
        await message.answer("❌ Пожалуйста, введите корректное число часов")
    except Exception as e:
        await message.answer(f"❌ Произошла ошибка: {str(e)}")
        await state.clear()

async def schedule_unblock(ip, hours):
    """Планирует разблокировку IP через указанное количество часов"""
    try:
        # Ждем указанное время
        await asyncio.sleep(hours * 3600)
        
        # Проверяем, всё ещё ли IP заблокирован
        if ip in ip_states and ip_states[ip].get("blocked", False):
            # Выполняем разблокировку
            cmd_executor = CommandExecutor()
            result = cmd_executor.execute_command(f"sudo iptables -D INPUT -s {ip} -j DROP")
            
            if not result.strip():
                # Обновляем статус IP
                ip_states[ip]["blocked"] = False
                ip_states[ip]["unblock_time"] = None
                
                logger.info(f"IP {ip} автоматически разблокирован после {hours} часов блокировки")
    
    except Exception as e:
        logger.error(f"Ошибка при автоматической разблокировке IP {ip}: {e}")

async def process_hids_alert(alert_info, bot=None, admin_chat_id=None):
    """
    Обрабатывает уведомление от HIDS и отправляет его в Telegram
    
    :param alert_info: Информация об уведомлении
    :param bot: Экземпляр бота
    :param admin_chat_id: ID чата администратора
    """
    if not bot or not admin_chat_id:
        logger.error("Не указан бот или ID чата администратора")
        return
    
    try:
        ip = alert_info.get('ip', 'N/A')
        reason = alert_info.get('reason', 'Неизвестная причина')
        timestamp = alert_info.get('timestamp', datetime.now())
        
        # Формируем сообщение
        alert_text = (
            f"🚨 <b>УВЕДОМЛЕНИЕ О ВТОРЖЕНИИ!</b>\n\n"
            f"🔹 <b>IP-адрес:</b> {ip}\n"
            f"🔹 <b>Причина:</b> {reason}\n"
            f"🔹 <b>Время:</b> {timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        )
        
        # Добавляем геолокацию (если IP валиден)
        ip_validator = IPValidator()
        if ip_validator.is_valid_ip(ip) and ip != "127.0.0.1" and ip != "0.0.0.0":
            cmd_executor = CommandExecutor()
            geo_info = cmd_executor.execute_command(f"geoiplookup {ip}").strip()
            
            if geo_info and "IP Address not found" not in geo_info:
                alert_text += f"🌐 <b>Геолокация:</b>\n{geo_info}\n\n"
        
        # Добавляем кнопки действий
        keyboard = types.InlineKeyboardMarkup(inline_keyboard=[
            [
                types.InlineKeyboardButton(text="🚫 Заблокировать", callback_data=f"block:{ip}"),
                types.InlineKeyboardButton(text="🔍 Подробнее", callback_data=f"whois:{ip}")
            ]
        ])
        
        # Отправляем уведомление
        await bot.send_message(
            chat_id=admin_chat_id,
            text=alert_text,
            parse_mode="HTML",
            reply_markup=keyboard
        )
        
        logger.info(f"Уведомление о вторжении отправлено в Telegram: IP={ip}, причина={reason}")
    
    except Exception as e:
        logger.error(f"Ошибка при отправке уведомления в Telegram: {e}") 