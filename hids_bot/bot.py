#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
HIDS Telegram Bot - Бот для оповещения и управления системой обнаружения вторжений на хосте.
"""

import os
import logging
import asyncio
from aiogram import Bot, Dispatcher, types
from aiogram.filters import Command
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.client.session.aiohttp import AiohttpSession
from aiogram.client.default import DefaultBotProperties
from dotenv import load_dotenv

from utils.system_commands import block_ip, unblock_ip, check_hids_status, is_ip_blocked
from utils.ip_validator import is_valid_ip
from database.db_manager import DatabaseManager
from handlers.auth_handler import authorized_only, AUTHORIZED_USERS, router as auth_router
from handlers.alert_handler import router as alert_router, process_hids_alert
from handlers.system_handler import router as system_router
from hids_listener import HIDSListener

# Загрузка переменных окружения
load_dotenv()

# Конфигурация логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("hids_bot.log"),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

# Получение токена из переменных окружения
BOT_TOKEN = os.getenv("BOT_TOKEN")
if not BOT_TOKEN:
    raise ValueError("Не указан токен бота. Добавьте его в файл .env")

# ID чата администратора
ADMIN_CHAT_ID = os.getenv("ADMIN_CHAT_ID")
if not ADMIN_CHAT_ID:
    logger.warning("Не указан ID чата администратора. Некоторые функции могут быть недоступны.")

# Путь к UNIX-сокету HIDS
HIDS_SOCKET = os.getenv("HIDS_SOCKET", "/var/run/hids/alert.sock")

# Инициализация бота
async def main():
    # Настройка сессии
    session = AiohttpSession(json_serialize=lambda obj: obj)
    bot_properties = DefaultBotProperties(parse_mode="HTML")
    
    # Инициализация бота и диспетчера
    bot = Bot(token=BOT_TOKEN, session=session, default=bot_properties)
    dp = Dispatcher(storage=MemoryStorage())
    
    # Инициализация БД
    db_manager = DatabaseManager("hids.db")
    db_manager.init_db()
    
    # Регистрация мидлварей
    dp.message.middleware.register(lambda handler, event, data: data.update({"db_manager": db_manager}))
    dp.callback_query.middleware.register(lambda handler, event, data: data.update({"db_manager": db_manager}))
    
    # Регистрация роутеров
    dp.include_router(auth_router)
    dp.include_router(alert_router)
    dp.include_router(system_router)
    
    # Коллбэк для обработки уведомлений от HIDS
    async def handle_hids_notification(alert_info):
        await process_hids_alert(alert_info, bot, ADMIN_CHAT_ID)
    
    # Инициализация и запуск слушателя HIDS
    hids_listener = HIDSListener(
        socket_path=HIDS_SOCKET,
        db_manager=db_manager,
        callback=handle_hids_notification
    )
    hids_listener.start()
    
    # Обработчик команды /start
    @dp.message(Command("start"))
    async def cmd_start(message: types.Message):
        user_id = message.from_user.id
        user_fullname = message.from_user.full_name
        
        await message.answer(
            f"👋 Привет, {user_fullname}!\n\n"
            f"Я бот для управления системой обнаружения вторжений (HIDS).\n"
            f"Я буду оповещать о потенциальных вторжениях и помогать управлять защитой.\n\n"
            f"Доступные команды:\n"
            f"/alerts - Показать последние уведомления\n"
            f"/alert_detail <IP> - Показать детальную информацию об IP\n"
            f"/system - Показать состояние системы\n"
            f"/help - Показать справку по всем командам"
        )
        
        # Логируем начало работы с ботом
        logger.info(f"Пользователь {user_id} ({user_fullname}) начал работу с ботом")
    
    # Обработчик команды /help
    @dp.message(Command("help"))
    async def cmd_help(message: types.Message):
        await message.answer(
            "📚 <b>Справка по командам</b>\n\n"
            "<b>Основные команды:</b>\n"
            "/start - Начать работу с ботом\n"
            "/help - Показать эту справку\n\n"
            
            "<b>Управление уведомлениями:</b>\n"
            "/alerts - Показать последние уведомления\n"
            "/alert_detail <IP> - Подробная информация об уведомлениях для IP\n\n"
            
            "<b>Системная информация:</b>\n"
            "/system - Проверить состояние системы\n"
            "/services - Статус важных сервисов\n"
            "/logs - Последние записи в журнале\n"
            "/network - Сетевые соединения\n\n"
            
            "<b>Действия с IP:</b>\n"
            "Через интерфейс команды /alert_detail можно:\n"
            "- Заблокировать IP\n"
            "- Разблокировать IP\n"
            "- Посмотреть Whois\n"
            "- Запустить трассировку\n"
        )
    
    try:
        # Отправка сообщения администратору о запуске бота
        if ADMIN_CHAT_ID:
            await bot.send_message(
                chat_id=ADMIN_CHAT_ID,
                text="🚀 <b>Бот HIDS запущен!</b>\n\n"
                     "Система готова к обнаружению вторжений и отправке уведомлений."
            )
        
        # Запуск поллинга
        await dp.start_polling(bot)
    
    finally:
        # Остановка слушателя HIDS
        hids_listener.stop()
        
        # Корректное завершение сессии
        await bot.session.close()

if __name__ == "__main__":
    try:
        # Запуск бота
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        # Выход по Ctrl+C
        logger.info("Бот остановлен!")
    except Exception as e:
        logger.error(f"Произошла ошибка: {e}", exc_info=True) 