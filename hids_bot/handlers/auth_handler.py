#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Модуль авторизации для HIDS Telegram Bot.
"""

import os
import functools
import logging
from typing import Callable, Any, Dict
from aiogram import Router, types
from aiogram.filters import Command
from dotenv import load_dotenv

# Настройка логирования
logger = logging.getLogger(__name__)

# Создаем роутер
router = Router(name="auth_router")

# Загрузка списка авторизованных пользователей из .env
load_dotenv()
AUTHORIZED_USERS_STR = os.getenv("AUTHORIZED_USERS", "")
AUTHORIZED_USERS = [int(user_id.strip()) for user_id in AUTHORIZED_USERS_STR.split(",") if user_id.strip().isdigit()]

def authorized_only(func: Callable) -> Callable:
    """
    Декоратор для проверки, авторизован ли пользователь.
    Функция будет выполнена только если ID пользователя находится в списке AUTHORIZED_USERS.
    """
    @functools.wraps(func)
    async def wrapped(message: types.Message, *args, **kwargs):
        user_id = message.from_user.id
        
        if user_id not in AUTHORIZED_USERS:
            await message.answer(
                "⛔ У вас нет доступа к этой команде. "
                "Обратитесь к администратору системы."
            )
            logger.warning(f"Неавторизованный доступ от пользователя {user_id} ({message.from_user.full_name})")
            return
        
        logger.debug(f"Авторизованный доступ от пользователя {user_id} ({message.from_user.full_name})")
        return await func(message, *args, **kwargs)
    
    return wrapped

def auth_middleware(handler, event, data):
    """Мидлварь для проверки авторизации пользователя"""
    user = data["event_from_user"]
    
    if user.id not in AUTHORIZED_USERS:
        logger.warning(f"Неавторизованный доступ от пользователя {user.id} ({user.full_name})")
        return
    
    return handler(event, data)

@router.message(Command("auth"))
async def cmd_auth(message: types.Message):
    """Проверка авторизации пользователя"""
    user_id = message.from_user.id
    
    if user_id in AUTHORIZED_USERS:
        await message.answer(
            "✅ У вас есть доступ к управлению ботом HIDS."
        )
    else:
        await message.answer(
            "⛔ У вас нет доступа к управлению ботом HIDS.\n"
            "Обратитесь к администратору системы."
        )
    
    logger.info(f"Проверка авторизации пользователем {user_id} ({message.from_user.full_name})") 