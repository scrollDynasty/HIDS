#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Модуль для работы с базой данных HIDS Telegram Bot.
"""

import sqlite3
import logging
import datetime
from typing import List, Tuple, Optional

logger = logging.getLogger(__name__)

class DatabaseManager:
    """Класс для работы с базой данных SQLite."""

    def __init__(self, db_path: str):
        """
        Инициализирует соединение с базой данных и создает таблицы при необходимости.
        
        Args:
            db_path: Путь к файлу базы данных SQLite
        """
        self.db_path = db_path
        self._create_tables()
    
    def _get_connection(self) -> sqlite3.Connection:
        """
        Получает соединение с базой данных.
        
        Returns:
            Соединение с базой данных
        """
        return sqlite3.connect(self.db_path)
    
    def _create_tables(self) -> None:
        """Создает необходимые таблицы в базе данных, если они не существуют."""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # Таблица инцидентов
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            reason TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            is_blocked INTEGER DEFAULT 0
        )
        ''')
        
        # Таблица заблокированных IP
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS blocked_ips (
            ip TEXT PRIMARY KEY,
            reason TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Таблица белого списка IP
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS whitelist (
            ip TEXT PRIMARY KEY,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        conn.commit()
        conn.close()
    
    def add_incident(self, ip: str, reason: str) -> None:
        """
        Добавляет новый инцидент в базу данных.
        
        Args:
            ip: IP-адрес источника инцидента
            reason: Причина/описание инцидента
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute(
                "INSERT INTO incidents (ip, reason) VALUES (?, ?)",
                (ip, reason)
            )
            conn.commit()
            logger.info(f"Добавлен инцидент: IP={ip}, причина={reason}")
        except sqlite3.Error as e:
            logger.error(f"Ошибка при добавлении инцидента: {e}")
        finally:
            conn.close()
    
    def add_to_blocked(self, ip: str, reason: str) -> None:
        """
        Добавляет IP в список заблокированных.
        
        Args:
            ip: IP-адрес для блокировки
            reason: Причина блокировки
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        
        try:
            # Добавляем IP в таблицу заблокированных
            cursor.execute(
                "INSERT OR REPLACE INTO blocked_ips (ip, reason) VALUES (?, ?)",
                (ip, reason)
            )
            
            # Обновляем статус инцидентов для этого IP
            cursor.execute(
                "UPDATE incidents SET is_blocked = 1 WHERE ip = ?",
                (ip,)
            )
            
            conn.commit()
            logger.info(f"IP {ip} заблокирован: {reason}")
        except sqlite3.Error as e:
            logger.error(f"Ошибка при блокировке IP: {e}")
        finally:
            conn.close()
    
    def remove_from_blocked(self, ip: str) -> None:
        """
        Удаляет IP из списка заблокированных.
        
        Args:
            ip: IP-адрес для разблокировки
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute(
                "DELETE FROM blocked_ips WHERE ip = ?",
                (ip,)
            )
            conn.commit()
            logger.info(f"IP {ip} разблокирован")
        except sqlite3.Error as e:
            logger.error(f"Ошибка при разблокировке IP: {e}")
        finally:
            conn.close()
    
    def add_to_whitelist(self, ip: str) -> None:
        """
        Добавляет IP в белый список.
        
        Args:
            ip: IP-адрес для добавления в белый список
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute(
                "INSERT OR REPLACE INTO whitelist (ip) VALUES (?)",
                (ip,)
            )
            conn.commit()
            logger.info(f"IP {ip} добавлен в белый список")
        except sqlite3.Error as e:
            logger.error(f"Ошибка при добавлении IP в белый список: {e}")
        finally:
            conn.close()
    
    def remove_from_whitelist(self, ip: str) -> None:
        """
        Удаляет IP из белого списка.
        
        Args:
            ip: IP-адрес для удаления из белого списка
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute(
                "DELETE FROM whitelist WHERE ip = ?",
                (ip,)
            )
            conn.commit()
            logger.info(f"IP {ip} удален из белого списка")
        except sqlite3.Error as e:
            logger.error(f"Ошибка при удалении IP из белого списка: {e}")
        finally:
            conn.close()
    
    def is_in_whitelist(self, ip: str) -> bool:
        """
        Проверяет, находится ли IP в белом списке.
        
        Args:
            ip: IP-адрес для проверки
            
        Returns:
            True если IP в белом списке, иначе False
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute(
                "SELECT 1 FROM whitelist WHERE ip = ? LIMIT 1",
                (ip,)
            )
            result = cursor.fetchone() is not None
            return result
        except sqlite3.Error as e:
            logger.error(f"Ошибка при проверке белого списка: {e}")
            return False
        finally:
            conn.close()
    
    def get_blocked_ips(self) -> List[Tuple[str, str, str]]:
        """
        Возвращает список всех заблокированных IP.
        
        Returns:
            Список кортежей (ip, reason, timestamp)
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute(
                "SELECT ip, reason, timestamp FROM blocked_ips ORDER BY timestamp DESC"
            )
            return cursor.fetchall()
        except sqlite3.Error as e:
            logger.error(f"Ошибка при получении списка заблокированных IP: {e}")
            return []
        finally:
            conn.close()
    
    def get_whitelist(self) -> List[Tuple[str, str]]:
        """
        Возвращает список всех IP в белом списке.
        
        Returns:
            Список кортежей (ip, timestamp)
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute(
                "SELECT ip, timestamp FROM whitelist ORDER BY timestamp DESC"
            )
            return cursor.fetchall()
        except sqlite3.Error as e:
            logger.error(f"Ошибка при получении белого списка: {e}")
            return []
        finally:
            conn.close()
    
    def get_recent_incidents(self, limit: int = 10) -> List[Tuple[str, str, str, int]]:
        """
        Возвращает список последних инцидентов.
        
        Args:
            limit: Максимальное количество инцидентов
            
        Returns:
            Список кортежей (ip, reason, timestamp, is_blocked)
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute(
                "SELECT ip, reason, timestamp, is_blocked FROM incidents "
                "ORDER BY timestamp DESC LIMIT ?",
                (limit,)
            )
            return cursor.fetchall()
        except sqlite3.Error as e:
            logger.error(f"Ошибка при получении списка инцидентов: {e}")
            return []
        finally:
            conn.close()
    
    def get_incidents_by_ip(self, ip: str) -> List[dict]:
        """
        Возвращает список инцидентов для указанного IP-адреса.
        
        Args:
            ip: IP-адрес для поиска
            
        Returns:
            Список словарей с информацией об инцидентах для данного IP
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        
        try:
            cursor.execute(
                "SELECT id, ip, reason, timestamp, is_blocked FROM incidents "
                "WHERE ip = ? ORDER BY timestamp DESC",
                (ip,)
            )
            
            incidents = []
            for row in cursor.fetchall():
                incidents.append({
                    "id": row[0],
                    "ip": row[1],
                    "reason": row[2],
                    "timestamp": datetime.datetime.strptime(row[3], "%Y-%m-%d %H:%M:%S"),
                    "is_blocked": bool(row[4])
                })
            
            return incidents
        except sqlite3.Error as e:
            logger.error(f"Ошибка при получении инцидентов для IP {ip}: {e}")
            return []
        finally:
            conn.close() 