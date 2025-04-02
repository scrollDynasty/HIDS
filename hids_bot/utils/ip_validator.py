#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Модуль для валидации IP-адресов.
"""

import re
import socket
import ipaddress

def is_valid_ip(ip: str) -> bool:
    """
    Проверяет, является ли строка действительным IPv4-адресом.
    
    Args:
        ip: Строка для проверки
        
    Returns:
        True если строка является валидным IPv4-адресом, иначе False
    """
    if not ip:
        return False
    
    # Проверка с использованием регулярного выражения для быстрого исключения невалидных форматов
    ip_pattern = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")
    if not ip_pattern.match(ip):
        return False
    
    # Более строгая проверка с использованием библиотеки ipaddress
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def get_hostname(ip: str) -> str:
    """
    Пытается получить имя хоста по IP-адресу.
    
    Args:
        ip: IP-адрес для поиска
        
    Returns:
        Имя хоста или пустую строку в случае ошибки
    """
    if not is_valid_ip(ip):
        return ""
    
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror):
        return ""
    
def get_geolocation(ip: str) -> dict:
    """
    Получает геолокацию IP-адреса (для этого требуется внешняя библиотека или API).
    
    Args:
        ip: IP-адрес для поиска
        
    Returns:
        Словарь с информацией о геолокации или пустой словарь в случае ошибки
    """
    # Заглушка - в реальном проекте здесь должен быть код для запроса геолокации
    # Например, с использованием библиотеки geoip2 или публичных API
    return {"country": "Unknown", "city": "Unknown"}

class IPValidator:
    """
    Класс для валидации и работы с IP-адресами
    """
    
    @staticmethod
    def is_valid_ip(ip: str) -> bool:
        """
        Проверяет, является ли строка действительным IPv4-адресом.
        
        Args:
            ip: Строка для проверки
            
        Returns:
            True если строка является валидным IPv4-адресом, иначе False
        """
        return is_valid_ip(ip)
    
    @staticmethod
    def get_hostname(ip: str) -> str:
        """
        Пытается получить имя хоста по IP-адресу.
        
        Args:
            ip: IP-адрес для поиска
            
        Returns:
            Имя хоста или пустую строку в случае ошибки
        """
        return get_hostname(ip)
    
    @staticmethod
    def get_geolocation(ip: str) -> dict:
        """
        Получает геолокацию IP-адреса.
        
        Args:
            ip: IP-адрес для поиска
            
        Returns:
            Словарь с информацией о геолокации
        """
        return get_geolocation(ip) 