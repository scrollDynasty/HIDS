#!/bin/bash

# Скрипт для установки зависимостей HIDS

echo "Установка зависимостей для HIDS..."

# Определение дистрибутива
if [ -f /etc/debian_version ]; then
    # Debian/Ubuntu
    echo "Обнаружен Debian/Ubuntu"
    
    # Установка необходимых пакетов
    sudo apt-get update
    sudo apt-get install -y \
        build-essential \
        cmake \
        libssl-dev \
        libboost-system-dev \
        libboost-filesystem-dev \
        libboost-regex-dev \
        g++ \
        pkg-config
        
elif [ -f /etc/redhat-release ]; then
    # Red Hat/CentOS/Fedora
    echo "Обнаружен Red Hat/CentOS/Fedora"
    
    # Установка необходимых пакетов
    sudo yum install -y \
        gcc-c++ \
        cmake \
        openssl-devel \
        boost-devel \
        make \
        pkg-config
        
else
    echo "Неподдерживаемый дистрибутив Linux"
    echo "Пожалуйста, установите вручную: cmake, libssl-dev, libboost-dev"
    exit 1
fi

echo "Зависимости установлены успешно!"
echo "Теперь вы можете собрать HIDS с помощью:"
echo "mkdir -p build && cd build && cmake .. && make" 