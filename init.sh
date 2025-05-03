#!/bin/bash

# ==============================================================================
# Ubuntu 24.04 LTS Server Initialization Script
# ==============================================================================
# Цель: Базовая настройка безопасности, обновление системы, установка Docker.
# Запускать от имени root или через sudo.
# ==============================================================================

# Выход при любой ошибке
set -e

# --- Конфигурация (можно изменить) ---
NEW_USER="" # Имя нового пользователя будет запрошено
DEFAULT_SSH_PORT="22" # Оставляем стандартный порт SSH по умолчанию

# --- Проверка запуска от root ---
if [ "$(id -u)" -ne 0 ]; then
  echo "Ошибка: Этот скрипт должен быть запущен от имени пользователя root или через sudo." >&2
  exit 1
fi

# --- Запрос имени нового пользователя ---
while [ -z "$NEW_USER" ]; do
  read -p "Введите имя для нового sudo пользователя (например, adminuser): " NEW_USER
  if [ -z "$NEW_USER" ]; then
    echo "Имя пользователя не может быть пустым."
  elif id "$NEW_USER" &>/dev/null; then
    echo "Пользователь '$NEW_USER' уже существует. Выберите другое имя."
    NEW_USER="" # Сбросить, чтобы запросить снова
  fi
done
echo "Будет создан пользователь: $NEW_USER"

# --- Обновление системы ---
echo ""
echo "========================================="
echo " Шаг 1: Обновление системы"
echo "========================================="
apt-get update
apt-get upgrade -y
apt-get autoremove -y
apt-get autoclean

# --- Установка базовых утилит ---
echo ""
echo "========================================="
echo " Шаг 2: Установка базовых утилит"
echo "========================================="
apt-get install -y curl wget git vim nano sudo unattended-upgrades apt-transport-https ca-certificates software-properties-common

# --- Настройка автоматических обновлений безопасности ---
echo ""
echo "========================================="
echo " Шаг 3: Настройка Unattended Upgrades"
echo "========================================="
# Обычно включено по умолчанию, но проверим и переконфигурируем
dpkg-reconfigure --priority=low unattended-upgrades
echo "Unattended Upgrades настроены (рекомендуется проверить /etc/apt/apt.conf.d/50unattended-upgrades)."

# --- Создание нового пользователя с sudo ---
echo ""
echo "========================================="
echo " Шаг 4: Создание нового пользователя"
echo "========================================="
adduser $NEW_USER # Эта команда интерактивно запросит пароль и информацию
usermod -aG sudo $NEW_USER
echo "Пользователь '$NEW_USER' создан и добавлен в группу sudo."
echo "Не забудьте настроить для него вход по SSH-ключу!"

# --- Настройка SSH (Базовая безопасность) ---
echo ""
echo "========================================="
echo " Шаг 5: Настройка SSH"
echo "========================================="
SSH_CONFIG_FILE="/etc/ssh/sshd_config"
# Создаем бэкап конфига
cp $SSH_CONFIG_FILE "${SSH_CONFIG_FILE}.bak_$(date +%F_%T)"
echo "Создан бэкап SSH конфига: ${SSH_CONFIG_FILE}.bak_*"

# Отключаем вход для root
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' $SSH_CONFIG_FILE
echo "Вход для root по SSH отключен."

# Включаем вход по ключам (обычно включен по умолчанию)
sed -i 's/^#\?PubkeyAuthentication.*/PubkeyAuthentication yes/' $SSH_CONFIG_FILE
echo "Вход по SSH ключам разрешен (убедитесь, что он не закомментирован)."

# !!! ВАЖНО: Не отключайте вход по паролю СРАЗУ !!!
# Сначала убедитесь, что вы можете войти под новым пользователем по ключу.
# Закомментируйте строку ниже, если хотите отключить пароли ПОЗЖЕ вручную.
# sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' $SSH_CONFIG_FILE
# echo "Вход по паролю будет отключен после перезапуска sshd (ЗАКОММЕНТИРОВАНО ПО УМОЛЧАНИЮ!)."
echo "ПРЕДУПРЕЖДЕНИЕ: Вход по паролю пока РАЗРЕШЕН. Отключите его вручную ('PasswordAuthentication no' в $SSH_CONFIG_FILE и перезапустите sshd) ПОСЛЕ настройки входа по ключу для пользователя $NEW_USER."

# Перезапускаем SSH сервис для применения изменений
systemctl restart sshd
echo "SSH сервис перезапущен."
echo "Не забудьте скопировать ваш публичный SSH ключ в ~/.ssh/authorized_keys для пользователя $NEW_USER!"

# --- Настройка Firewall (UFW) ---
echo ""
echo "========================================="
echo " Шаг 6: Настройка Firewall (UFW)"
echo "========================================="
apt-get install -y ufw
ufw default deny incoming    # Запретить все входящие по умолчанию
ufw default allow outgoing   # Разрешить все исходящие по умолчанию
ufw allow $DEFAULT_SSH_PORT/tcp # Разрешить SSH на стандартном порту (или измененном, если меняли)
ufw allow http               # Разрешить HTTP (80)
ufw allow https              # Разрешить HTTPS (443)
# Добавьте другие нужные порты, например:
# ufw allow 5432/tcp # Если PostgreSQL должен быть доступен извне (НЕ РЕКОМЕНДУЕТСЯ)

echo "Правила UFW добавлены для портов: $DEFAULT_SSH_PORT (SSH), 80 (HTTP), 443 (HTTPS)."
echo "ВАЖНО: Фаервол UFW НЕ активирован!"
echo "После проверки доступа по SSH для пользователя '$NEW_USER', активируйте фаервол вручную командой: sudo ufw enable"

# --- Установка Docker и Docker Compose ---
echo ""
echo "========================================="
echo " Шаг 7: Установка Docker и Docker Compose"
echo "========================================="
# Удаляем старые версии (если были)
apt-get remove docker docker-engine docker.io containerd runc -y || true # Игнорируем ошибки, если их нет

# Добавляем официальный GPG ключ Docker
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc

# Добавляем репозиторий Docker
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  tee /etc/apt/sources.list.d/docker.list > /dev/null
apt-get update

# Устанавливаем Docker Engine, CLI, Containerd и Docker Compose Plugin
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Добавляем нового пользователя в группу docker
usermod -aG docker $NEW_USER
echo "Пользователь '$NEW_USER' добавлен в группу 'docker'."
echo "ВАЖНО: Пользователю '$NEW_USER' нужно будет ПЕРЕЛОГИНИТЬСЯ (выйти и зайти снова), чтобы использовать Docker без sudo."

# Проверяем установку Docker
docker --version
docker compose version

# --- Установка Fail2ban (Опционально, но рекомендуется) ---
echo ""
echo "========================================="
echo " Шаг 8: Установка Fail2ban (Защита от брутфорса)"
echo "========================================="
apt-get install -y fail2ban
systemctl enable fail2ban
systemctl start fail2ban
echo "Fail2ban установлен и запущен."
echo "Рекомендуется настроить jail'ы в /etc/fail2ban/jail.local (скопировав из jail.conf)."

# --- Опционально: Создание Swap файла (если мало RAM) ---
# echo ""
# echo "========================================="
# echo " Шаг 9 (Опционально): Создание Swap файла"
# echo "========================================="
# SWAP_SIZE="2G" # Укажите нужный размер (например, 1G, 2G, 4G)
# SWAP_FILE="/swapfile"
# if [ -f "$SWAP_FILE" ]; then
#   echo "Swap файл $SWAP_FILE уже существует."
# else
#   fallocate -l $SWAP_SIZE $SWAP_FILE
#   chmod 600 $SWAP_FILE
#   mkswap $SWAP_FILE
#   swapon $SWAP_FILE
#   # Делаем swap постоянным
#   echo "$SWAP_FILE none swap sw 0 0" >> /etc/fstab
#   echo "Swap файл $SWAP_SIZE создан и активирован."
#   # Настройка swappiness (как часто использовать swap)
#   SWAPPINESS=10 # Низкое значение (1-100), чтобы использовать реже
#   sysctl vm.swappiness=$SWAPPINESS
#   echo "vm.swappiness = $SWAPPINESS" >> /etc/sysctl.conf
#   echo "Параметр vm.swappiness установлен в $SWAPPINESS."
# fi

# --- Завершение ---
echo ""
echo "========================================="
echo " Первоначальная настройка сервера ЗАВЕРШЕНА!"
echo "========================================="
echo ""
echo ">>> ВАЖНЫЕ СЛЕДУЮЩИЕ ШАГИ: <<<"
echo "1.  СКОПИРУЙТЕ ваш ПУБЛИЧНЫЙ SSH ключ в /home/$NEW_USER/.ssh/authorized_keys."
echo "    Пример команды (выполнить на вашем локальном компьютере):"
echo "    ssh-copy-id $NEW_USER@<IP_АДРЕС_СЕРВЕРА>"
echo "    ИЛИ вручную: cat ~/.ssh/id_rsa.pub | ssh $NEW_USER@<IP_АДРЕС_СЕРВЕРА> 'mkdir -p ~/.ssh && touch ~/.ssh/authorized_keys && chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys && cat >> ~/.ssh/authorized_keys'"
echo "2.  ПРОВЕРЬТЕ вход по SSH под пользователем '$NEW_USER' с использованием ключа."
echo "3.  (РЕКОМЕНДУЕТСЯ) ОТКЛЮЧИТЕ вход по паролю в SSH:"
echo "    Отредактируйте /etc/ssh/sshd_config: установите 'PasswordAuthentication no'"
echo "    Перезапустите SSH: sudo systemctl restart sshd"
echo "4.  АКТИВИРУЙТЕ фаервол UFW:"
echo "    sudo ufw enable  (введите 'y' для подтверждения)"
echo "5.  ПЕРЕЛОГИНИТЕСЬ под пользователем '$NEW_USER', чтобы он мог использовать Docker без sudo."
echo "6.  (Опционально) Настройте Fail2ban в /etc/fail2ban/jail.local."
echo "7.  Теперь вы можете клонировать ваш проект и запускать его с помощью 'docker compose up'."
echo ""

exit 0
