# RouteGuard Auto Suite (CLI + GUI)

Полностью рабочая Python-реализация для Arch Linux и других Linux-систем.
Принимает **WireGuard `.conf`**, автоматически извлекает `Endpoint` и имя интерфейса, генерирует защитные правила `nftables`, запускает мониторинг маршрутов и умеет корректно **останавливаться с удалением `nft`**.

## Что делает программа

### В режиме `monitor`
- парсит WireGuard-конфиг (`Endpoint`, имя интерфейса из имени файла)
- резолвит endpoint (если это домен)
- мониторит маршруты (`ip -j route`) каждые N секунд
- ищет подозрительные split-default маршруты (`0.0.0.0/1`, `128.0.0.0/1`, `::/1`, `8000::/1`) не через VPN-интерфейс
- пишет предупреждения в лог

### В режиме `protect`
Делает всё из `monitor` +
- создаёт `table inet routeguard`
- разрешает:
  - `lo`
  - трафик через VPN-интерфейс
  - доступ к WireGuard endpoint (IP/порт из WG-конфига)
  - (опционально) DHCP и LAN
- блокирует остальной исходящий трафик вне VPN (kill-switch)
- при остановке удаляет `table inet routeguard`

## Зависимости

### Arch Linux
```bash
sudo pacman -S --needed python tk nftables iproute2 wireguard-tools
```

### Debian/Ubuntu
```bash
sudo apt update && sudo apt install -y python3 python3-tk nftables iproute2 wireguard-tools
```

## CLI версия

### Предпросмотр сгенерированного конфига
```bash
python3 routeguard_cli.py print-config --wg-config /etc/wireguard/smth.conf
```

### Безопасно (без блокировок)
```bash
sudo python3 routeguard_cli.py run --wg-config /etc/wireguard/smth.conf --mode monitor
```

### Полная защита + автоподъём VPN
```bash
sudo python3 routeguard_cli.py run --wg-config /etc/wireguard/smth.conf --mode protect --up-vpn
```

### Остановить и удалить `nft`
- В текущем окне: `Ctrl+C` (правила удалятся автоматически)
- Из другого терминала:
```bash
sudo python3 routeguard_cli.py stop
```
- Только снять блокировку:
```bash
sudo python3 routeguard_cli.py cleanup
```

## GUI версия (обновлённый минималистичный интерфейс)

Поддерживает **RU/EN** переключение языка, выбор WireGuard-конфига, предпросмотр сгенерированного JSON, запуск/остановку, статус и очистку `nft`.

```bash
sudo python3 routeguard_gui.py
```

Если появляется ошибка display authorization при запуске под `sudo`, запусти GUI так:
```bash
xhost +SI:localuser:root
sudo env DISPLAY=$DISPLAY XAUTHORITY=${XAUTHORITY:-$HOME/.Xauthority} python3 routeguard_gui.py
```

В GUI:
1. Выбери `.conf`
2. (Опционально) переключи язык RU/EN
3. Нажми **Preview config / Показать конфиг**
4. Сначала запусти `monitor`
5. Затем `protect`
6. Останови кнопкой **Stop** (очистка `nft` выполнится автоматически)

## Удаление правил в крайнем случае
```bash
sudo nft delete table inet routeguard 2>/dev/null || true
```

## Примеры

- `routeguard-cli` и `routeguard-gui` — удобные shell-обёртки для запуска через `./routeguard-cli ...` и `./routeguard-gui`
- `scripts/check_archive.sh` — быстрая проверка синтаксиса

