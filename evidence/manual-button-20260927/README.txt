РУЧНОЙ ПРОГОН BOOT + RESET, 27.09.2026

Что сделал человек на подключённой плате:
  1. Зажал BOOT.
  2. Не отпуская BOOT, коротко нажал RESET.
  3. Примерно через секунду отпустил BOOT.

Что зафиксировал ноутбук:
  14:42:00 — обычная прошивка PositiveLabs, VID:PID cafe:4000, том NO NAME.
  14:42:02 — ROM-загрузчик Raspberry Pi, VID:PID 2e8a:0003.
  INFO_UF2.TXT — UF2 Bootloader v3.0, Model Raspberry Pi RP2.

После отмонтирования служебного тома выполнен reproduce_readonly.sh.
Команд записи, стирания и исполнения кода в этом прогоне нет.

Результат:
  flash.bin:       2097152 байт
  flash SHA-256:   183ec770b9581e5add2a85dc7d0fa82377bb5d92f7e525281c09250906acc4ca
  pin.bin:         08 01 07 00, то есть 8170
  disk-region.bin: 1048576 байт
  disk SHA-256:    a8e537b29d87c960eac967df56e15e0474e850f6ed34fcdf92e09022b382f87f
  FAT:             FAT12, сигнатура 55aa
  повторное чтение flash, PIN и disk-region совпало с первым чтением.

Сравнение с ранним дампом:
  первый 1 МиБ с прошивкой совпал полностью;
  PIN совпал;
  522 изменённых байта находятся в четырёх секторах области FAT-диска.

Содержимое ZIP не открывалось, не копировалось и не распаковывалось.
fat-root.json содержит file_contents_read=false.

Основные файлы:
  01-before-boot.txt       состояние до кнопок
  02-button-transition.txt журнал переключения
  03-after-bootsel.txt     состояние после кнопок
  session.log              полный вывод read-only прогона
  *.json                   адреса, размеры, хеши и разбор
  compare-with-initial.json сравнение с первым дампом
