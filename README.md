# CyberSafe — ЛЦТ 2026

Закрытый комплект для жюри кейса Positive Technologies. Главное описание:
[отчёт PDF](CyberSafe_LCT2026_jury_final.pdf). Исходный текст —
[Markdown](CyberSafe_report.md). Условия задачи — в
[оригинальном PDF](Positive%20Technologies%20-%20task.pdf).

## Что доказано на выданной плате

| Вектор | Результат | Прямой пруф |
|---|---|---|
| ROM BOOTSEL / PICOBOOT | Без PIN считана вся внешняя Flash, 2 МиБ; повторные чтения совпали | [лог](evidence/reproduction-final/session.log), [метаданные дампа](evidence/reproduction-final/flash.bin.json), [ручное BOOT + RESET](evidence/manual-button-20260927/session.log) |
| Открытый PIN в прошивке | Байты 08 01 07 00 по 0x10005500 дали PIN 8170; он открыл штатный USB-накопитель | [дизассемблирование](evidence/password-routine-disassembly.txt), [PIN](evidence/reproduction-final/pin.bin.json), [USB после ввода](evidence/normal-unlock-proof.txt) |
| Фиксированное XOR-преобразование диска | Из считанного второго мегабайта получен корректный FAT12 объёмом 1 МиБ; ZIP не открывался | [декодирование](evidence/reproduction-final/disk.img.json), [параметры FAT12](evidence/reproduction-final/fat-root.json), [перекрёстная проверка](evidence/disk-from-region.img.json), [обратимость и изменение](evidence/transform/transform-proof.json) |
| Неподписанное обновление | На плате временно заменён PIN 8170 на 0000; 0000 открыл диск; исходный сектор восстановлен | [живой опыт](evidence/live-pin-0000-20260927/result.json), [лог записи](evidence/live-pin-0000-20260927/03-patch-write.txt), [лог восстановления](evidence/live-pin-0000-20260927/08-restore-write.txt) |

Дополнительно на живой плате доказано выполнение своего кода в SRAM через
PICOBOOT: [маркер и возврат SRAM](evidence/ram-exec-proof.json).
Этот примитив сам по себе не снимал диск. После десяти неверных попыток PIN
плата приняла 8170: [частичный опыт](evidence/live-no-lockout-20260927/result.json).
Полный перебор 0000–9999 не проводился.

**Задержка при проверке PIN:** в машинном коде найдены ранний переход при ошибке
и задержка 50 мс после совпавшей цифры. Это видно в
[дизассемблировании](evidence/password-routine-disassembly.txt).
Физически получить PIN по времени **не удалось**: на съёмке 240 FPS разница
не была различима. [Журнал отрицательного опыта](evidence/timing-camera-20260927/README.txt)
и [результат](evidence/timing-camera-20260927/result.json).
Исходное видео в комплект не передавалось. Электрическое измерение не выполнялось.
Этот способ не заявлен как рабочий.

## Где искать все доказательства

- [Индекс подтверждённых этапов](evidence/PROOF_INDEX.md) — статусы и ограничения.
- [Матрица 42 методов](evidence/METHOD_PROOF_MATRIX.md) — что проверено на плате, что только на дампе, что осталось планом и что дало отрицательный результат.
- [SHA-256 комплекта](evidence/SHA256SUMS.txt) — контроль файлов этого репозитория.
- [Полный дизассемблированный фрагмент](llm-handoff/firmware-full-disassembly.txt) и [команда получения](analysis/README.md).
- [Финальный контроль платы](evidence/final-audit-20260927/result.json) — плата работала после опытов.
- [Исходный полный дамп](evidence/reproduction-final/flash.bin), [закодированная область диска](evidence/reproduction-final/disk-region.bin), [декодированный FAT12](evidence/reproduction-final/disk.img) — бинарные артефакты для независимой проверки.

Разные программы для одного чтения и разные точечные патчи одной проверки
не считаются отдельными корневыми уязвимостями. Теоретические варианты в отчёте
имеют статус C, отрицательные опыты — N. Живых видео в этом комплекте пока нет;
подтверждение опирается на логи, дампы, хеши и результат USB на самой плате.

## Повторение чтения

На macOS перевести плату в BOOTSEL: держать BOOT, коротко нажать RESET, отпустить
BOOT. Должен появиться том RPI-RP2. Если macOS заняла интерфейс, выполнить
`diskutil unmount /Volumes/RPI-RP2`. Затем из корня репозитория:

```bash
./reproduce_readonly.sh ./demo-run
```

Скрипт читает Flash через PICOBOOT, повторяет чтение для проверки, извлекает
четыре байта PIN и область диска, восстанавливает FAT12, проверяет файловую
систему и считает хеши. ZIP-файл из виртуального диска не открывается и не
распаковывается. Для чтения используется локальная библиотека libusb.
