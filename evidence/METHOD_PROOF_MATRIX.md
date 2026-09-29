# Пруфы и ограничения для M01–M42

Эта таблица нужна для финальной проверки отчёта. A означает живой результат, B — результат на дампе или проверенный артефакт, C — план/неполная проверка, N — отрицательный опыт. Разные M внутри одного V не заявляются как разные корневые уязвимости.

| Метод | Вектор | Статус | Вид пруфа | Файлы | Что не доказано |
|---|---|---|---|---|---|
| M01 | V-01 | A | live_board | `evidence/reproduction-final/session.log`<br>`evidence/reproduction-final/flash.bin.json`<br>`evidence/manual-button-20260927/session.log`<br>`evidence/manual-button-20260927/compare-with-initial.json` | Живой read-only дамп сделан дважды; пользовательский ZIP не открывался. |
| M02 | V-01 | A | live_board | `evidence/reproduction-final/disk-region.bin.json`<br>`evidence/manual-button-20260927/disk-region.bin.json` | Живое чтение диапазона сделано дважды; содержимое файлов не извлекалось. |
| M03 | V-01 | A | live_board | `evidence/reproduction-final/pin.bin.json`<br>`evidence/manual-button-20260927/pin.bin.json` | Четыре байта считаны без PIN и повторены в отдельной сессии. |
| M04 | V-01 | C | plan_only | — | picotool на этом ноутбуке не установлен и команда не запускалась; это альтернативный клиент того же ROM-примитива. |
| M05 | V-02 | B | offline_device_specific | `evidence/reproduction-final/firmware-analysis.json`<br>`evidence/password-routine-disassembly.txt` | Статический анализ дампа; работоспособность найденного PIN отдельно подтверждена M06. |
| M06 | V-02 | A | live_board | `evidence/normal-unlock-proof.txt`<br>`evidence/final-device-state.txt` | PIN введён вручную; лог хоста видит USB и mount, но не электрические события энкодера. |
| M07 | V-03 | B | offline_device_specific | `evidence/reproduction-final/disk.img.json`<br>`evidence/reproduction-final/fat-root.json`<br>`evidence/disk-from-region.img.json`<br>`evidence/disk-repeat.img.json`<br>`evidence/fat-root-metadata.json` | Два независимых пути дали одинаковый FAT12; содержимое ZIP не читалось. |
| M08 | V-03 | B | offline_device_specific | `evidence/transform/transform-proof.json` | Known plaintext восстанавливает поток только на известных позициях; полный диск декодирован по алгоритму из прошивки. |
| M09 | V-03 | B | offline_device_specific | `evidence/transform/transform-proof.json`<br>`evidence/transform/sector0-label-modified-cipher.bin` | Направленная замена доказана на копии сектора; flash платы не менялась. |
| M10 | V-03 | B | offline_device_specific | `evidence/transform/transform-proof.json` | Обратное кодирование совпало на этой плате; перенос на второй экземпляр не проверялся. |
| M11 | V-04 | N | negative_result | `evidence/password-routine-disassembly.txt`<br>`evidence/timing-camera-20260927/README.txt`<br>`evidence/timing-camera-20260927/result.json` | Камера 240 FPS не дала различимого сигнала; PIN этим способом не получен. |
| M12 | V-04 | C | partial_live | `evidence/live-no-lockout-20260927/result.json`<br>`evidence/live-no-lockout-20260927/session.txt`<br>`evidence/live-no-lockout-20260927/ioreg-after-success.txt` | Проверены 10 заявленных ошибок и успешный вход; нажатия не считались электрически, диапазон 0000..9999 не пройден. |
| M13 | V-04 | C | plan_only | `evidence/firmware-analysis.json` | GPIO найдены статически, второй МК к плате не подключался. |
| M14 | V-04 | C | plan_only | `evidence/password-routine-disassembly.txt`<br>`evidence/timing-camera-20260927/result.json` | Ранний выход и задержка есть в коде; электрический датчик и автомат ввода не собирались, камера дала отрицательный результат. |
| M15 | V-05 | A | live_board | `evidence/ram-exec-proof.json` | Выполнен короткий маркерный payload и восстановлена SRAM; данные диска этим payload не снимались. |
| M16 | V-05 | C | plan_only | `evidence/ram-exec-proof.json`<br>`evidence/ram-sector-debug.bin.json` | Примитив M15 работает, но RAM-only копировщик сектора не закончен; отладочный опыт дал FF до снятия питания. |
| M17 | V-06 | B | offline_device_specific | `evidence/patches/bypass-compare.uf2`<br>`evidence/patches/patch-manifest.json`<br>`evidence/patches/roundtrip-proof.json`<br>`evidence/disassembly-proof.txt`<br>`evidence/uf2-validation.txt` | Байты и UF2 проверены офлайн; на плату этот патч не записывался. |
| M18 | V-06 | B | offline_device_specific | `evidence/patches/skip-password-call.uf2`<br>`evidence/patches/patch-manifest.json`<br>`evidence/patches/roundtrip-proof.json`<br>`evidence/disassembly-proof.txt`<br>`evidence/uf2-validation.txt` | Байты и UF2 проверены офлайн; на плату этот патч не записывался. |
| M19 | V-06 | B | offline_device_specific | `evidence/patches/return-from-password.uf2`<br>`evidence/patches/patch-manifest.json`<br>`evidence/patches/roundtrip-proof.json`<br>`evidence/disassembly-proof.txt`<br>`evidence/uf2-validation.txt` | Байты и UF2 проверены офлайн; на плату этот патч не записывался. |
| M20 | V-06 | A | live_board | `evidence/patches/pin-0000.uf2`<br>`evidence/patches/restore-sector-005000.uf2`<br>`evidence/patches/roundtrip-proof.json`<br>`evidence/live-pin-0000-20260927/result.json`<br>`evidence/live-pin-0000-20260927/03-patch-write.txt`<br>`evidence/live-pin-0000-20260927/05-pin-0000-success.txt`<br>`evidence/live-pin-0000-20260927/08-restore-write.txt`<br>`evidence/live-pin-0000-20260927/10-operator-confirmation.txt`<br>`evidence/final-device-state.txt` | PIN 0000 проверен на плате и сектор восстановлен; прямое чтение четырёх байтов после restore не выполнено, зато 8170 проверен после полного переподключения. |
| M21 | V-06 | C | plan_only | — | Собственная MSC-прошивка не написана и не запускалась. |
| M22 | V-06 | C | plan_only | `evidence/restore-full-original.uf2`<br>`evidence/restore-full-original.json`<br>`evidence/patches/patch-manifest.json`<br>`evidence/uf2-validation.txt` | Полный модифицированный образ не записывался; готовы точечные UF2 и полный UF2 возврата. |
| M23 | V-07 | C | plan_only | `evidence/firmware-analysis.json` | Электрический автомат ввода не подключался; есть только статически найденные GPIO. |
| M24 | V-07 | C | plan_only | `evidence/firmware-analysis.json`<br>`images/board-from-task.png` | Съёмка фактического ввода владельца не выполнялась; камера 240 FPS проверяла другой timing-сценарий M11 и там не сработала. |
| M25 | V-07 | C | plan_only | `evidence/firmware-analysis.json`<br>`images/board-from-task.png` | Логический анализатор к линиям энкодера не подключался. |
| M26 | V-08 | C | plan_only | `images/board-from-task.png` | SWD-точки и отсутствие защиты живым probe не проверялись. |
| M27 | V-08 | C | plan_only | `evidence/password-routine-disassembly.txt` | Адрес ветки известен, но остановка CPU и перенос PC через SWD не выполнялись. |
| M28 | V-08 | C | plan_only | `evidence/firmware-analysis.json`<br>`evidence/sram-read.bin.json` | SRAM через SWD без reset не читалась; чтение после BOOTSEL дало отрицательный M40. |
| M29 | V-09 | C | plan_only | `images/board-from-task.png`<br>`evidence/reproduction-final/flash.bin.json` | Прищепка и внешний программатор не подключались; пригодность контактов in-circuit не проверена. |
| M30 | V-09 | C | plan_only | `images/board-from-task.png`<br>`evidence/reproduction-final/flash.bin.json` | Микросхема не выпаивалась; риск высокий, запасной платы нет. |
| M31 | V-09 | C | plan_only | `evidence/firmware-analysis.json`<br>`evidence/reproduction-final/disk-region.bin.json` | QSPI-трасса анализатором не снималась. |
| M32 | V-09 | C | plan_only | `evidence/patches/patch-manifest.json`<br>`evidence/patches/roundtrip-proof.json` | Клон flash не устанавливался; готовые патчи проверены только как файлы, кроме M20. |
| M33 | V-10 | A | live_board | `evidence/normal-unlock-proof.txt`<br>`evidence/final-device-state.txt`<br>`evidence/final-audit-20260927/result.json` | Штатный MSC подтверждён после PIN 8170; содержимое ZIP не открывалось. |
| M34 | V-10 | C | plan_only | `evidence/normal-unlock-proof.txt` | USB-трафик анализатором не записывался; есть только факт обычного MSC. |
| M35 | V-11 | C | plan_only | `evidence/password-routine-disassembly.txt` | Voltage glitch не выполнялся; окно известно только по машинному коду. |
| M36 | V-11 | C | plan_only | `evidence/password-routine-disassembly.txt` | Clock glitch не выполнялся; внешний тактовый тракт на стенде не проверен. |
| M37 | V-11 | C | plan_only | `evidence/password-routine-disassembly.txt` | EMFI-оборудование не использовалось. |
| M38 | V-11 | C | plan_only | `evidence/password-routine-disassembly.txt`<br>`evidence/firmware-analysis.json` | Инъекция на QSPI не выполнялась; есть карта адресов и код проверки. |
| M39 | V-12 | C | plan_only | `evidence/fat-root-metadata.json`<br>`evidence/organizer-qa-notes-20260927.md` | Carving намеренно не запускался: ZIP организаторы назвали пасхалкой вне задания. |
| M40 | V-12 | N | negative_result | `evidence/sram-read.bin`<br>`evidence/sram-read.bin.json` | Вся SRAM после RESET/BOOTSEL считана, полезные сигнатуры не найдены. |
| M41 | V-11 | C | plan_only | `evidence/password-routine-disassembly.txt`<br>`evidence/timing-camera-20260927/result.json` | Ток и ЭМ не измерялись; камера не увидела разницу, наличие задержки подтверждено только кодом. |
| M42 | V-07 | C | plan_only | `evidence/firmware-analysis.json`<br>`images/board-from-task.png` | Видео или аудиозапись реального ввода владельца не делалась. |

Уникальных файлов в этой матрице: 48. Их размеры и SHA-256 лежат в `method-proof-matrix.json`.
