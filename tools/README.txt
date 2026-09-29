ОСНОВНЫЕ СКРИПТЫ

read_picoboot.py          Только читает flash/SRAM. Нет erase/write/exec.
decode_disk_region.py     Раскодирует 1 МиБ области диска.
extract_disk.py           Достаёт и раскодирует диск из полного дампа.
inspect_fat_root.py       Читает только структуру FAT и метаданные корня.
analyze_firmware.py       Находит PIN, адреса, GPIO и константы.
prove_transform.py        Проверяет обратимость XOR и изменение метки тома.
picoboot_ram_exec_probe.py   Пишет короткий тест только в SRAM, выполняет и возвращает RAM.
make_patch_artifacts.py   Делает полные BIN и секторные UF2-патчи.
check_uf2.py              Разбирает и проверяет UF2.
build_documents.py        Собирает DOCX и PDF из CyberSafe_report.md.
make_diagrams.py          Перерисовывает две схемы отчёта.
build_llm_handoff.py      Собирает ZIP-free пакет контекста для другой LLM.
build_proof_matrix.py     Собирает индекс P01..P14 с SHA-256 артефактов.
build_method_proof_matrix.py  Проверяет M01..M42 и пишет пруф/ограничение каждого.
verify_patch_roundtrip.py Проверяет точные изменённые байты и обратимость restore UF2.
validate_package.py       Запускает итоговые проверки всего комплекта.

ЭКСПЕРИМЕНТАЛЬНОЕ / НЕ ИСПОЛЬЗОВАТЬ ДЛЯ ДЕМО

picoboot_ram_sector_copy.py и copy_sector_payload.* — незаконченный XIP-тест.
restore_picoboot.py — отладочный скрипт записи flash, успешного прогона нет.
reset_usb_device.py и reset_bootsel_payload.* — восстановление USB/BOOTSEL при отладке.

Для безопасной демонстрации запускать ../reproduce_readonly.sh.
ZIP ни один основной скрипт не открывает и не извлекает.
