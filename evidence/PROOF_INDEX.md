# Индекс доказательств CyberSafe

Этот файл связывает каждое утверждение с конкретными артефактами. Статус C не выдаётся за выполненную атаку, статус N сохраняет отрицательный результат.

## Этапы

| Этап | Статус | Что доказано | Ограничение |
|---|---|---|---|
| P01 | A | Кнопки BOOT+RESET переводят выданную плату из PositiveLabs cafe:4000 в ROM RP2 Boot 2e8a:0003. | — |
| P02 | A | Вся внешняя flash размером 2 МиБ читается без ввода PIN; два чтения совпадают. | — |
| P03 | A | Четыре байта 08 01 07 00 читаются напрямую по 0x10005500 и дают PIN 8170. | — |
| P04 | A | Закодированная область хранилища размером 1 МиБ читается напрямую по 0x10100000. | — |
| P05 | B | Фиксированное XOR-преобразование восстанавливает корректный FAT12; прямое чтение области и извлечение из полного дампа дают одинаковый образ, а обратное кодирование совпадает с исходным шифротекстом. | Проверены файловая система и метаданные. Содержимое файла-пасхалки не читалось. |
| P06 | A | Найденный PIN 8170 штатно включает USB Mass Storage cafe:4000 и том NO NAME. | — |
| P07 | A | PICOBOOT PC_WRITE и PC_EXEC выполняют загруженный код в SRAM, маркер 0xc0dec0de прочитан обратно. | Доказан примитив выполнения кода; полный RAM-only дампер данных не закончен. |
| P08 | A | Точечная UF2-замена PIN 8170 на 0000 принята платой; 0000 включает cafe:4000 и NO NAME; затем исходный сектор записан обратно. | Возврат исходного PIN подтверждён оператором и последующим штатным USB; отдельного электрического счётчика нажатий не было. |
| P09 | C-partial-live | После серии из десяти неверных попыток по инструкции плата приняла 8170 и создала новый USB-сеанс. | Хост подтверждает новый USB session ID, но отдельные нажатия не считались электрически; все 10 000 PIN не перебирались. |
| P10 | N | В прошивке есть ранний выход и sleep_ms(50), но камера 240 FPS не дала пригодного timing-сигнала. | Исходное видео в пакет не передано; сохранено наблюдение оператора. Электрическое измерение не выполнялось. |
| P11 | B | Готовые патчи M17-M19 меняют только заявленные инструкции и собраны в валидные UF2. | M17-M19 на плату не записывались и отдельными корневыми векторами не считаются. |
| P12 | N | Чтение SRAM после RESET/BOOTSEL не нашло полезного plaintext. | RESET уничтожает нужный контекст; для чтения без RESET нужен SWD. |
| P13 | B | Для возврата подготовлен полный UF2 исходной flash и отдельные исходные секторы; UF2 структурно проверены. | Полный 2 МиБ UF2 не требовалось записывать; в M20 на плате проверена запись точечного восстановительного сектора. |
| P14 | A | После экспериментов плата осталась рабочей: после полного переподключения PIN 8170 запускал штатный USB, а финальный read-only снимок снова видит PositiveLabs cafe:4000. | В финальном снимке USB-сеанс уже существовал и том не был смонтирован; сам ввод 8170 после полного переподключения зафиксирован отдельным логом. |

## Файлы и SHA-256

- `disassembly-proof.txt` — 5687 байт, `03848069f8fe51be0c8b493bd866b2d835ab6e286396ee9ffe04da473c51f498`
- `disk-from-region.img` — 1048576 байт, `6df635a0ddfd0f1b5c8c243382cc23dd366c63393fd18a20baaf73d5372e2c4b`
- `disk-from-region.img.json` — 424 байт, `ad596d4dbdb4bef41920ae1afc0a56fd5b3c4de0880db53e96a973ca0f6363d8`
- `disk-region-direct.bin` — 1048576 байт, `5b07fe65994a80d2bf4cc67fd7d031ff49bfda003ae50f24a3eb41c35e57d053`
- `disk-region-direct.bin.json` — 374 байт, `875197267845babcd5ef883981cf1c12a6d8de9883f8ad9d6c6ec191eb43e2a1`
- `disk-repeat.img` — 1048576 байт, `6df635a0ddfd0f1b5c8c243382cc23dd366c63393fd18a20baaf73d5372e2c4b`
- `disk-repeat.img.json` — 435 байт, `be4afde575bbbad3f00b600d0984e4458971eb69f77e7fe0096ce1b4086f9718`
- `fat-root-metadata.json` — 722 байт, `40348798cc28787b9903ca6e0a606524a33d2c516acf455fd87cb95164843b53`
- `final-audit-20260927/00-timestamp.txt` — 21 байт, `777a124910871f93cea52b58252821fdfc401d926838f9e420e6d13bd856ea20`
- `final-audit-20260927/01-system-profiler.txt` — 539 байт, `cf51fba864282467f5c003ec6b1b8dd938787439d689353288b3cfb7e3fd2ef5`
- `final-audit-20260927/02-ioreg.txt` — 1580 байт, `3dfb948d79e96897ef653609ada5d293eedb8c256dbccd443a596bfced4787bc`
- `final-audit-20260927/03-mount.txt` — 1129 байт, `7df61ed7124c277e766b0e046e817cf862ff4323245e9d44439c7ff5b469029b`
- `final-audit-20260927/README.txt` — 912 байт, `6154ed675176f34c9a23f0231f8e1df315c7f4979ec2a3c09383f383581c1856`
- `final-audit-20260927/result.json` — 944 байт, `56d2b3a8fd0e5e6542bf800fa8b93b0211522998dfbe7f113d7a2970e1ccb379`
- `final-device-state.txt` — 1946 байт, `6fe870887b195b7a5607587d90b6ae53068657ca8be340f541b193a0022eac2b`
- `firmware-analysis.json` — 2471 байт, `7112747d8fde8817297cc750d172d6acf7e685fd3a25584a3079be61a5b79d74`
- `flash-read-repeat.bin` — 2097152 байт, `640626b93d7492a6efadba09759cf349d84a45b785cd31703ad37912d6cf9eb9`
- `flash-read-repeat.bin.json` — 373 байт, `14f799d91a93b2442e2d13de06fd91e7b581b9a47e3ff3b26ba0ee1f220e4c60`
- `live-no-lockout-20260927/ioreg-after-success.txt` — 1589 байт, `65cca735baea084565c68edbe18570162fa39ae02166367ba45db5df81ed3306`
- `live-no-lockout-20260927/result.json` — 792 байт, `269c83aebe61161c5d5afb6a49a815c74bf4e2a97d45823d0250466e79befadc`
- `live-no-lockout-20260927/session.txt` — 907 байт, `1436d3669a50d455f42355357f02bf9e5882b22231bd142ab9f90f1a4016fd0b`
- `live-pin-0000-20260927/03-patch-write.txt` — 236 байт, `4dd658da9dea7ccd3f9c5077e23653c754cade93679f46fed33e383db5512ecd`
- `live-pin-0000-20260927/04-unlock-0000-usb.txt` — 748 байт, `f90d7e77b098903857fdc76004191aedd43576a0cebba83f565a89869ba46fbe`
- `live-pin-0000-20260927/05-pin-0000-success.txt` — 769 байт, `e7a12cc160e66083063c8960ebf328ef24872a696653c178c4f84175b85f2fec`
- `live-pin-0000-20260927/07-restore-bootsel.txt` — 739 байт, `8545e170ee6a02bad37bcc9ed7646cbbd1ceac2ff84bff3a2e719515a35d2168`
- `live-pin-0000-20260927/08-restore-write.txt` — 270 байт, `607c4c13f59e3bec4c70544d1e001a95fdde6ad09d8e7ee22c2d00317ea5e00f`
- `live-pin-0000-20260927/10-operator-confirmation.txt` — 732 байт, `0015e8b001cd2e298c678f8b23b8af306571f26f5beaf3a8a637e79ad6840607`
- `live-pin-0000-20260927/result.json` — 784 байт, `b2d1d868139d6ed5e5f24d9ace75ce5a217872da171d76f531c3a12d1b2eb3eb`
- `manual-button-20260927/01-before-boot.txt` — 1977 байт, `73c5053717b25dd87907831608a3137f76783e30267879b81e0621426091ae8d`
- `manual-button-20260927/02-button-transition.txt` — 4699 байт, `9cf94d8100edcb3359a721a86efec03c092573c455863951cc1e3e023ac9d29a`
- `manual-button-20260927/03-after-bootsel.txt` — 1827 байт, `e8e49ac962bd871d00c5e0e5510582d3e087bf524740b08e8e40f4f46aa88933`
- `manual-button-20260927/compare-with-initial.json` — 663 байт, `c4c994603f6622bb0b26c0e77e41f794a78aac3d78f88a8701638b27523b0202`
- `manual-button-20260927/disk-region.bin.json` — 399 байт, `03063227dc80a07486bf2ef21242328cb6d412029df37571a71ec08630180034`
- `manual-button-20260927/flash.bin.json` — 393 байт, `b86f62f5248fdbece134b372ebb8a2d8f6650ec19785954c8b02e17bc9b67f61`
- `manual-button-20260927/pin.bin.json` — 385 байт, `18891dc39f5b9ba4e93e8c206f177952c15b5970c0ae5be4ed8a1b6f7c34c4c7`
- `normal-unlock-proof.txt` — 1946 байт, `53d1b913431b40bc71ccb06e4fc9be8f6332be15f3b40f79ef0665f1eb3e1f8e`
- `password-routine-disassembly.txt` — 4104 байт, `437e1f34a92ac26a89c5cc68ea65fa1e4f9fc0833f05c6a49540d5838965ffc6`
- `patches/bypass-compare.uf2` — 8192 байт, `a13254bfb00e6c1d0efeb3eb7c2093d84464b923a4cf614b145914eaee75da14`
- `patches/patch-manifest.json` — 3614 байт, `bd0e6707782fec98dd2102a53dc4de4c1dd94ee135f980da8d877845100de8db`
- `patches/pin-0000.uf2` — 8192 байт, `1e99c65d33c733d51f566f1f5947c1a6526b19abe6d7b92e965f6cf2e691370a`
- `patches/restore-sector-000000.uf2` — 8192 байт, `f75ef6dcf905ad81b504b83663eb8188ed28b6519d355eefa464e34f5bc1e2ea`
- `patches/restore-sector-005000.uf2` — 8192 байт, `590c5b29a9517af9ff2a0fb00c459e86049a9b6701fd911ab0ab2450d3909d75`
- `patches/return-from-password.uf2` — 8192 байт, `f42cd8c8faa26c3d7c343348d9e0cd7126fd2f2b46de1b846770bd1e241296ad`
- `patches/roundtrip-proof.json` — 2921 байт, `10ca5d9ea5c38640ae3f1df4b655ff368839ffbb61aaa6c5b4f74f50f529b8f5`
- `patches/skip-password-call.uf2` — 8192 байт, `d98bd6719c775d925ec04810bf68de2e91d7ac60eb772797e51960afc6473ff4`
- `ram-exec-proof.json` — 513 байт, `de37c154e4e3bc828af50098aa925b672ed156fd286c2dd2f89b9bc7fad1e962`
- `reproduction-final/disk-region.bin` — 1048576 байт, `5b07fe65994a80d2bf4cc67fd7d031ff49bfda003ae50f24a3eb41c35e57d053`
- `reproduction-final/disk-region.bin.json` — 386 байт, `e9c1b078becceed22b8d06c67ada87005209900b4b44c7c4a5a89d78a1631b59`
- `reproduction-final/disk.img` — 1048576 байт, `6df635a0ddfd0f1b5c8c243382cc23dd366c63393fd18a20baaf73d5372e2c4b`
- `reproduction-final/disk.img.json` — 443 байт, `73bd4420f788d113d71402aaa219491ca009e6ba45129236e2b8db5b2fcdd322`
- `reproduction-final/fat-root.json` — 729 байт, `ce7b8daf095cc0c44e509a15ccaaecbbe43b2a5199a6c6658ea6c2e7316665cb`
- `reproduction-final/flash.bin` — 2097152 байт, `640626b93d7492a6efadba09759cf349d84a45b785cd31703ad37912d6cf9eb9`
- `reproduction-final/flash.bin.json` — 380 байт, `c6b9060513af54ab3888f5223552cc8e1114800ea835a3961aafd04f0d22e43a`
- `reproduction-final/pin.bin` — 4 байт, `080fe7399f197fc37d89d01ffbbb17f04f7f2ba3dd84baab2b5f09b3fc54a140`
- `reproduction-final/pin.bin.json` — 372 байт, `3eb585bb2eaf97f0435fc7bcfe7398c20ac779136f650abc1020c47b39733e02`
- `reproduction-final/session.log` — 9080 байт, `397f9dfb7bf4269ca5716cf38b09e1bc272a8c62d3b22a9edfd7255fb8a37a44`
- `restore-full-original.json` — 500 байт, `212246116b430eb57837b9c3c9f04bd60460ed781dbea34f69982bdf53d4f391`
- `restore-full-original.uf2` — 4194304 байт, `1915760aaeea360dd6da47bf10906789312b57341dee3214c2f7bca3f33054ae`
- `sram-read.bin` — 270336 байт, `9f90ada3e201a521cd7b4109ec02f8241153f22cadf5ed6735589b2651271c1b`
- `sram-read.bin.json` — 364 байт, `344e4f18ebaabf54767b087a0bd6603567729890765859dbd54608f18aadd972`
- `timing-camera-20260927/README.txt` — 1703 байт, `ecdcc8be6d5c3e42eeba9647608c88f3da3a7b019fdde857ba333d1083516a9a`
- `timing-camera-20260927/result.json` — 692 байт, `de1dac4993ec1a32710e253954c597759e5cbf01194b1355602dafd664612dbb`
- `transform/transform-proof.json` — 1523 байт, `0d4e63e72c59bb38799faae56ea268e48331191866ada1f39d9ea12941600c11`
- `uf2-validation.txt` — 3294 байт, `f696702f8b5d594e55ceca4582867c06442c988e5a1753b10896f2f11bad3f1a`

ZIP-пасхалка не открывалась, не копировалась отдельным файлом и не распаковывалась.
