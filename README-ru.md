# YubiCA

`yubica` — это CLI на Rust для работы с офлайн Root CA, размещённым в PIV-слоте YubiKey, и для
подписи сертификатов или CSR без извлечения root private key.

Инструмент рассчитан на air-gapped или semi-air-gapped сценарии, где:

- root CA key остаётся внутри YubiKey
- intermediate или leaf CSR подписываются офлайн
- выходные файлы записываются только в уже существующую директорию

## Текущие возможности

- Список подключённых YubiKey и их serial-номеров
- Быстрый вывод состояния типовых слотов
- Инициализация self-signed root CA в слоте YubiKey
- Получение сертификата из PIV-слота YubiKey
- Подпись существующего CSR через CA-ключ на YubiKey
- Локальная генерация host private key и CSR с последующей подписью через CA на YubiKey

## Выбор устройства

Все команды, кроме `list-keys`, требуют `--serial` (или `YUBICA_SERIAL`), чтобы
выбрать, с каким подключённым YubiKey работать. Никакого варианта "просто
взять тот, что подключён" нет: если подключено больше одного устройства,
неявный выбор неоднозначен, и инструмент отказывается угадывать.

```powershell
yubica list-keys
yubica get-ca --serial 12345678 --iopath . --filename current-ca
```

## Логирование

Для управления уровнем логов используется `--log`.

Поддерживаемые значения:

- `trace`
- `debug`
- `info`
- `warn`
- `error`

Примеры:

```powershell
yubica --log info get-ca --serial 12345678
yubica --log debug list-slots --serial 12345678
```

Если передан `--log`, он имеет приоритет над `RUST_LOG`.
Если не заданы ни `--log`, ни `RUST_LOG`, используется уровень `info`.

## Секреты

`--pin`, `--mgm-key-hex` и `--passwd` можно передать как обычные CLI-флаги, но
это оставляет их в истории шелла и в списке процессов. Предпочтительнее
переменные окружения ниже; явный CLI-флаг всё равно имеет приоритет, если
заданы оба варианта.

| Флаг | Переменная окружения |
| --- | --- |
| `--pin` | `YUBICA_PIN` |
| `--mgm-key-hex` | `YUBICA_MGM_KEY_HEX` |
| `--passwd` | `YUBICA_PASSWD` |

```powershell
$env:YUBICA_PIN = "123456"
yubica sign-csr --serial 12345678 --iopath . --filename intermediate
```

## Модель вывода

Команды, которые создают файлы, используют:

- `--iopath` для директории вывода
- `--filename` для базового имени файла

Директория должна существовать заранее. Инструмент не создаёт её автоматически.

Используемые расширения:

- сертификат: `.crt`
- private key: `.key`
- CSR: `.csr`

Примеры:

```powershell
yubica get-ca --serial 12345678 --iopath . --filename current-ca
yubica sign-csr --serial 12345678 --iopath . --filename intermediate
yubica issue-host --serial 12345678 --host app.example.internal --iopath . --filename app-example
```

## Аргументы срока действия

Следующие флаги взаимоисключающие:

- `--valid-days`
- `--valid-months`
- `--valid-years`

Если ни один не задан, используется срок по умолчанию для соответствующей команды.

Текущие значения по умолчанию:

- Root CA: `20` лет
- Подпись CSR: `20` лет
- Host certificate: `1` год

Примеры:

```powershell
yubica init-ca --serial 12345678 --valid-years 20
yubica sign-csr --serial 12345678 --filename int --valid-days 7300
yubica issue-host --serial 12345678 --host api.example.internal --valid-months 6
```

## Команды

### `list-keys`

Перечисляет подключённые PC/SC-ридеры и сообщает serial каждого найденного
YubiKey. Это единственная команда, не требующая `--serial`.

```powershell
yubica list-keys
```

### `list-slots`

Логирует состояние типовых PIV-слотов.

```powershell
yubica list-slots --serial 12345678
```

### `init-ca`

Создаёт self-signed root CA certificate, привязанный к private key, сгенерированному внутри YubiKey.

```powershell
yubica init-ca --serial 12345678 --pin 654321 --mgm-key-hex 010203040506070801020304050607080102030405060708
```

Важные замечания:

- слот по умолчанию: `9c`
- subject по умолчанию: `CN=Offline Root CA`
- алгоритм по умолчанию: `ecc-p384`
- PIN policy по умолчанию: `always`
- touch policy по умолчанию: `always`
- `init-ca` всегда требует `--pin`, чтобы проверить текущий PIN токена до генерации ключа
- `init-ca` отказывается работать с factory-default management key
- `init-ca` отказывается работать с factory-default PIN (`123456`)
- `--algorithm`, `--pin-policy` и `--touch-policy` можно настраивать
- инструмент не пытается проверять default PIN или PUK на самом токене, потому что неверные попытки уменьшают счётчики retries
- `--force` отключает предварительную проверку занятости слота, но не является полноценной процедурой удаления старого ключа
- `init-ca` не записывает файлы; для экспорта получившегося сертификата используйте `get-ca`
- management key должен быть алгоритма `TDES`: инструмент реализует только 3DES challenge-response
  и вообще не может авторизоваться против management key на `AES128`/`AES192`/`AES256`. Прошивка
  5.7.x и новее по умолчанию ставит на свежем устройстве `AES192`, так что на таком устройстве
  сначала нужно принудительно вернуть алгоритм на TDES: `ykman piv access change-management-key
  -a tdes -n <new-key-hex>` — иначе `init-ca` (и любая другая команда с `--mgm-key-hex`) не
  авторизуется

### `get-ca`

Читает сертификат из PIV-слота YubiKey (по умолчанию — слот root CA, `9c`) и экспортирует его,
если он присутствует.

```powershell
yubica get-ca --serial 12345678 --iopath . --filename current-ca
```

Результат:

- `current-ca.crt`

Замечания:

- слот по умолчанию: `9c`
- `--slot` позволяет прочитать другой слот, например если CA был инициализирован не на стандартном
- если в слоте нет сертификата, ничего не записывается, в лог пишется сообщение

### `sign-csr`

Подписывает существующий CSR с использованием CA certificate/key из выбранного слота YubiKey.
CSR читается из `<iopath>/<filename>.csr` — положите его туда под тем же базовым именем, что и
у выходного файла.

```powershell
yubica sign-csr --serial 12345678 --pin 123456 --iopath . --filename intermediate
```

Читает:

- `intermediate.csr`

Результат:

- `intermediate.crt`

Обработка CSR:

- слот по умолчанию: `9c`
- срок действия по умолчанию: `20` лет
- поддерживаются PEM и DER на входе
- запрошенные расширения переносятся частично
- неподдерживаемые CSR extensions игнорируются с warning
- перед подписью (и до того, как YubiKey запросит touch) в лог выводятся subject и запрошенные
  расширения CSR — для проверки перед подтверждением

Сейчас переносятся следующие CSR extensions:

- `BasicConstraints`
- `KeyUsage`
- `ExtendedKeyUsage`
- `SubjectAltName`

Также инструмент добавляет:

- `SubjectKeyIdentifier`
- `AuthorityKeyIdentifier`

Является ли выпускаемый сертификат CA — решает подписывающая сторона, а не тот, кто прислал CSR:
собственные `BasicConstraints`/`KeyUsage` из CSR — это лишь запрос, а не авторизация. Передайте
`--ca`, чтобы подписать промежуточный CA: это принудительно проставит `BasicConstraints` `CA:TRUE`
и `KeyUsage` `keyCertSign`+`cRLSign` в выпускаемом сертификате, игнорируя то, что запросил сам CSR
по этим двум расширениям. Без `--ca` команда откажется подписывать CSR, который сам запрашивает
`CA:TRUE` или `keyCertSign`/`cRLSign` — она не понижает такой CSR молча до leaf-сертификата. Это не
даёт никакому CSR самостоятельно объявить себе полномочия CA через обычный вызов `sign-csr`.

```powershell
yubica sign-csr --serial 12345678 --ca --pin 123456 --iopath . --filename intermediate
```

CA никогда не выпускает сертификат, переживающий сам себя: если запрошенный
срок действия выходит за пределы срока действия сертификата издателя,
`not_after` молча ограничивается сроком действия издателя (при этом в лог
пишется warning).

### `issue-host`

Локально генерирует host private key, создаёт CSR, подписывает его через CA на YubiKey и записывает все артефакты на диск.

```powershell
yubica issue-host --serial 12345678 --host api.example.internal --host 10.10.10.20 --pin 123456 --iopath . --filename api-example
```

Результат:

- `api-example.key`
- `api-example.csr`
- `api-example.crt`

Сгенерированный host CSR всегда запрашивает `BasicConstraints` (`CA:FALSE`) и
`KeyUsage` (`digitalSignature`) в дополнение к SAN и EKU `serverAuth`, поэтому
выпущенный leaf-сертификат несёт их независимо от того, что добавил бы общий
механизм переноса расширений CSR в `sign-csr`.

Если передан `--passwd`, сгенерированный private key сохраняется как encrypted PKCS#8 PEM.

```powershell
yubica issue-host --serial 12345678 --host api.example.internal --pin 123456 --passwd changeit --iopath . --filename api-example
```

## Air-gapped OpenBao intermediate flow

Если OpenBao генерирует intermediate key внутри себя, private key не покидает Bao. В таком сценарии
офлайн root нужен только для подписи CSR.

Типовой процесс:

1. Сгенерировать intermediate CSR внутри OpenBao.
2. Сохранить CSR как `<filename>.csr` в директории, которую передадите как `--iopath`, например
   `intermediate.csr`.
3. Подписать его офлайн через `yubica sign-csr --ca` — собственный CSR от OpenBao не всегда
   запрашивает `BasicConstraints`/`KeyUsage`, и без `--ca` выпущенный сертификат оказался бы
   обычным leaf, который OpenBao затем откажется импортировать как intermediate ("Refusing to
   import non-CA certificate").
4. Вернуть полученный `intermediate.crt` обратно в OpenBao.
5. При необходимости собрать chain из signed intermediate certificate и root certificate.

Пример офлайн-подписи:

```powershell
yubica sign-csr --serial 12345678 --ca --pin 123456 --iopath . --filename intermediate
```

## Замечания по безопасности

- Поддерживается только ECC (`ecc-p256`, `ecc-p384`); RSA удалён из проекта. Заодно это снимает
  вопрос с непропатченным advisory о тайминговой атаке Marvin в крейте `rsa` (RUSTSEC-2023-0071) —
  он больше не актуален, так как этот крейт не используется как зависимость
- Предпочитайте `YUBICA_PIN`/`YUBICA_MGM_KEY_HEX`/`YUBICA_PASSWD` вместо соответствующих
  CLI-флагов, чтобы не оставлять секреты в истории шелла и списке процессов
- Root private key остаётся на YubiKey при `init-ca` и `sign-csr`
- `issue-host` намеренно генерирует host private key локально, а не на YubiKey
- Заводской management key не должен использоваться в production-процедурах
- Factory-default PIN должен быть заменён до `init-ca`; CLI жёстко запрещает default management
  key и отклоняет default PIN
- Все команды, кроме `list-keys`, требуют явного `--serial`; инструмент никогда не угадывает, с
  каким подключённым YubiKey работать
- В репозитории пока нет полноценного workflow для очистки слота или безопасной замены
  существующего CA in-place

## Тестирование

`cargo test` запускает набор юнит-тестов (чистая логика: расчёт срока действия
и календарная арифметика, обработка subject/SAN в CSR, разбор management key,
определение алгоритма по OID, валидация выходных путей). Никакое железо не
затрагивается, ни один из этих тестов не требует подключённого YubiKey.

Отдельный набор в `tests/hardware.rs` прогоняет реальное железо end-to-end
(`list-keys`-подобное перечисление там не покрыто, но `get-ca`, `init-ca` и
`issue-host` — да). Он никогда не запускается по умолчанию:

```powershell
$env:YUBICA_TEST_SERIAL = "12345678"     # обязательно: нужно каждому тесту
$env:YUBICA_TEST_PIN = "..."             # обязательно: только для деструктивного теста
$env:YUBICA_TEST_MGM_KEY_HEX = "..."     # обязательно: только для деструктивного теста
$env:YUBICA_TEST_SLOT = "9c"             # опционально, по умолчанию 9c

cargo test --features hardware-tests --test hardware -- --test-threads=1
```

Замечания:

- Используйте одноразовый YubiKey. `init_ca_then_issue_host_round_trip`
  генерирует настоящую пару ключей в выбранном слоте с флагом `--force`,
  безвозвратно перезаписывая всё, что там было.
- PIN и management key тестового ключа должны быть уже заменены с заводских
  значений — это проверяют собственные защитные механизмы `init-ca`, точно
  так же, как в продакшене. На прошивке 5.7.x+ это также означает
  принудительный возврат алгоритма management key на `TDES` (см. раздел
  `init-ca` выше — почему).
- `--test-threads=1` обязателен. PC/SC не переносит одновременное открытие
  одной и той же физической смарт-карты двумя тестами (иначе запуск в
  несколько потоков по умолчанию упадёт с PC/SC-ошибкой `ResetCard`).
- Отдельного флага "точно ли вы уверены" сверх cargo-фичи и переменных
  окружения выше нет — указание реального serial устройства и его реальных
  секретов уже само по себе является тем осознанным шагом, который делает
  запуск безопасным.

## Краткая сводка примеров

```powershell
yubica list-keys

yubica list-slots --serial 12345678

yubica init-ca --serial 12345678 --pin 654321 --mgm-key-hex 010203040506070801020304050607080102030405060708

yubica get-ca --serial 12345678 --iopath . --filename current-ca

yubica sign-csr --serial 12345678 --ca --pin 123456 --iopath . --filename intermediate

yubica issue-host --serial 12345678 --host app.example.internal --host 10.0.0.10 --pin 123456 --iopath . --filename app
```
