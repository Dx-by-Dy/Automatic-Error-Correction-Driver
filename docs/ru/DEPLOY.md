# VM для разработки

Никогда не загружайте драйвер и не запускайте его тесты на хосте: они перезаписывают `/dev/vdb`, а ошибка в драйвере
может уронить ядро. Всё работает в VM на QEMU, которой управляет `deploy/vm.sh`. В ней последняя Fedora с
отладочным ядром (KASAN, lockdep, UBSAN, kmemleak), доступная по SSH на localhost.

```bash
deploy/vm.sh create       # once: download the image, create and provision the VM
deploy/vm.sh start        # start the VM and wait for SSH
deploy/vm.sh reinit       # sync the working tree, rebuild the driver and dcorrsetup, reload, recreate the device
deploy/vm.sh test [ARGS]  # reinit, run the tests, ARGS go to pytest: -m "not slow", -k corruption
deploy/vm.sh check        # compiler warnings at W=1, sparse, checkpatch; dcorrsetup with -Werror
deploy/vm.sh ssh [CMD]    # shell in the VM or run CMD there
deploy/vm.sh status       # the VM, the test disk and the driver
deploy/vm.sh reset        # power off and start again, for a stuck kernel
deploy/vm.sh stop
```

Драйвер разрабатывается, собирается и проверяется только в VM. На хосте `make check` останавливается с ошибкой, так
как он оставил бы объектные файлы в дереве и проверял бы без sparse из VM; обычный `make` оставлен для
пользователей.

`deploy/vm.sh help` перечисляет все команды и настройки, которые задаются переменными окружения.

## Где что лежит

- VM живёт вне репозитория, в `~/vms/corrdm` (`CORRDM_VM_DIR`). Журналы тестов там же в `logs/`, консоль ядра в
  `serial.log`, консоль предыдущей загрузки в `serial.prev.log`.
- Рабочее дерево копируется в `~/corrdm` в VM, вместе с незакоммиченными изменениями. Правьте на хосте, а не в VM:
  следующая синхронизация перезапишет копию.
- Тесты описаны в [TESTS.md](TESTS.md).

## Тестовый диск

Гость видит его как `/dev/vdb`. Полный прогон тестов пишет на него больше сотни гигабайт, в основном `fio` по одним
и тем же небольшим областям, поэтому по умолчанию это файл в 2 GiB в RAM, `/dev/shm/corrdm/vdb.img`. Тесты
используют только его первые 512 MiB. На нём нет ничего ценного: `deploy/vm.sh start` создаёт его заново, если его
нет, например после перезагрузки хоста.

Чтобы тестировать на настоящем диске, укажите в `CORRDM_TEST_DISK_DIR` каталог на нём, для каждой команды сеанса:

```bash
export CORRDM_TEST_DISK_DIR=~/vms/corrdm
deploy/vm.sh stop && deploy/vm.sh start
```

QEMU открывает его с `cache=none`, так что гость в любом случае видит диск с кэшем обратной записи, и flush доходит
до файла. На настоящем диске он использует Linux AIO, а на tmpfs, где Linux AIO блокируется, — свои потоки.

## Код

`deploy/vm.sh` читает настройки и запускает команду из `deploy/vm/`:

| Файл | Что делает |
| ---- | ---------- |
| `config.sh` | Настройки и их значения по умолчанию, `log` и `die` |
| `connection.sh` | Работает ли VM, SSH, `guest_run` |
| `image.sh` | `create`, `provision`, `destroy` |
| `power.sh` | `start`, `stop`, `reset`, `status`, тестовый диск |
| `driver.sh` | `sync`, `reinit`, `test`, `check` |
| `guest.sh` | Работает от root внутри VM: пересобирает и перезагружает драйвер и `dcorrsetup`, форматирует `/dev/vdb` и создаёт на нём `dcorr`, запускает pytest |

`guest_run` передаёт `guest.sh` по SSH в `bash` внутри VM, так что гостю нужно только синхронизированное дерево.
`guest.sh` отказывается работать вне VM.

## sparse

`deploy/vm.sh check` запускает `sparse` через сборку ядра (`C=1`). Ядро принимает его, только если он понимает
`__typeof_unqual__`, а sparse 0.6.4 из Fedora не понимает, так что без более нового `make check` печатает
предупреждение и продолжает без него. Соберите его из upstream внутри VM, один раз; `/usr/local/bin` стоит первым в
`secure_path` у `sudo`, так что `make check` его находит:

```bash
deploy/vm.sh ssh 'sudo dnf -y -q install git && git clone --depth 1 https://git.kernel.org/pub/scm/devel/sparse/sparse.git ~/sparse && make -C ~/sparse -j6 sparse && sudo install -m 755 ~/sparse/sparse /usr/local/bin/sparse'
deploy/vm.sh ssh 'sh /usr/src/kernels/$(uname -r)/scripts/checker-valid.sh sparse -m64 -mlittle-endian'   # must print 1
```

Проверено с коммитом `84ec065` от 2026-10-22, у которого `--version` всё ещё говорит 0.6.4. Намеренная ошибка
порядка байт (`md->crc[i] = current_crc` без `cpu_to_le64`) даёт `incorrect type in assignment`.

## Тесты и зависания

- Тест также падает на отчётах `BUG`, `WARNING`, KASAN, UBSAN, lockdep и о зависших задачах в журнале ядра.
- Зависание сразу завершает прогон с кодом выхода 3 и оставляет VM зависшей для изучения. Заблокированные задачи и
  занятые workqueue есть в журнале ядра, сохранённом в `logs/`. Затем выполните `deploy/vm.sh reset`.
- Перед прогоном, который должен показать, что lockdep был включён всё время, начните с чистой загрузки через
  `deploy/vm.sh reset`: после прогона `sudo grep debug_locks /proc/lockdep_stats` должен дать 1. Lockdep
  выключается сам после первого отчёта.
- Не снимайте цифры бенчмарков на отладочном ядре: его проверки определяют время.

## Намеренная поломка драйвера

Чтобы проверить, что тесты ловят ошибку, сломайте копию в VM и протестируйте её без синхронизации:

```bash
deploy/vm.sh sync
deploy/vm.sh ssh                       # edit ~/corrdm/src/ in the VM
deploy/vm.sh test --no-sync -m "not slow"
deploy/vm.sh sync                      # restore the copy
```

Результаты на сегодня — в последнем разделе [TESTS.md](TESTS.md#ловят-ли-тесты-ошибки).

## Проверка документации

Документы лежат в `docs/en/`, а на русском — в `docs/ru/`. Перед коммитом запустите на хосте:

```bash
tools/check-docs.py              # links and anchors, tests named, pairs of languages, mermaid diagrams
tools/check-docs.py --no-mermaid # without the mermaid CLI, which npx fetches on its first run
```

Нужны Python 3 и, для диаграмм, Node.js с `npx`. Что документы говорят то же, что код и друг друга, проверяется
вручную.
