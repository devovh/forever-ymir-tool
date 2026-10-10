// UI texts in English, Spanish and Russian (same languages as the Forever launcher), and the few settings the tool remembers.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace YmirTool
{
    public static class L
    {
        public static int Lang;                     // 0 English, 1 Spanish, 2 Russian
        public static readonly string[] Names = { "English", "Español", "Русский" };

        static readonly Dictionary<string, string[]> T = new Dictionary<string, string[]>
        {
            // tabs and their one-line help
            { "tab.patch",      new[] { "1. Patch Ymir", "1. Parchear Ymir", "1. Патч Ymir" } },
            { "tab.record",     new[] { "2. Record", "2. Grabar", "2. Запись" } },
            { "tab.viewer",     new[] { "3. Viewer", "3. Visor", "3. Просмотр" } },
            { "help.patch",     new[] { "Ymir only works with the client build it was made for. Here you make a copy of it for the build you have now.",
                                        "Ymir solo funciona con la build del cliente para la que se hizo. Aquí haces una copia para la build que tienes ahora.",
                                        "Ymir работает только со сборкой клиента, для которой он сделан. Здесь создаётся копия для вашей текущей сборки." } },
            { "help.record", new[] { "Start the recorder (Ymir, or our Forever Sniffer) before the game, play, then close the game: it saves the sniff and stops by itself.",
                                        "Inicia el grabador (Ymir o nuestro Forever Sniffer) antes que el juego, juega y cierra el juego: guarda la captura y se cierra solo.",
                                        "Запустите запись (Ymir или наш Forever Sniffer) до игры, играйте, затем закройте игру: сниф сохранится, и запись закроется сама." } },
            { "help.viewer",    new[] { "Open a sniff (or drag it here). With Follow live on, new packets appear while Ymir is recording.",
                                        "Abre una captura (o arrástrala aquí). Con Seguir en vivo, los paquetes nuevos aparecen mientras Ymir graba.",
                                        "Откройте сниф (или перетащите его сюда). С «Следить» новые пакеты появляются во время записи Ymir." } },
            { "language",       new[] { "Language", "Idioma", "Язык" } },

            // patch tab
            { "ymir",           new[] { "Ymir (original)", "Ymir (original)", "Ymir (оригинал)" } },
            { "browse",         new[] { "Browse...", "Buscar...", "Обзор..." } },
            { "client",         new[] { "Game client", "Cliente del juego", "Клиент игры" } },
            { "refresh",        new[] { "Refresh", "Actualizar", "Обновить" } },
            { "find",           new[] { "Find addresses", "Buscar direcciones", "Найти адреса" } },
            { "create",         new[] { "Create patched Ymir", "Crear Ymir parcheado", "Создать патченный Ymir" } },
            { "openfolder",     new[] { "Open Ymir folder", "Abrir carpeta de Ymir", "Открыть папку Ymir" } },
            { "col.address",    new[] { "Address", "Dirección", "Адрес" } },
            { "col.original",   new[] { "Ymir original (70124)", "Ymir original (70124)", "Оригинал Ymir (70124)" } },
            { "col.new",        new[] { "This client", "Este cliente", "Этот клиент" } },
            { "col.method",     new[] { "Found by", "Encontrada por", "Найдено" } },
            { "col.check",      new[] { "Check", "Comprobación", "Проверка" } },
            { "addr.locale_table", new[] { "Locale table", "Tabla de idiomas", "Таблица языков" } },
            { "addr.locale_index", new[] { "Locale index", "Índice de idioma", "Индекс языка" } },
            { "addr.session",   new[] { "Session key object", "Objeto de la clave de sesión", "Объект ключа сессии" } },
            { "noclient",       new[] { "Not running. Start the game (and log in to the character screen to confirm the session key).",
                                        "No está abierto. Inicia el juego (y entra a la pantalla de personajes para confirmar la clave de sesión).",
                                        "Не запущен. Запустите игру (и войдите до выбора персонажа, чтобы подтвердить ключ сессии)." } },
            { "ymir.ok",        new[] { "OK: the Ymir for build 70124", "OK: el Ymir para la build 70124", "OK: Ymir для сборки 70124" } },
            { "ymir.bad",       new[] { "Not the Ymir this tool knows: {0}", "No es el Ymir que conoce esta herramienta: {0}", "Это не тот Ymir, который знает программа: {0}" } },
            { "ymir.none",      new[] { "Choose regedit.exe from the Ymir Forever beta folder.", "Elige regedit.exe de la carpeta de Ymir Forever beta.", "Выберите regedit.exe из папки Ymir Forever beta." } },
            { "known",          new[] { "Build {0} is already known: its addresses are filled in (no search needed).",
                                        "La build {0} ya es conocida: sus direcciones están puestas (no hace falta buscar).",
                                        "Сборка {0} уже известна: адреса заполнены (поиск не нужен)." } },
            { "method.known",   new[] { "known build", "build conocida", "известная сборка" } },
            { "method.fp",      new[] { "fingerprint {0}/{1} (next best {2})", "huella {0}/{1} (siguiente {2})", "отпечаток {0}/{1} (след. {2})" } },
            { "check.ok",       new[] { "OK: {0}", "OK: {0}", "OK: {0}" } },
            { "check.unconfirmed", new[] { "Unconfirmed: {0}", "Sin confirmar: {0}", "Не подтверждено: {0}" } },
            { "check.failed",   new[] { "FAILED: {0}", "FALLÓ: {0}", "ОШИБКА: {0}" } },
            { "searching",      new[] { "Searching client build {0} (starting near build {1})...", "Buscando en el cliente build {0} (empezando cerca de la build {1})...",
                                        "Поиск в клиенте сборки {0} (начиная рядом со сборкой {1})..." } },
            { "learned",        new[] { "All three confirmed: build {0} saved for next time.", "Las tres confirmadas: build {0} guardada para la próxima vez.",
                                        "Все три подтверждены: сборка {0} сохранена на будущее." } },
            { "notall",         new[] { "Not every address is confirmed. Log in to the character screen and search again before creating Ymir.",
                                        "No todas las direcciones están confirmadas. Entra a la pantalla de personajes y busca otra vez antes de crear Ymir.",
                                        "Не все адреса подтверждены. Войдите до выбора персонажа и повторите поиск перед созданием Ymir." } },
            { "written",        new[] { "Written: {0} ({1} values changed). The Record tab uses it from now on.",
                                        "Guardado: {0} ({1} valores cambiados). La pestaña Grabar lo usa a partir de ahora.",
                                        "Записано: {0} (изменено значений: {1}). Вкладка «Запись» теперь использует его." } },
            { "overwrite",      new[] { "{0} already exists. Replace it?", "{0} ya existe. ¿Reemplazarlo?", "{0} уже существует. Заменить?" } },

            // record tab
            { "recorder",       new[] { "Recorder", "Grabador", "Запись через" } },
            { "rec.sniffer",    new[] { "Forever Sniffer (ours, any client build)", "Forever Sniffer (nuestro, cualquier build)", "Forever Sniffer (наш, любая сборка)" } },
            { "strict",         new[] { "Close the game if the recording goes wrong", "Cerrar el juego si la grabación falla", "Закрыть игру, если запись сбоит" } },
            { "pick.sniffer",   new[] { "Forever Sniffer (ForeverSniffer.exe)", "Forever Sniffer (ForeverSniffer.exe)", "Forever Sniffer (ForeverSniffer.exe)" } },
            { "no.sniffer",     new[] { "ForeverSniffer.exe not found: choose it with Browse", "No se encuentra ForeverSniffer.exe: elígelo con Examinar", "ForeverSniffer.exe не найден: выберите его кнопкой «Обзор»" } },
            { "sniffer.adapter", new[] { "every adapter (or interface.cfg next to the sniffer)", "todos los adaptadores (o interface.cfg junto al sniffer)", "все адаптеры (или interface.cfg рядом со сниффером)" } },
            { "checklist",      new[] { "Before recording", "Antes de grabar", "Перед записью" } },
            { "chk.npcap",      new[] { "Npcap (network capture driver)", "Npcap (controlador de captura)", "Npcap (драйвер захвата)" } },
            { "chk.adapter",    new[] { "Capture adapter (interface.cfg)", "Adaptador de captura (interface.cfg)", "Адаптер захвата (interface.cfg)" } },
            { "chk.ymir",       new[] { "Ymir for client build {0}", "Ymir para la build {0} del cliente", "Ymir для сборки клиента {0}" } },
            { "chk.nobuild",    new[] { "Ymir for the client build (start the game once, or pick the game folder in tab 1)",
                                        "Ymir para la build del cliente (abre el juego una vez)", "Ymir для сборки клиента (запустите игру один раз)" } },
            { "ok.npcap",       new[] { "installed", "instalado", "установлен" } },
            { "ok.adapter",     new[] { "set", "configurado", "задан" } },
            { "no.adapter",     new[] { "not set: start Ymir once and choose your network adapter in its window", "sin configurar: abre Ymir una vez y elige tu adaptador de red en su ventana",
                                        "не задан: запустите Ymir один раз и выберите сетевой адаптер в его окне" } },
            { "no.ymir",        new[] { "missing: make it in tab 1", "falta: créalo en la pestaña 1", "нет: создайте его на вкладке 1" } },
            { "clearcache",     new[] { "Delete the game's Cache folder before starting (recommended by Ymir)", "Borrar la carpeta Cache del juego antes de empezar (lo recomienda Ymir)",
                                        "Удалить папку Cache игры перед запуском (рекомендует Ymir)" } },
            { "start", new[] { "Start recording",
                                        "Iniciar grabación",
                                        "Начать запись" } },
            { "stop", new[] { "Stop recording",
                                        "Detener grabación",
                                        "Остановить запись" } },
            { "opendumps",      new[] { "Open sniff folder", "Abrir carpeta de capturas", "Открыть папку снифов" } },
            { "state.off", new[] { "The recorder is not running.",
                                        "El grabador no está en marcha.",
                                        "Запись не запущена." } },
            { "state.on", new[] { "The recorder is running (PID {0}).",
                                        "El grabador está en marcha (PID {0}).",
                                        "Запись работает (PID {0})." } },
            { "state.rec", new[] { "Recording: {0}, {1}{2}",
                                        "Grabando: {0}, {1}{2}",
                                        "Идёт запись: {0}, {1}{2}" } },
            { "growing",        new[] { ", growing", ", creciendo", ", растёт" } },
            { "cache.gamerunning", new[] { "The game is running: the Cache folder can only be deleted while it is closed. Ymir starts without it.",
                                           "El juego está abierto: la carpeta Cache solo se puede borrar con el juego cerrado. Ymir se inicia sin borrarla.",
                                           "Игра запущена: папку Cache можно удалить только при закрытой игре. Ymir запускается без этого." } },
            { "cache.deleted",  new[] { "Deleted {0}", "Borrado {0}", "Удалено {0}" } },
            { "started", new[] { "Recorder started. Now start the game and log in.",
                                        "Grabador iniciado. Ahora inicia el juego y entra.",
                                        "Запись запущена. Теперь запустите игру и войдите." } },
            { "stopped", new[] { "Recorder stopped.",
                                        "Grabador detenido.",
                                        "Запись остановлена." } },
            { "notstopped",     new[] { "Ymir did not stop. Close the game (Ymir then stops by itself) or close its window.",
                                        "Ymir no se detuvo. Cierra el juego (Ymir se cierra solo) o cierra su ventana.",
                                        "Ymir не остановился. Закройте игру (Ymir закроется сам) или его окно." } },
            { "recordings",     new[] { "Your sniffs", "Tus capturas", "Ваши снифы" } },
            { "col.date",       new[] { "Recorded", "Grabada", "Записан" } },
            { "col.build",      new[] { "Build", "Build", "Сборка" } },
            { "col.file",       new[] { "File", "Archivo", "Файл" } },
            { "openrec",        new[] { "Open in viewer", "Abrir en el visor", "Открыть в просмотре" } },

            // viewer tab
            { "open",           new[] { "Open sniff...", "Abrir captura...", "Открыть сниф..." } },
            { "follow",         new[] { "Follow live", "Seguir en vivo", "Следить" } },
            { "tolive",         new[] { "Back to live", "Volver al final", "К концу" } },
            { "filter",         new[] { "Filter: name or opcode", "Filtro: nombre u opcode", "Фильтр: имя или опкод" } },
            { "dir.all",        new[] { "Both directions", "Ambas direcciones", "Оба направления" } },
            { "dir.server",     new[] { "Server -> client", "Servidor -> cliente", "Сервер -> клиент" } },
            { "dir.client",     new[] { "Client -> server", "Cliente -> servidor", "Клиент -> сервер" } },
            { "summary",        new[] { "Summary by opcode", "Resumen por opcode", "Сводка по опкодам" } },
            { "search",         new[] { "Search packet contents", "Buscar en el contenido", "Поиск в содержимом" } },
            { "search.text",    new[] { "Text", "Texto", "Текст" } },
            { "search.hex",     new[] { "Hex bytes", "Bytes hex", "Hex-байты" } },
            { "prev",           new[] { "< Previous", "< Anterior", "< Назад" } },
            { "next",           new[] { "Next >", "Siguiente >", "Далее >" } },
            { "found",          new[] { "Found in packet #{0} at byte {1}.", "Encontrado en el paquete #{0}, byte {1}.", "Найдено в пакете #{0}, байт {1}." } },
            { "notfound",       new[] { "Not found {0} (in the packets the filter shows).", "No encontrado {0} (en los paquetes que muestra el filtro).",
                                        "Не найдено {0} (среди пакетов, которые показывает фильтр)." } },
            { "dir.down",       new[] { "after this packet", "después de este paquete", "после этого пакета" } },
            { "dir.up",         new[] { "before this packet", "antes de este paquete", "до этого пакета" } },
            { "badhex",         new[] { "Hex search: type bytes like  8B 02 FF", "Búsqueda hex: escribe bytes como  8B 02 FF", "Hex-поиск: введите байты, например  8B 02 FF" } },
            { "export",         new[] { "Export list (CSV)", "Exportar lista (CSV)", "Экспорт списка (CSV)" } },
            { "copyhex",        new[] { "Copy hex", "Copiar hex", "Копировать hex" } },
            { "savepkt",        new[] { "Save packet", "Guardar paquete", "Сохранить пакет" } },
            { "exported",       new[] { "Saved {0} rows to {1}", "Guardadas {0} filas en {1}", "Сохранено строк: {0} в {1}" } },
            { "copied",         new[] { "Copied {0} bytes as hex.", "Copiados {0} bytes como hex.", "Скопировано байт: {0}." } },
            { "col.n",          new[] { "#", "#", "#" } },
            { "col.time",       new[] { "Time", "Tiempo", "Время" } },
            { "col.dir",        new[] { "Dir", "Dir", "Напр." } },
            { "col.conn",       new[] { "Conn", "Con", "Соед." } },
            { "col.opcode",     new[] { "Opcode", "Opcode", "Опкод" } },
            { "col.name",       new[] { "Name", "Nombre", "Имя" } },
            { "col.size",       new[] { "Size", "Tamaño", "Размер" } },
            { "col.count",      new[] { "Count", "Cantidad", "Кол-во" } },
            { "col.sizes",      new[] { "Sizes", "Tamaños", "Размеры" } },
            { "pktinfo",        new[] { "{0}  ·  build {1}  ·  started {2}  ·  {3:N0} packets ({4:N0} shown)  ·  {5}",
                                        "{0}  ·  build {1}  ·  iniciada {2}  ·  {3:N0} paquetes ({4:N0} mostrados)  ·  {5}",
                                        "{0}  ·  сборка {1}  ·  начало {2}  ·  пакетов {3:N0} (показано {4:N0})  ·  {5}" } },
            { "nopkt",          new[] { "No sniff open.", "Ninguna captura abierta.", "Сниф не открыт." } },
            { "loading",        new[] { "Opening {0}...", "Abriendo {0}...", "Открытие {0}..." } },
        };

        public static string Get(string key, params object[] args)
        {
            string[] t;
            string s = T.TryGetValue(key, out t) ? t[Lang] : key;
            return args.Length > 0 ? string.Format(s, args) : s;
        }

        public static void Load() { int v; Lang = int.TryParse(Settings.Get("lang", "0"), out v) ? Math.Max(0, Math.Min(2, v)) : 0; }
        public static void Save() { Settings.Set("lang", Lang.ToString()); }
    }

    // %APPDATA%\YmirTool\settings.txt: key=value lines
    public static class Settings
    {
        public static string Dir { get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "YmirTool"); } }
        static string File { get { return Path.Combine(Dir, "settings.txt"); } }

        static Dictionary<string, string> Read()
        {
            var d = new Dictionary<string, string>();
            try
            {
                foreach (var line in System.IO.File.ReadAllLines(File))
                {
                    int i = line.IndexOf('=');
                    if (i > 0) d[line.Substring(0, i)] = line.Substring(i + 1);
                }
            }
            catch { }
            return d;
        }

        public static string Get(string key, string fallback)
        {
            string v;
            return Read().TryGetValue(key, out v) && v.Length > 0 ? v : fallback;
        }

        public static void Set(string key, string value)
        {
            try
            {
                var d = Read();
                d[key] = value ?? "";
                Directory.CreateDirectory(Dir);
                System.IO.File.WriteAllLines(File, d.Select(kv => kv.Key + "=" + kv.Value));
            }
            catch { }
        }

        // the game's WowB.exe: remembered, else the Forever launcher's game folder, else the usual Battle.net place
        public static string GameExe()
        {
            string saved = Get("game", "");
            if (System.IO.File.Exists(saved)) return saved;
            try
            {
                string launcher = System.IO.File.ReadAllText(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "ForeverLauncher", "gamedir.txt")).Trim();
                string exe = Path.Combine(launcher, "WowB.exe");
                if (System.IO.File.Exists(exe)) return exe;
            }
            catch { }
            return null;
        }
    }
}
