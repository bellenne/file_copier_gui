import os
import json
import shutil
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from queue import Queue, Empty
import tkinter as tk
from tkinter import ttk, filedialog, messagebox


APP_NAME = "File Copier"
SETTINGS_FILE = "settings.json"


def safe_mkdir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def user_data_dir() -> Path:
    # %APPDATA%\File Copier
    appdata = os.environ.get("APPDATA") or str(Path.home())
    return Path(appdata) / APP_NAME


def load_settings() -> dict:
    d = user_data_dir()
    safe_mkdir(d)
    fp = d / SETTINGS_FILE
    if not fp.exists():
        return {"server_root": ""}
    try:
        return json.loads(fp.read_text(encoding="utf-8"))
    except Exception:
        return {"server_root": ""}


def save_settings(data: dict) -> None:
    d = user_data_dir()
    safe_mkdir(d)
    fp = d / SETTINGS_FILE
    fp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def normalize_list_name(raw: str) -> str:
    """
    В списке у тебя строки типа:
      260130-...-XGV_POUF_LID,
    То есть может быть хвостовая запятая, кавычки, пробелы.
    """
    s = (raw or "").strip()
    if not s:
        return ""
    # убрать кавычки по краям
    if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
        s = s[1:-1].strip()
    # убрать хвостовые запятые/точки с запятой
    s = s.rstrip(",;")
    return s.strip()


def read_names_from_file(path: Path) -> list[str]:
    # Поддерживаем: txt/csv/любое, читаем построчно
    text = path.read_text(encoding="utf-8", errors="ignore")
    names: list[str] = []
    for line in text.splitlines():
        n = normalize_list_name(line)
        if n:
            names.append(n)
    # У тебя без дублей, но на всякий случай сохраним порядок и уберём дубли
    seen = set()
    uniq: list[str] = []
    for n in names:
        if n in seen:
            continue
        seen.add(n)
        uniq.append(n)
    return uniq


def file_stem(p: Path) -> str:
    # "name.ext" -> "name"
    return p.stem


def is_unc_path(p: str) -> bool:
    return p.startswith("\\\\")


def path_exists_fast(p: Path) -> bool:
    try:
        return p.exists()
    except OSError:
        return False


@dataclass
class FoundFile:
    stem: str
    path: Path


class FinderCopier:
    def __init__(
        self,
        server_root: Path,
        dest_dir: Path,
        delete_after: bool,
        log_q: Queue,
        progress_q: Queue,
        stop_event: threading.Event,
    ):
        self.server_root = server_root
        self.dest_dir = dest_dir
        self.delete_after = delete_after
        self.log_q = log_q
        self.progress_q = progress_q
        self.stop_event = stop_event

        self.found: dict[str, Path] = {}
        self.missing: list[str] = []
        self.copied: list[str] = []
        self.overwritten: list[str] = []
        self.errors: list[tuple[str, str]] = []

    def log(self, msg: str) -> None:
        self.log_q.put(msg)

    def set_progress(self, done: int, total: int) -> None:
        self.progress_q.put((done, total))

    def scan_root_fast(self, needed: set[str]) -> None:
        # 1) Быстро смотрим только файлы в корне
        try:
            for entry in os.scandir(self.server_root):
                if self.stop_event.is_set():
                    return
                if not entry.is_file():
                    continue
                p = Path(entry.path)
                st = p.stem
                if st in needed and st not in self.found:
                    self.found[st] = p
        except Exception as e:
            self.log(f"Ошибка доступа к корню: {e}")
            raise

    def walk_subdirs_until_found(self, needed: set[str]) -> None:
        # 2) Один проход по подпапкам, досрочно выходим, когда нашли всё
        remaining = needed - set(self.found.keys())
        if not remaining:
            return

        for root, dirs, files in os.walk(self.server_root):
            if self.stop_event.is_set():
                return

            # пропускаем сам корень — мы его уже сканировали
            # os.walk начнёт с корня, так что можно пропустить первый проход
            # но дешевле просто проверить:
            # (не критично, но ок)
            # if Path(root) == self.server_root:
            #     continue

            for fn in files:
                if self.stop_event.is_set():
                    return
                st = Path(fn).stem
                if st in remaining and st not in self.found:
                    self.found[st] = Path(root) / fn
                    remaining.remove(st)
                    if not remaining:
                        return  # нашли всё

    def choose_destination_name(self, src: Path) -> Path:
        # Не сохраняем структуру подпапок, просто кладём в dest с исходным именем
        return self.dest_dir / src.name

    def copy_one(self, stem: str, src: Path) -> None:
        dst = self.choose_destination_name(src)

        try:
            # ensure dest exists
            safe_mkdir(self.dest_dir)

            overwritten = dst.exists()
            # copy2 сохраняет метаданные (даты) — удобно
            shutil.copy2(src, dst)

            if overwritten:
                self.overwritten.append(stem)

            self.copied.append(stem)
            self.log(f"✅ Скопировано: {src} -> {dst}")

            if self.delete_after:
                try:
                    src.unlink()
                    self.log(f"🗑️ Удалено с сервера: {src}")
                except Exception as de:
                    self.errors.append((stem, f"Не смог удалить: {de}"))
                    self.log(f"⚠️ Не смог удалить {src}: {de}")

        except Exception as e:
            self.errors.append((stem, str(e)))
            self.log(f"❌ Ошибка копирования {src}: {e}")

    def write_report(self, list_file: Path) -> Path:
        report_dir = user_data_dir() / "reports"
        safe_mkdir(report_dir)

        ts = time.strftime("%Y%m%d-%H%M%S")
        report_path = report_dir / f"report_{ts}.txt"

        total = 0
        try:
            total = len(read_names_from_file(list_file))
        except Exception:
            pass

        lines = []
        lines.append(f"Отчёт: {ts}")
        lines.append(f"Список: {list_file}")
        lines.append(f"Сервер: {self.server_root}")
        lines.append(f"Назначение: {self.dest_dir}")
        lines.append(f"Удалять после копирования: {'ДА' if self.delete_after else 'НЕТ'}")
        lines.append("")
        lines.append(f"Итого в списке: {total}")
        lines.append(f"Найдено: {len(self.found)}")
        lines.append(f"Скопировано: {len(self.copied)}")
        lines.append(f"Перезаписано: {len(self.overwritten)}")
        lines.append(f"Не найдено: {len(self.missing)}")
        lines.append(f"Ошибок: {len(self.errors)}")
        lines.append("")

        if self.missing:
            lines.append("Не найдено:")
            for n in self.missing:
                lines.append(f"- Изображение {n} не найдено, свяжитесь с дизайнерами для загрузки")
            lines.append("")

        if self.errors:
            lines.append("Ошибки:")
            for stem, err in self.errors:
                lines.append(f"- {stem}: {err}")
            lines.append("")

        report_path.write_text("\n".join(lines), encoding="utf-8")
        return report_path

    def run(self, names: list[str], list_file: Path) -> dict:
        total = len(names)
        self.set_progress(0, total)

        if total == 0:
            self.log("Список пуст.")
            return {
                "total": 0,
                "found": 0,
                "copied": 0,
                "missing": 0,
                "overwritten": 0,
                "report_path": "",
            }

        needed = set(names)

        # Проверка доступа к серверу
        if not path_exists_fast(self.server_root):
            raise RuntimeError(f"Папка на сервере недоступна: {self.server_root}")

        self.log(f"Сканирую корень: {self.server_root}")
        self.scan_root_fast(needed)

        remaining = needed - set(self.found.keys())
        if remaining:
            self.log(f"В корне не найдено {len(remaining)} — ищу в подпапках...")
            self.walk_subdirs_until_found(needed)

        # now copy in original list order
        done = 0
        for stem in names:
            if self.stop_event.is_set():
                self.log("Остановлено пользователем.")
                break

            src = self.found.get(stem)
            if not src:
                self.missing.append(stem)
                self.log(f"⚠️ Изображение {stem} не найдено, свяжитесь с дизайнерами для загрузки")
            else:
                self.copy_one(stem, src)

            done += 1
            self.set_progress(done, total)

        report_path = self.write_report(list_file)
        self.log(f"📄 Отчёт сохранён: {report_path}")

        return {
            "total": total,
            "found": len(self.found),
            "copied": len(self.copied),
            "missing": len(self.missing),
            "overwritten": len(self.overwritten),
            "report_path": str(report_path),
        }


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Копирование файлов с сервера")
        self.geometry("820x520")
        self.minsize(760, 480)

        self.settings = load_settings()

        self.list_file_var = tk.StringVar(value="")
        self.server_root_var = tk.StringVar(value=self.settings.get("server_root", ""))
        self.dest_dir_var = tk.StringVar(value="")
        self.delete_after_var = tk.BooleanVar(value=False)

        self.status_var = tk.StringVar(value="Готово.")
        self.progress_var = tk.DoubleVar(value=0.0)

        self.log_q: Queue = Queue()
        self.progress_q: Queue = Queue()

        self.worker_thread: threading.Thread | None = None
        self.stop_event = threading.Event()

        self._build_ui()
        self._poll_queues()

    def _build_ui(self):
        pad = {"padx": 10, "pady": 6}

        top = ttk.Frame(self)
        top.pack(fill="x", padx=12, pady=10)

        # Row: list file
        row1 = ttk.Frame(top)
        row1.pack(fill="x", **pad)
        ttk.Label(row1, text="Файл-список:").pack(side="left")
        ttk.Entry(row1, textvariable=self.list_file_var).pack(side="left", fill="x", expand=True, padx=8)
        ttk.Button(row1, text="Выбрать…", command=self.pick_list_file).pack(side="left")

        # Row: server root
        row2 = ttk.Frame(top)
        row2.pack(fill="x", **pad)
        ttk.Label(row2, text="Папка на сервере (UNC):").pack(side="left")
        ttk.Entry(row2, textvariable=self.server_root_var).pack(side="left", fill="x", expand=True, padx=8)
        ttk.Button(row2, text="…", command=self.pick_server_root).pack(side="left")

        # Row: dest
        row3 = ttk.Frame(top)
        row3.pack(fill="x", **pad)
        ttk.Label(row3, text="Куда сохранить:").pack(side="left")
        ttk.Entry(row3, textvariable=self.dest_dir_var).pack(side="left", fill="x", expand=True, padx=8)
        ttk.Button(row3, text="Выбрать…", command=self.pick_dest_dir).pack(side="left")

        # Options
        row4 = ttk.Frame(top)
        row4.pack(fill="x", **pad)
        ttk.Checkbutton(row4, text="Удалить после копирования (с сервера)", variable=self.delete_after_var).pack(side="left")

        # Actions
        row5 = ttk.Frame(top)
        row5.pack(fill="x", **pad)
        self.btn_start = ttk.Button(row5, text="Старт", command=self.start)
        self.btn_start.pack(side="left")
        self.btn_stop = ttk.Button(row5, text="Стоп", command=self.stop, state="disabled")
        self.btn_stop.pack(side="left", padx=8)

        # Progress + status
        mid = ttk.Frame(self)
        mid.pack(fill="x", padx=12)
        self.pb = ttk.Progressbar(mid, variable=self.progress_var, maximum=100.0)
        self.pb.pack(fill="x", pady=6)
        ttk.Label(mid, textvariable=self.status_var).pack(anchor="w", pady=2)

        # Log area
        bottom = ttk.Frame(self)
        bottom.pack(fill="both", expand=True, padx=12, pady=10)

        ttk.Label(bottom, text="Лог:").pack(anchor="w")
        self.txt = tk.Text(bottom, height=12, wrap="word")
        self.txt.pack(fill="both", expand=True, side="left")
        scr = ttk.Scrollbar(bottom, command=self.txt.yview)
        scr.pack(fill="y", side="right")
        self.txt.configure(yscrollcommand=scr.set)

        # hints
        self._log_line("Подсказка: укажи UNC путь вида \\\\SERVER\\share\\folder")

    def _log_line(self, s: str) -> None:
        self.txt.insert("end", s + "\n")
        self.txt.see("end")

    def pick_list_file(self):
        p = filedialog.askopenfilename(
            title="Выбери файл со списком",
            filetypes=[("Text files", "*.txt *.csv *.log"), ("All files", "*.*")],
        )
        if p:
            self.list_file_var.set(p)

    def pick_dest_dir(self):
        p = filedialog.askdirectory(title="Куда сохранить файлы")
        if p:
            self.dest_dir_var.set(p)

    def pick_server_root(self):
        # tkinter не умеет выбирать UNC "папку" напрямую идеально, но askdirectory обычно работает.
        p = filedialog.askdirectory(title="Выбери папку на сервере (UNC)")
        if p:
            self.server_root_var.set(p)

    def validate_inputs(self) -> tuple[Path, Path, Path, bool]:
        list_file = Path(self.list_file_var.get().strip())
        if not list_file.exists() or not list_file.is_file():
            raise ValueError("Укажи корректный файл-список.")

        server_root_str = self.server_root_var.get().strip()
        if not server_root_str:
            raise ValueError("Укажи UNC папку на сервере.")
        # Allow non-UNC too, but warn; user explicitly uses \\...
        if not is_unc_path(server_root_str):
            # still ok; could be mapped drive like Z:\...
            pass
        server_root = Path(server_root_str)

        dest_dir_str = self.dest_dir_var.get().strip()
        if not dest_dir_str:
            raise ValueError("Укажи папку назначения (куда сохранить).")
        dest_dir = Path(dest_dir_str)

        delete_after = bool(self.delete_after_var.get())
        return list_file, server_root, dest_dir, delete_after

    def start(self):
        if self.worker_thread and self.worker_thread.is_alive():
            return

        try:
            list_file, server_root, dest_dir, delete_after = self.validate_inputs()
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))
            return

        # persist server root
        self.settings["server_root"] = str(server_root)
        save_settings(self.settings)

        # read names
        try:
            names = read_names_from_file(list_file)
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не смог прочитать список: {e}")
            return

        self.txt.delete("1.0", "end")
        self._log_line(f"Файл-список: {list_file}")
        self._log_line(f"Сервер: {server_root}")
        self._log_line(f"Назначение: {dest_dir}")
        self._log_line(f"Удалять после копирования: {'ДА' if delete_after else 'НЕТ'}")
        self._log_line(f"Элементов в списке: {len(names)}")
        self._log_line("-----")

        self.progress_var.set(0.0)
        self.status_var.set("Запуск...")
        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.stop_event.clear()

        def worker():
            try:
                fc = FinderCopier(
                    server_root=server_root,
                    dest_dir=dest_dir,
                    delete_after=delete_after,
                    log_q=self.log_q,
                    progress_q=self.progress_q,
                    stop_event=self.stop_event,
                )
                res = fc.run(names, list_file)
                self.log_q.put(
                    f"✅ Готово. found={res['found']} copied={res['copied']} missing={res['missing']} overwritten={res['overwritten']}"
                )
                self.log_q.put(f"Отчёт: {res['report_path']}")
            except Exception as e:
                self.log_q.put(f"❌ Фатальная ошибка: {e}")
            finally:
                self.progress_q.put(("done", None))

        self.worker_thread = threading.Thread(target=worker, daemon=True)
        self.worker_thread.start()

    def stop(self):
        if self.worker_thread and self.worker_thread.is_alive():
            self.stop_event.set()
            self.status_var.set("Остановка...")
            self._log_line("Запрошена остановка...")

    def _poll_queues(self):
        # logs
        try:
            while True:
                msg = self.log_q.get_nowait()
                self._log_line(msg)
        except Empty:
            pass

        # progress
        try:
            while True:
                item = self.progress_q.get_nowait()
                if isinstance(item, tuple) and item[0] == "done":
                    self.btn_start.configure(state="normal")
                    self.btn_stop.configure(state="disabled")
                    self.status_var.set("Готово.")
                    continue

                done, total = item
                if isinstance(done, int) and isinstance(total, int) and total > 0:
                    pct = (done / total) * 100.0
                    self.progress_var.set(pct)
                    self.status_var.set(f"Обработано: {done}/{total}")
        except Empty:
            pass

        self.after(120, self._poll_queues)


if __name__ == "__main__":
    # Важно: на некоторых системах ttk выглядит лучше с темой "clam"
    try:
        app = App()
        style = ttk.Style()
        if "clam" in style.theme_names():
            style.theme_use("clam")
        app.mainloop()
    except Exception as e:
        messagebox.showerror("Ошибка запуска", str(e))
