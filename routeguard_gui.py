#!/usr/bin/env python3
from __future__ import annotations

import json
import math
import os
import queue
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

from routeguard_core import (
    RouteGuardRunner,
    build_generated_config_from_wg,
    check_dependencies,
    remove_nft_rules,
    status_summary,
)


I18N = {
    "en": {
        "app_title": "RouteGuard Auto",
        "lang": "Language",
        "wg_config": "WireGuard config",
        "browse": "Browse",
        "iface_override": "Interface override",
        "mode": "Mode",
        "interval": "Interval (sec)",
        "allow_lan": "Allow LAN",
        "allow_dhcp": "Allow DHCP",
        "auto_up": "Auto wg-quick up",
        "auto_down": "Auto wg-quick down on stop",
        "cleanup_nft": "Cleanup nft on stop",
        "preview_btn": "Preview",
        "start_btn": "Start",
        "stop_btn": "Stop",
        "status_btn": "Status",
        "cleanup_btn": "Remove nft rules",
        "preview_tab": "Generated config",
        "logs_tab": "Logs",
        "ready": "Ready",
        "already_running_title": "Already running",
        "already_running_msg": "RouteGuard is already running in this GUI session.",
        "missing_deps_title": "Missing dependencies",
        "config_error_title": "Config error",
        "preview_error_title": "Preview error",
        "nft_error_title": "nft error",
        "generated_updated": "Generated config preview updated.",
        "start_requested": "Start requested.",
        "stop_requested": "Stop requested.",
        "no_running": "No running instance in this GUI session.",
        "status_label": "Status",
        "confirm_exit_title": "Exit",
        "confirm_exit_text": "Close the window and stop RouteGuard in this session?",
        "mode_monitor": "monitor",
        "mode_protect": "protect",
        "placeholder": "Select a WireGuard config and click Preview / Start",
        "status_idle": "Idle",
        "status_running": "Running",
        "status_stopping": "Stopping",
        "status_preview_ok": "Preview OK",
        "status_preview_error": "Preview error",
        "status_nft_present": "nft active",
        "status_nft_absent": "nft inactive",
        "status_nft_cleaned": "nft cleaned",
        "status_nft_error": "nft error",
        "section_setup": "Setup",
        "section_options": "Options",
        "section_actions": "Actions",
        "status_dot_label": "State",
        "footer_text": "CLI and GUI versions included",
    },
    "ru": {
        "app_title": "RouteGuard Auto",
        "lang": "Язык",
        "wg_config": "Конфиг WireGuard",
        "browse": "Выбрать",
        "iface_override": "Интерфейс (переопределить)",
        "mode": "Режим",
        "interval": "Интервал (сек)",
        "allow_lan": "Разрешить LAN",
        "allow_dhcp": "Разрешить DHCP",
        "auto_up": "Авто wg-quick up",
        "auto_down": "Авто wg-quick down при остановке",
        "cleanup_nft": "Очистить nft при остановке",
        "preview_btn": "Предпросмотр",
        "start_btn": "Старт",
        "stop_btn": "Стоп",
        "status_btn": "Статус",
        "cleanup_btn": "Удалить nft правила",
        "preview_tab": "Сгенерированный конфиг",
        "logs_tab": "Логи",
        "ready": "Готово",
        "already_running_title": "Уже запущено",
        "already_running_msg": "RouteGuard уже запущен в этой GUI-сессии.",
        "missing_deps_title": "Нет зависимостей",
        "config_error_title": "Ошибка конфигурации",
        "preview_error_title": "Ошибка предпросмотра",
        "nft_error_title": "Ошибка nft",
        "generated_updated": "Предпросмотр конфига обновлён.",
        "start_requested": "Запуск запрошен.",
        "stop_requested": "Остановка запрошена.",
        "no_running": "В этой GUI-сессии нет запущенного экземпляра.",
        "status_label": "Статус",
        "confirm_exit_title": "Выход",
        "confirm_exit_text": "Закрыть окно и остановить RouteGuard в этой сессии?",
        "mode_monitor": "monitor",
        "mode_protect": "protect",
        "placeholder": "Выберите WireGuard-конфиг и нажмите «Предпросмотр» / «Старт»",
        "status_idle": "Ожидание",
        "status_running": "Работает",
        "status_stopping": "Остановка",
        "status_preview_ok": "Предпросмотр OK",
        "status_preview_error": "Ошибка предпросмотра",
        "status_nft_present": "nft активен",
        "status_nft_absent": "nft не активен",
        "status_nft_cleaned": "nft очищен",
        "status_nft_error": "Ошибка nft",
        "section_setup": "Настройка",
        "section_options": "Параметры",
        "section_actions": "Действия",
        "status_dot_label": "Состояние",
        "footer_text": "Доступны CLI и GUI версии",
    },
}


class RouteGuardGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.lang = tk.StringVar(value='ru')
        self.title(I18N[self.lang.get()]["app_title"])
        self.geometry('1120x780')
        self.minsize(980, 680)

        self.log_q: 'queue.Queue[str]' = queue.Queue()
        self.runner = None
        self.worker = None
        self._txt_widgets: dict[str, list[tuple[object, str]]] = {}
        self._status_kind = 'idle'
        self._running_dots = 0
        self._anim_t = 0.0

        self._setup_style()
        self._init_vars()
        self._build_ui()
        self._apply_i18n()
        self.after(120, self._pump_logs)
        self.after(80, self._animate)
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def tr(self, key: str) -> str:
        return I18N.get(self.lang.get(), I18N['en']).get(key, key)

    def _setup_style(self):
        style = ttk.Style(self)
        try:
            style.theme_use('clam')
        except tk.TclError:
            pass

        self._colors = {
            'bg': '#f6f2ea'
            'panel': '#fffdf8',
            'panel_alt': '#f0e9dd',
            'surface': '#ffffff',
            'border': '#e3d8c8',
            'text': '#2b2a28',
            'muted': '#7a7368',
            'accent': '#3366cc',
            'accent_soft': '#eaf1ff',
            'success': '#2e8b57',
            'danger': '#c14d4d',
            'warning': '#b7791f',
            'shadow': '#efe7db',
            'log_bg': '#fbfaf6',
        }
        c = self._colors
        self.configure(bg=c['bg'])

        style.configure('.', background=c['bg'], foreground=c['text'], fieldbackground=c['surface'])
        style.configure('TFrame', background=c['bg'])
        style.configure('Card.TFrame', background=c['panel'], relief='flat', borderwidth=1)
        style.configure('CardInner.TFrame', background=c['panel'])
        style.configure('Header.TLabel', background=c['bg'], foreground=c['text'], font=('TkDefaultFont', 16, 'bold'))
        style.configure('Muted.TLabel', background=c['bg'], foreground=c['muted'])
        style.configure('CardTitle.TLabel', background=c['panel'], foreground=c['text'], font=('TkDefaultFont', 10, 'bold'))
        style.configure('TLabel', background=c['bg'], foreground=c['text'])

        style.configure('Field.TEntry', fieldbackground=c['surface'], foreground=c['text'], insertcolor=c['text'],
                        bordercolor=c['border'], lightcolor=c['border'], darkcolor=c['border'])
        style.configure('Field.TCombobox', fieldbackground=c['surface'], foreground=c['text'],
                        bordercolor=c['border'], lightcolor=c['border'], darkcolor=c['border'])
        style.map('Field.TCombobox', fieldbackground=[('readonly', c['surface'])], foreground=[('readonly', c['text'])])

        style.configure('Soft.TCheckbutton', background=c['panel'], foreground=c['text'])
        style.map('Soft.TCheckbutton', background=[('active', c['panel'])], foreground=[('active', c['text'])])

        style.configure('TNotebook', background=c['bg'], borderwidth=0)
        style.configure('TNotebook.Tab', background=c['panel_alt'], foreground=c['muted'], padding=(14, 8), borderwidth=0)
        style.map('TNotebook.Tab',
                  background=[('selected', c['panel'])],
                  foreground=[('selected', c['text'])])

        style.configure('Primary.TButton', background=c['accent'], foreground='white', padding=(12, 9), borderwidth=0)
        style.map('Primary.TButton', background=[('active', '#2957b5')])
        style.configure('Neutral.TButton', background=c['surface'], foreground=c['text'], padding=(10, 9), borderwidth=1)
        style.map('Neutral.TButton', background=[('active', '#f5f1ea')])
        style.configure('Danger.TButton', background='#f6eaea', foreground=c['danger'], padding=(10, 9), borderwidth=1)
        style.map('Danger.TButton', background=[('active', '#f3e0e0')])

    def _init_vars(self):
        self.wg_path = tk.StringVar(value='/etc/wireguard/wg0.conf')
        self.iface = tk.StringVar(value='')
        self.mode = tk.StringVar(value='monitor')
        self.interval = tk.StringVar(value='5')
        self.allow_lan = tk.BooleanVar(value=True)
        self.allow_dhcp = tk.BooleanVar(value=True)
        self.auto_up = tk.BooleanVar(value=False)
        self.auto_down = tk.BooleanVar(value=False)
        self.cleanup_nft = tk.BooleanVar(value=True)
        self.status_var = tk.StringVar(value='Idle')

    def _bind_text(self, key: str, widget, attr: str = 'text'):
        self._txt_widgets.setdefault(key, []).append((widget, attr))

    def _set_text(self, widget, attr: str, value: str):
        try:
            widget.configure(**{attr: value})
        except Exception:
            if attr == 'title' and hasattr(widget, 'configure'):
                try:
                    widget.configure(text=value)
                except Exception:
                    pass

    def _apply_i18n(self):
        self.title(self.tr('app_title'))
        for key, targets in self._txt_widgets.items():
            txt = self.tr(key)
            for widget, attr in targets:
                if isinstance(widget, ttk.Notebook) and attr.startswith('tab:'):
                    widget.tab(int(attr.split(':', 1)[1]), text=txt)
                else:
                    self._set_text(widget, attr, txt)
        self.mode_box.configure(values=['monitor', 'protect'])
        if self._status_kind == 'idle':
            self.status_var.set(self.tr('status_idle'))
        self._set_state_dot(self._status_kind)

    def _card(self, parent, row, col, title_key, padx=(0, 0), pady=(0, 0), rowspan=1, colspan=1, sticky='nsew'):
        outer = tk.Frame(parent, bg=self._colors['shadow'], highlightthickness=0)
        outer.grid(row=row, column=col, rowspan=rowspan, columnspan=colspan, sticky=sticky, padx=padx, pady=pady)
        inner = tk.Frame(outer, bg=self._colors['panel'], highlightbackground=self._colors['border'], highlightthickness=1)
        inner.pack(fill='both', expand=True)
        title = tk.Label(inner, text='', bg=self._colors['panel'], fg=self._colors['text'],
                         font=('TkDefaultFont', 10, 'bold'), anchor='w')
        title.pack(fill='x', padx=12, pady=(10, 6))
        self._bind_text(title_key, title)
        content = tk.Frame(inner, bg=self._colors['panel'])
        content.pack(fill='both', expand=True, padx=12, pady=(0, 12))
        return content, inner

    def _build_ui(self):
        c = self._colors
        root = tk.Frame(self, bg=c['bg'])
        root.pack(fill='both', expand=True, padx=18, pady=16)
        root.grid_columnconfigure(0, weight=11)
        root.grid_columnconfigure(1, weight=17)
        root.grid_rowconfigure(1, weight=1)

        header = tk.Frame(root, bg=c['bg'])
        header.grid(row=0, column=0, columnspan=2, sticky='ew', pady=(0, 12))
        header.grid_columnconfigure(0, weight=1)

        left_header = tk.Frame(header, bg=c['bg'])
        left_header.grid(row=0, column=0, sticky='w')
        title = tk.Label(left_header, text='', bg=c['bg'], fg=c['text'], font=('TkDefaultFont', 17, 'bold'))
        title.pack(anchor='w')
        self._bind_text('app_title', title)
        footer = tk.Label(left_header, text='', bg=c['bg'], fg=c['muted'])
        footer.pack(anchor='w', pady=(2, 0))
        self._bind_text('footer_text', footer)

        right_header = tk.Frame(header, bg=c['bg'])
        right_header.grid(row=0, column=1, sticky='e')
        lang_lbl = tk.Label(right_header, text='', bg=c['bg'], fg=c['muted'])
        lang_lbl.pack(side='left', padx=(0, 8))
        self._bind_text('lang', lang_lbl)
        self.lang_box = ttk.Combobox(right_header, textvariable=self.lang, values=['ru', 'en'], state='readonly', width=6, style='Field.TCombobox')
        self.lang_box.pack(side='left')
        self.lang_box.bind('<<ComboboxSelected>>', lambda _e: self._apply_i18n())

        left_col = tk.Frame(root, bg=c['bg'])
        left_col.grid(row=1, column=0, sticky='nsew', padx=(0, 10))
        left_col.grid_columnconfigure(0, weight=1)
        left_col.grid_rowconfigure(2, weight=1)

        setup_wrap, _ = self._card(left_col, 0, 0, 'section_setup', pady=(0, 10), sticky='ew')
        setup_wrap.grid_columnconfigure(1, weight=1)

        pad_y = 6
        tk.Label(setup_wrap, text='', bg=c['panel'], fg=c['text']).grid(row=0, column=0, sticky='w', pady=pad_y)
        self._bind_text('wg_config', setup_wrap.grid_slaves(row=0, column=0)[0])
        self.wg_entry = ttk.Entry(setup_wrap, textvariable=self.wg_path, style='Field.TEntry')
        self.wg_entry.grid(row=1, column=0, columnspan=2, sticky='ew', pady=(0, pad_y))
        self.browse_btn = ttk.Button(setup_wrap, style='Neutral.TButton', command=self._browse)
        self.browse_btn.grid(row=1, column=2, sticky='e', padx=(8, 0), pady=(0, pad_y))
        self._bind_text('browse', self.browse_btn)

        tk.Label(setup_wrap, text='', bg=c['panel'], fg=c['text']).grid(row=2, column=0, sticky='w', pady=pad_y)
        self._bind_text('iface_override', setup_wrap.grid_slaves(row=2, column=0)[0])
        self.iface_entry = ttk.Entry(setup_wrap, textvariable=self.iface, style='Field.TEntry')
        self.iface_entry.grid(row=3, column=0, columnspan=2, sticky='ew', pady=(0, pad_y))

        tk.Label(setup_wrap, text='', bg=c['panel'], fg=c['text']).grid(row=4, column=0, sticky='w', pady=pad_y)
        self._bind_text('mode', setup_wrap.grid_slaves(row=4, column=0)[0])
        self.mode_box = ttk.Combobox(setup_wrap, textvariable=self.mode, values=['monitor', 'protect'], width=14, state='readonly', style='Field.TCombobox')
        self.mode_box.grid(row=5, column=0, sticky='w', pady=(0, pad_y))

        tk.Label(setup_wrap, text='', bg=c['panel'], fg=c['text']).grid(row=4, column=1, sticky='w', padx=(10, 0), pady=pad_y)
        self._bind_text('interval', setup_wrap.grid_slaves(row=4, column=1)[0])
        self.interval_entry = ttk.Entry(setup_wrap, textvariable=self.interval, width=10, style='Field.TEntry')
        self.interval_entry.grid(row=5, column=1, sticky='w', padx=(10, 0), pady=(0, pad_y))

        options_wrap, _ = self._card(left_col, 1, 0, 'section_options', pady=(0, 10), sticky='ew')
        options_wrap.grid_columnconfigure(0, weight=1)
        options_wrap.grid_columnconfigure(1, weight=1)

        self.chk_allow_lan = ttk.Checkbutton(options_wrap, variable=self.allow_lan, style='Soft.TCheckbutton')
        self.chk_allow_lan.grid(row=0, column=0, sticky='w', pady=4)
        self._bind_text('allow_lan', self.chk_allow_lan)

        self.chk_allow_dhcp = ttk.Checkbutton(options_wrap, variable=self.allow_dhcp, style='Soft.TCheckbutton')
        self.chk_allow_dhcp.grid(row=0, column=1, sticky='w', pady=4)
        self._bind_text('allow_dhcp', self.chk_allow_dhcp)

        self.chk_auto_up = ttk.Checkbutton(options_wrap, variable=self.auto_up, style='Soft.TCheckbutton')
        self.chk_auto_up.grid(row=1, column=0, sticky='w', pady=4)
        self._bind_text('auto_up', self.chk_auto_up)

        self.chk_auto_down = ttk.Checkbutton(options_wrap, variable=self.auto_down, style='Soft.TCheckbutton')
        self.chk_auto_down.grid(row=1, column=1, sticky='w', pady=4)
        self._bind_text('auto_down', self.chk_auto_down)

        self.chk_cleanup_nft = ttk.Checkbutton(options_wrap, variable=self.cleanup_nft, style='Soft.TCheckbutton')
        self.chk_cleanup_nft.grid(row=2, column=0, columnspan=2, sticky='w', pady=4)
        self._bind_text('cleanup_nft', self.chk_cleanup_nft)

        actions_wrap, actions_card = self._card(left_col, 2, 0, 'section_actions', sticky='nsew')
        actions_wrap.grid_columnconfigure(0, weight=1)
        actions_wrap.grid_columnconfigure(1, weight=1)
        actions_wrap.grid_rowconfigure(3, weight=1)

        status_strip = tk.Frame(actions_wrap, bg=c['panel'])
        status_strip.grid(row=0, column=0, columnspan=2, sticky='ew', pady=(0, 8))
        status_strip.grid_columnconfigure(1, weight=1)
        self.status_dot = tk.Canvas(status_strip, width=20, height=20, bg=c['panel'], highlightthickness=0)
        self.status_dot.grid(row=0, column=0, sticky='w')
        self.status_oval = self.status_dot.create_oval(4, 4, 16, 16, fill=c['muted'], outline='')
        state_lbl = tk.Label(status_strip, text='', bg=c['panel'], fg=c['muted'])
        state_lbl.grid(row=0, column=1, sticky='w', padx=(8, 8))
        self._bind_text('status_dot_label', state_lbl)
        self.status_pill = tk.Label(status_strip, textvariable=self.status_var, bg=c['accent_soft'], fg=c['accent'],
                                    padx=10, pady=5, relief='flat')
        self.status_pill.grid(row=0, column=2, sticky='e')

        self.preview_btn = ttk.Button(actions_wrap, style='Neutral.TButton', command=self.preview_config)
        self.preview_btn.grid(row=1, column=0, sticky='ew', padx=(0, 6), pady=4)
        self._bind_text('preview_btn', self.preview_btn)
        self.status_btn = ttk.Button(actions_wrap, style='Neutral.TButton', command=self.show_status)
        self.status_btn.grid(row=1, column=1, sticky='ew', padx=(6, 0), pady=4)
        self._bind_text('status_btn', self.status_btn)

        self.start_btn = ttk.Button(actions_wrap, style='Primary.TButton', command=self.start_guard)
        self.start_btn.grid(row=2, column=0, sticky='ew', padx=(0, 6), pady=4)
        self._bind_text('start_btn', self.start_btn)
        self.stop_btn = ttk.Button(actions_wrap, style='Neutral.TButton', command=self.stop_guard)
        self.stop_btn.grid(row=2, column=1, sticky='ew', padx=(6, 0), pady=4)
        self._bind_text('stop_btn', self.stop_btn)

        self.cleanup_btn = ttk.Button(actions_wrap, style='Danger.TButton', command=self.remove_nft)
        self.cleanup_btn.grid(row=3, column=0, columnspan=2, sticky='sew', pady=(8, 0))
        self._bind_text('cleanup_btn', self.cleanup_btn)

        right_col = tk.Frame(root, bg=c['bg'])
        right_col.grid(row=1, column=1, sticky='nsew')
        right_col.grid_columnconfigure(0, weight=1)
        right_col.grid_rowconfigure(0, weight=1)

        notebook_card_shadow = tk.Frame(right_col, bg=c['shadow'])
        notebook_card_shadow.grid(row=0, column=0, sticky='nsew')
        notebook_frame = tk.Frame(notebook_card_shadow, bg=c['panel'], highlightbackground=c['border'], highlightthickness=1)
        notebook_frame.pack(fill='both', expand=True)
        notebook = ttk.Notebook(notebook_frame)
        notebook.pack(fill='both', expand=True, padx=8, pady=8)

        preview_tab = tk.Frame(notebook, bg=c['panel'])
        logs_tab = tk.Frame(notebook, bg=c['panel'])
        preview_tab.grid_rowconfigure(0, weight=1)
        preview_tab.grid_columnconfigure(0, weight=1)
        logs_tab.grid_rowconfigure(0, weight=1)
        logs_tab.grid_columnconfigure(0, weight=1)
        notebook.add(preview_tab, text='')
        notebook.add(logs_tab, text='')
        self._bind_text('preview_tab', notebook, 'tab:0')
        self._bind_text('logs_tab', notebook, 'tab:1')

        self.preview = scrolledtext.ScrolledText(
            preview_tab, height=12, wrap='none', bg=c['log_bg'], fg=c['text'], insertbackground=c['text'],
            relief='flat', borderwidth=0, padx=10, pady=10
        )
        self.preview.grid(row=0, column=0, sticky='nsew')
        self.preview.insert('1.0', self.tr('placeholder') + '\n')
        self.preview.configure(state='disabled')

        self.logs = scrolledtext.ScrolledText(
            logs_tab, height=18, wrap='word', bg=c['log_bg'], fg=c['text'], insertbackground=c['text'],
            relief='flat', borderwidth=0, padx=10, pady=10
        )
        self.logs.grid(row=0, column=0, sticky='nsew')
        self.logs.configure(state='disabled')

        self._set_status(self.tr('status_idle'), kind='idle')
        self._log(self.tr('ready'))

    def _set_state_dot(self, kind: str):
        c = self._colors
        self._status_kind = kind
        palette = {
            'idle': (c['muted'], c['panel_alt'], c['muted']),
            'running': (c['success'], '#dff3e7', c['success']),
            'warn': (c['warning'], '#f7edd8', c['warning']),
            'error': (c['danger'], '#f8e6e6', c['danger']),
        }
        dot, pill_bg, pill_fg = palette.get(kind, palette['idle'])
        self.status_dot.itemconfig(self.status_oval, fill=dot)
        self.status_pill.configure(bg=pill_bg, fg=pill_fg)

    def _set_status(self, text: str, kind: str | None = None):
        if kind is not None:
            self._set_state_dot(kind)
        self.status_var.set(text)

    def _animate(self):
        self._anim_t += 0.16
        kind = self._status_kind
        if kind in ('running', 'warn'):
            pulse = 0.55 + 0.45 * (0.5 + 0.5 * math.sin(self._anim_t))
            base = {'running': '#2e8b57', 'warn': '#b7791f'}[kind]
            glow = {'running': '#8fd4ae', 'warn': '#e7c27a'}[kind]
            fill = self._mix_hex(base, glow, pulse)
            self.status_dot.itemconfig(self.status_oval, fill=fill)
        elif kind == 'error':
            pulse = 0.25 + 0.25 * (0.5 + 0.5 * math.sin(self._anim_t * 0.6))
            fill = self._mix_hex('#c14d4d', '#efb1b1', pulse)
            self.status_dot.itemconfig(self.status_oval, fill=fill)
        else:
            self.status_dot.itemconfig(self.status_oval, fill=self._colors['muted'])

        if kind in ('running', 'warn'):
            base = self.tr('status_running') if kind == 'running' else self.tr('status_stopping')
            self._running_dots = (self._running_dots + 1) % 4
            self.status_var.set(base + '.' * self._running_dots)
        self.after(120, self._animate)

    @staticmethod
    def _mix_hex(a: str, b: str, t: float) -> str:
        t = max(0.0, min(1.0, t))
        def _p(x):
            x = x.lstrip('#')
            return int(x[0:2], 16), int(x[2:4], 16), int(x[4:6], 16)
        ar, ag, ab = _p(a)
        br, bg, bb = _p(b)
        r = int(ar + (br - ar) * t)
        g = int(ag + (bg - ag) * t)
        bl = int(ab + (bb - ab) * t)
        return f'#{r:02x}{g:02x}{bl:02x}'

    @property
    def logs_empty(self) -> bool:
        try:
            return self.logs.index('end-1c') == '1.0'
        except Exception:
            return True

    def _browse(self):
        p = filedialog.askopenfilename(filetypes=[('WireGuard config', '*.conf'), ('All files', '*.*')])
        if p:
            self.wg_path.set(p)
            self._set_status(os.path.basename(p), kind='idle')

    def _log(self, msg: str):
        self.logs.configure(state='normal')
        ts = time.strftime('%H:%M:%S')
        self.logs.insert('end', f'[{ts}] {msg.rstrip()}\n')
        self.logs.see('end')
        self.logs.configure(state='disabled')

    def _enqueue_log(self, msg: str):
        self.log_q.put(msg)

    def _pump_logs(self):
        try:
            while True:
                msg = self.log_q.get_nowait()
                if msg == '__RG_UI__STOPPED__':
                    self._set_status(self.tr('status_idle'), kind='idle')
                    self._log('RouteGuard session ended.')
                    continue
                self._log(msg)
                m = msg.lower()
                if m.startswith('error:'):
                    self._set_status(self.tr('status_nft_error'), kind='error')
                elif 'applied nftables rules' in m:
                    self._set_status(self.tr('status_nft_present'), kind='running')
        except queue.Empty:
            pass
        self.after(120, self._pump_logs)

    def _cfg(self):
        try:
            interval = int((self.interval.get() or '5').strip())
        except ValueError:
            raise ValueError('Interval must be an integer / Интервал должен быть целым числом')
        return build_generated_config_from_wg(
            self.wg_path.get().strip(),
            mode=self.mode.get(),
            vpn_iface=(self.iface.get().strip() or None),
            allow_lan=self.allow_lan.get(),
            allow_dhcp=self.allow_dhcp.get(),
            poll_interval_sec=interval,
        )

    def preview_config(self):
        try:
            cfg = self._cfg()
            text = cfg.to_json()
            self.preview.configure(state='normal')
            self.preview.delete('1.0', 'end')
            self.preview.insert('1.0', text)
            self.preview.configure(state='disabled')
            self._log(self.tr('generated_updated'))
            self._set_status(self.tr('status_preview_ok'), kind='idle')
        except Exception as e:
            messagebox.showerror(self.tr('preview_error_title'), str(e))
            self._set_status(self.tr('status_preview_error'), kind='error')

    def start_guard(self):
        if self.worker and self.worker.is_alive():
            messagebox.showinfo(self.tr('already_running_title'), self.tr('already_running_msg'))
            return
        missing = check_dependencies(require_tk=False)
        if missing:
            messagebox.showerror(self.tr('missing_deps_title'), ', '.join(missing))
            self._set_status(self.tr('missing_deps_title'), kind='error')
            return
        try:
            cfg = self._cfg()
        except Exception as e:
            messagebox.showerror(self.tr('config_error_title'), str(e))
            self._set_status(self.tr('config_error_title'), kind='error')
            return

        self.runner = RouteGuardRunner(
            cfg,
            logger=self._enqueue_log,
            auto_up_vpn=self.auto_up.get(),
            auto_down_vpn_on_exit=self.auto_down.get(),
            cleanup_nft_on_exit=self.cleanup_nft.get(),
        )

        self._set_status(self.tr('status_running'), kind='running')

        def _work():
            try:
                rc = self.runner.run()
                self._enqueue_log(f'RouteGuard stopped with code {rc}.')
            except Exception as e:
                self._enqueue_log('ERROR: ' + str(e))
            finally:
                self.log_q.put('__RG_UI__STOPPED__')

        self.worker = threading.Thread(target=_work, daemon=True)
        self.worker.start()
        self._log(self.tr('start_requested'))

    def stop_guard(self):
        if self.runner:
            self.runner.request_stop()
            self._log(self.tr('stop_requested'))
            self._set_status(self.tr('status_stopping'), kind='warn')
        else:
            self._log(self.tr('no_running'))

    def show_status(self):
        try:
            st = status_summary()
            self._log(self.tr('status_label') + ':\n' + json.dumps(st, indent=2, ensure_ascii=False))
            present = bool(st.get('routeguard_nft_table_present'))
            self._set_status(self.tr('status_nft_present') if present else self.tr('status_nft_absent'),
                             kind='running' if present else 'idle')
        except Exception as e:
            self._log('Status error: ' + str(e))
            self._set_status('Status error', kind='error')

    def remove_nft(self):
        try:
            remove_nft_rules(logger=self._enqueue_log)
            self._set_status(self.tr('status_nft_cleaned'), kind='idle')
        except Exception as e:
            messagebox.showerror(self.tr('nft_error_title'), str(e))
            self._set_status(self.tr('status_nft_error'), kind='error')

    def on_close(self):
        if self.worker and self.worker.is_alive():
            if not messagebox.askyesno(self.tr('confirm_exit_title'), self.tr('confirm_exit_text')):
                return
            if self.runner:
                self.runner.request_stop()
        self.destroy()

    def destroy(self):
        try:
            if self.runner:
                self.runner.request_stop()
        finally:
            super().destroy()


if __name__ == '__main__':
    app = RouteGuardGUI()
    app.mainloop()
