"""
FreePBX Monitoring Dashboard — Backend
Запускается на том же сервере что и FreePBX.
Порт по умолчанию: 8080
"""

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional
import subprocess
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
import re
import os
import sqlite3
import zipfile
import io

# Попытка импорта mysql — если не установлен, запросы к CDR будут недоступны
try:
    import mysql.connector
    MYSQL_AVAILABLE = True
except ImportError:
    MYSQL_AVAILABLE = False

app = FastAPI(title="FreePBX Dashboard", docs_url=None, redoc_url=None)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Пути и константы ────────────────────────────────────────────────────────

RECORDINGS_PATH = Path("/var/spool/asterisk/monitor")
ASTERISK_LOG    = Path("/var/log/asterisk/full")
FAIL2BAN_LOCAL  = Path("/etc/fail2ban/jail.local")
FAIL2BAN_CONF   = Path("/etc/fail2ban/jail.conf")
STATIC_DIR      = Path(__file__).parent / "static"
CDR_DATABASE    = "asteriskcdrdb"
CDR_TABLE       = "cdr"

# ─── Вспомогательные функции ─────────────────────────────────────────────────

def run(cmd: str, timeout: int = 15) -> tuple[str, str]:
    """Выполнить shell-команду, вернуть (stdout, stderr)."""
    result = subprocess.run(
        cmd, shell=True, capture_output=True, text=True, timeout=timeout
    )
    return result.stdout, result.stderr


def asterisk(cmd: str) -> str:
    """Выполнить команду в Asterisk CLI."""
    out, _ = run(f'asterisk -rx "{cmd}"')
    return out


def get_mysql_creds() -> tuple[str, str, str]:
    """
    Читаем учётные данные MySQL из конфига FreePBX.
    FreePBX использует PHP-синтаксис:
        $amp_conf["AMPDBUSER"] = "freepbxuser";
        $amp_conf["AMPDBPASS"] = "secret";
    Возвращаем (user, password, dbname).
    """
    for path in ["/etc/freepbx.conf", "/etc/asterisk/freepbx.conf"]:
        try:
            content = Path(path).read_text()

            # PHP-формат: $amp_conf["KEY"] = "VALUE";
            user = re.search(r'\["AMPDBUSER"\]\s*=\s*"([^"]+)"', content)
            pwd  = re.search(r'\["AMPDBPASS"\]\s*=\s*"([^"]*)"', content)
            db   = re.search(r'\["AMPDBNAME"\]\s*=\s*"([^"]+)"', content)

            if user:
                return (
                    user.group(1),
                    pwd.group(1) if pwd else "",
                    db.group(1)  if db  else "asterisk",
                )
        except FileNotFoundError:
            continue
    return "root", "", "asterisk"


def get_cdr_database(user: str, pwd: str, main_db: str) -> str:
    """
    Определяем в какой базе лежит таблица cdr.
    FreePBX может хранить CDR либо в отдельной базе asteriskcdrdb,
    либо прямо в основной базе (asterisk).
    """
    for db in ["asteriskcdrdb", main_db]:
        try:
            conn = mysql.connector.connect(
                host="localhost", user=user, password=pwd,
                database=db, connection_timeout=3,
            )
            cur = conn.cursor()
            cur.execute("SELECT 1 FROM cdr LIMIT 1")
            cur.fetchall()
            cur.close()
            conn.close()
            return db          # нашли — возвращаем эту базу
        except Exception:
            continue
    return "asteriskcdrdb"     # fallback


# Кэшируем чтобы не читать конфиг при каждом запросе
_creds_cache: tuple | None = None


def mysql_query(sql: str, params: list = None) -> list[dict]:
    """Выполнить SELECT-запрос к MySQL CDR базе, вернуть список dict."""
    global _creds_cache

    if not MYSQL_AVAILABLE:
        raise RuntimeError("mysql-connector-python не установлен")

    if _creds_cache is None:
        user, pwd, main_db = get_mysql_creds()
        cdr_db = get_cdr_database(user, pwd, main_db)
        _creds_cache = (user, pwd, cdr_db)

    user, pwd, cdr_db = _creds_cache

    conn = mysql.connector.connect(
        host="localhost",
        user=user,
        password=pwd,
        database=cdr_db,
        connection_timeout=5,
    )
    cursor = conn.cursor(dictionary=True)
    cursor.execute(sql, params or [])
    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    # Сериализуем datetime → строки, timedelta → секунды
    from decimal import Decimal as _Decimal
    for row in rows:
        for k, v in row.items():
            if isinstance(v, datetime):
                row[k] = v.strftime("%Y-%m-%d %H:%M:%S")
            elif isinstance(v, timedelta):
                row[k] = int(v.total_seconds())
            elif isinstance(v, _Decimal):
                row[k] = float(v)   # Decimal → float для JSON-сериализации
    return rows


# ─── /api/server/info ────────────────────────────────────────────────────────

@app.get("/api/server/info")
def server_info():
    hostname, _ = run("hostname")
    uptime, _   = run("uptime -p")
    version     = asterisk("core show version")
    load, _     = run("cat /proc/loadavg")

    # Определяем к какой базе подключаемся
    db_info = "не настроено"
    try:
        user, pwd, main_db = get_mysql_creds()
        cdr_db = get_cdr_database(user, pwd, main_db)
        db_info = f"{user}@localhost/{cdr_db}"
    except Exception as e:
        db_info = f"ошибка: {e}"

    return {
        "hostname":         hostname.strip(),
        "uptime":           uptime.strip().replace("up ", ""),
        "asterisk_version": version.strip().split("\n")[0],
        "load":             load.strip().split()[:3],
        "db_info":          db_info,
        "timestamp":        datetime.now().isoformat(),
    }


# ─── /api/trunks ─────────────────────────────────────────────────────────────

def parse_pjsip_registrations(output: str) -> dict:
    """
    Разбирает вывод 'pjsip show registrations'.
    Строки выглядят так:
      trunkname/sip:server.com:5060   auth   Registered
    Возвращает dict {name: {status, server}}
    """
    result = {}
    for line in output.splitlines():
        # Пропускаем заголовки и разделители
        stripped = line.strip()
        if not stripped or stripped.startswith("<") or stripped.startswith("="):
            continue
        # Формат: name/uri   auth   Status
        match = re.match(r"^(\S+?)/(\S+)\s+\S+\s+(\S.*?)$", stripped)
        if match:
            name   = match.group(1)
            server = match.group(2)
            status = match.group(3).strip()
            result[name] = {"status": status, "server": server}
    return result


def parse_active_channels(output: str) -> dict:
    """
    Разбирает 'core show channels concise' — поля разделены '!'.
    Формат: Channel!Context!Exten!Prio!App!AppData!CallerID!...
    Возвращает dict {trunk_name: [список каналов]}
    """
    channels = {}
    for line in output.splitlines():
        if not line.strip():
            continue
        parts = line.split("!")
        if len(parts) < 2:
            continue
        channel = parts[0].strip()
        # Каналы PJSIP транков: PJSIP/trunkname-XXXXXXXX
        m = re.match(r"^PJSIP/([^-]+)-", channel)
        if m:
            trunk = m.group(1)
            channels.setdefault(trunk, []).append({
                "channel":   channel,
                "extension": parts[2].strip() if len(parts) > 2 else "",
                "callerid":  parts[6].strip() if len(parts) > 6 else "",
            })
    return channels


def parse_endpoints(output: str) -> list[str]:
    """
    Из 'pjsip show endpoints' берём только имена реальных транков.
    Фильтруем операторские экстеншены двух форматов:
      - чисто числовые:     "101", "2880"
      - числовые с /aor:    "1010/1010", "2880/2880"
    Реальные транки имеют текстовые имена: "abuasi", "trunk_rt" и т.п.
    """
    names = []
    for line in output.splitlines():
        m = re.match(r"^\s*Endpoint:\s+(\S+)", line)
        if m:
            name = m.group(1)
            if not re.match(r"^\d+(/\d+)?$", name):
                names.append(name)
    return names


@app.get("/api/trunks")
def get_trunks():
    reg_out      = asterisk("pjsip show registrations")
    channels_out = asterisk("core show channels concise")
    ep_out       = asterisk("pjsip show endpoints")

    registrations    = parse_pjsip_registrations(reg_out)
    channels_by_trunk = parse_active_channels(channels_out)
    endpoint_names   = parse_endpoints(ep_out)

    # Объединяем: транки из регистраций + транки из эндпоинтов (без дублей)
    all_trunk_names = list({*registrations.keys(), *endpoint_names})

    trunks = []
    for name in sorted(all_trunk_names):
        reg_info = registrations.get(name, {})
        ch_list  = channels_by_trunk.get(name, [])
        trunks.append({
            "name":            name,
            "status":          reg_info.get("status", "Unknown"),
            "server":          reg_info.get("server", ""),
            "active_channels": len(ch_list),
            "channels":        ch_list,
        })

    registered = sum(1 for t in trunks if "Registered" in t["status"])
    total_ch   = sum(t["active_channels"] for t in trunks)

    return {
        "trunks":       trunks,
        "summary": {
            "total":       len(trunks),
            "registered":  registered,
            "unreachable": len(trunks) - registered,
            "channels":    total_ch,
        }
    }



# ─── /api/contacts ───────────────────────────────────────────────────────────

def parse_pjsip_contacts(output: str) -> list[dict]:
    """
    Разбирает вывод 'pjsip show contacts'.
    Формат строки:
      Contact:  endpoint/aor/sip:user@ip:port   hash   Avail   5.432
    """
    contacts = []
    for line in output.splitlines():
        m = re.match(r"\s*Contact:\s+(\S+)\s+\S+\s+(\w+)\s+([\d.]+|N/A)", line)
        if not m:
            continue
        full   = m.group(1)
        status = m.group(2)
        rtt    = m.group(3)

        parts    = full.split("/", 2)
        endpoint = parts[0] if len(parts) > 0 else full
        aor      = parts[1] if len(parts) > 1 else ""
        uri      = parts[2] if len(parts) > 2 else ""

        ip_match = re.search(r"@([^:;>]+)", uri)
        ip = ip_match.group(1) if ip_match else ""

        contacts.append({
            "endpoint": endpoint,
            "aor":      aor,
            "uri":      uri,
            "ip":       ip,
            "status":   status,
            "rtt":      rtt,
        })
    return contacts


@app.get("/api/contacts")
def get_contacts(q: str = ""):
    """
    Все контакты из 'pjsip show contacts' с опциональной фильтрацией.
    Аналог: asterisk -rx "pjsip show contacts" | grep "q"
    """
    output   = asterisk("pjsip show contacts")
    contacts = parse_pjsip_contacts(output)

    if q:
        q_lower  = q.lower()
        contacts = [
            c for c in contacts
            if q_lower in c["endpoint"].lower()
            or q_lower in c["aor"].lower()
            or q_lower in c["uri"].lower()
            or q_lower in c["ip"].lower()
        ]

    return {"contacts": contacts, "total": len(contacts), "filter": q}


# ─── /api/fail2ban ────────────────────────────────────────────────────────────

@app.get("/api/fail2ban/jails")
def get_jails():
    out, _ = run("fail2ban-client status 2>&1")
    jails = []
    m = re.search(r"Jail list:\s+(.+)", out)
    if m:
        jails = [j.strip() for j in m.group(1).split(",") if j.strip()]
    return {"jails": jails or ["asterisk"]}


@app.get("/api/fail2ban/banned")
def get_banned(jail: str = "asterisk"):
    out, err = run(f"fail2ban-client status {jail} 2>&1")
    if "ERROR" in err or "ERROR" in out:
        raise HTTPException(400, f"Jail '{jail}' не найден")

    # Достаём список забаненных IP
    m = re.search(r"Banned IP list:\s*(.*)", out)
    banned = m.group(1).strip().split() if m else []
    banned = [ip for ip in banned if ip]

    # Читаем whitelist из jail.local (приоритет) или jail.conf
    whitelist = _read_whitelist(jail)

    return {
        "jail":     jail,
        "banned":   banned,
        "count":    len(banned),
        "whitelist": whitelist,   # dict с ключами default/jail/all
    }


def _read_ignoreip(section: str) -> list[str]:
    """Читает ignoreip из указанной секции из конфиг-файлов."""
    for path in [FAIL2BAN_LOCAL, FAIL2BAN_CONF]:
        if not path.exists():
            continue
        fc = path.read_text()
        pat = rf"\[{re.escape(section)}\][^\[]*?ignoreip\s*=\s*([^\n]+)"
        m = re.search(pat, fc, re.DOTALL)
        if m:
            return [ip for ip in m.group(1).strip().split() if ip]
    return []


def _read_whitelist(jail: str) -> dict:
    """
    Возвращает вайтлист двух уровней:
    default — из [DEFAULT], действует для всех jail сразу
    jail    — из конкретного [jail]
    """
    system      = {"127.0.0.1/8", "::1", "127.0.0.1"}
    default_ips = [ip for ip in _read_ignoreip("DEFAULT") if ip not in system]
    jail_ips    = [ip for ip in _read_ignoreip(jail)      if ip not in system]
    return {
        "default": default_ips,
        "jail":    jail_ips,
    }


class UnbanRequest(BaseModel):
    ip: str
    jail: str = "asterisk"
    add_to_whitelist: bool = False


@app.post("/api/fail2ban/unban")
def unban_ip(req: UnbanRequest):
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", req.ip):
        raise HTTPException(400, "Некорректный IP-адрес")

    out, err = run(f"fail2ban-client set {req.jail} unbanip {req.ip} 2>&1")

    if req.add_to_whitelist:
        _write_whitelist(req.ip, req.jail)

    return {"success": True, "message": (out + err).strip(), "ip": req.ip}


class WhitelistRequest(BaseModel):
    ip: str               # Один или несколько IP через пробел: "1.2.3.4 5.6.7.8"
    jail: str = "asterisk"  # Или "DEFAULT" чтобы добавить во все jail сразу


@app.post("/api/fail2ban/whitelist")
def whitelist_ip(req: WhitelistRequest):
    # Разбиваем строку по пробелам/запятым — поддерживаем массовое добавление
    raw_ips = re.split(r"[\s,;]+", req.ip.strip())
    ips = [ip for ip in raw_ips if ip]

    if not ips:
        raise HTTPException(400, "Укажите хотя бы один IP-адрес")

    invalid = [ip for ip in ips
               if not re.match(r"^\d{1,3}(\.\d{1,3}){3}(/\d+)?$", ip)]
    if invalid:
        raise HTTPException(400, f"Некорректные IP: {', '.join(invalid)}")

    # Добавляем все IP за один проход (один reload fail2ban)
    _write_whitelist_bulk(ips, req.jail)
    return {"success": True, "ips": ips, "count": len(ips)}


def _write_whitelist_bulk(ips: list, jail: str):
    """
    Добавляет список IP в ignoreip в jail.local.
    jail="DEFAULT" — добавляет в глобальную секцию (действует для всех jail-ов).
    Один вызов — один reload fail2ban, сколько бы IP ни добавляли.
    """
    path = FAIL2BAN_LOCAL
    file_content = path.read_text() if path.exists() else ""
    jail_pat = rf"\[{re.escape(jail)}\]"

    # Только новые IP которых ещё нет в файле
    new_ips = [ip for ip in ips if ip not in file_content]
    if not new_ips:
        return

    new_str = " ".join(new_ips)

    if re.search(jail_pat, file_content):
        ig_pat = rf"(\[{re.escape(jail)}\][^\[]*?ignoreip\s*=\s*)([^\n]+)"
        m = re.search(ig_pat, file_content, re.DOTALL)
        if m:
            file_content = file_content[: m.end(2)] + f" {new_str}" + file_content[m.end(2):]
        else:
            file_content = re.sub(
                jail_pat, f"[{jail}]\nignoreip = 127.0.0.1/8 ::1 {new_str}", file_content
            )
    else:
        file_content += f"\n[{jail}]\nignoreip = 127.0.0.1/8 ::1 {new_str}\n"

    path.write_text(file_content)
    run("fail2ban-client reload 2>&1")


def _write_whitelist(ip: str, jail: str):
    """Один IP — обёртка над bulk."""
    _write_whitelist_bulk([ip], jail)

# ─── /api/quality/trunk_performance ─────────────────────────────────────────
# Показывает % дозвона по каждому транку (номеру) из пула.
# Помогает найти конкретные выгоревшие номера, которые надо менять в кабинете.

@app.get("/api/quality/trunk_performance")
def trunk_performance(period: str = "24h"):
    """
    Рейтинг транков по проценту дозвона.
    dstchannel в CDR содержит имя транка: PJSIP/trunkname-XXXXXXXX
    Сортировка: худшие наверху — сразу видно что менять.
    """
    interval = PERIOD_MAP.get(period, "24 HOUR")
    try:
        rows = mysql_query(f"""
            SELECT
                REPLACE(SUBSTRING_INDEX(dstchannel, '-', 1), 'PJSIP/', '') AS trunk,
                COUNT(*)                                                     AS total,
                SUM(CASE WHEN disposition='ANSWERED'  THEN 1 ELSE 0 END)    AS answered,
                SUM(CASE WHEN disposition='NO ANSWER' THEN 1 ELSE 0 END)    AS no_answer,
                SUM(CASE WHEN disposition='FAILED'    THEN 1 ELSE 0 END)    AS failed,
                ROUND(
                    SUM(CASE WHEN disposition='ANSWERED' THEN 1 ELSE 0 END)
                    / COUNT(*) * 100, 1
                )                                                            AS answer_rate,
                ROUND(AVG(
                    CASE WHEN disposition='ANSWERED' AND billsec > 0
                         THEN billsec ELSE NULL END
                ))                                                           AS avg_dur
            FROM {CDR_TABLE}
            WHERE calldate >= DATE_SUB(NOW(), INTERVAL {interval})
              AND dstchannel LIKE 'PJSIP/%'
              AND dstchannel != ''
              AND dstchannel NOT LIKE 'PJSIP/Local/%'
            GROUP BY trunk
            HAVING total >= 3
            ORDER BY answer_rate ASC, total DESC
            LIMIT 50
        """)
    except Exception as e:
        raise HTTPException(500, str(e))

    return {"trunks": rows, "period": period, "count": len(rows)}


# ─── /api/quality/dialplan ────────────────────────────────────────────────
# Анализ событий диалплана randcool из VERBOSE-лога.
# Показывает загруженность пула транков и ситуации "все заняты".

@app.get("/api/quality/dialplan")
def dialplan_stats(hours: int = 1):
    """
    Разбираем VERBOSE-лог на события диалплана randcool:
    - RANDCOOL START — старт каждого исходящего звонка
    - Using trunk=X — успешный выбор транка
    - Skipping trunk=X state=IN_CALL — транк занят
    - allbusy — все 99 транков заняты одновременно (проблема ёмкости!)
    Это единственный способ мониторить загрузку пула из лога.
    """
    cutoff = datetime.now() - timedelta(hours=hours)
    stats = {
        "calls_started":  0,
        "trunk_found":    0,
        "all_busy":       0,
        "skips_in_call":  0,   # пропуск из-за активного звонка
        "skips_cooldown": 0,   # пропуск из-за кулдауна
        "by_group":       {},  # группа оператора → кол-во звонков
    }

    try:
        # Берём достаточно строк чтобы покрыть период
        lines_to_read = hours * 30000
        out, _ = run(f"tail -n {lines_to_read} {ASTERISK_LOG}")
    except Exception:
        return stats

    for line in out.splitlines():
        ts_m = re.match(r"\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]", line)
        if ts_m:
            try:
                if datetime.strptime(ts_m.group(1), "%Y-%m-%d %H:%M:%S") < cutoff:
                    continue
            except ValueError:
                pass

        if "RANDCOOL START caller=" in line:
            stats["calls_started"] += 1
            m = re.search(r"caller=(\w+)", line)
            if m:
                g = m.group(1)
                stats["by_group"][g] = stats["by_group"].get(g, 0) + 1

        elif '"Using trunk=' in line or "NoOp.*Using trunk=" in line:
            stats["trunk_found"] += 1

        elif "allbusy" in line and "GotoIf" in line and "1?allbusy" in line:
            stats["all_busy"] += 1

        elif "Skipping trunk=" in line:
            if "IN_CALL" in line:
                stats["skips_in_call"] += 1
            else:
                stats["skips_cooldown"] += 1

    t = stats["calls_started"]
    stats["find_rate"]          = round(stats["trunk_found"]   / t * 100, 1) if t else 0
    stats["avg_skips_per_call"] = round(
        (stats["skips_in_call"] + stats["skips_cooldown"]) / t, 1
    ) if t else 0

    return stats


# ─── /api/recordings ──────────────────────────────────────────────────────────

def _find_file(filename: str) -> Optional[Path]:
    """
    Ищет файл записи с учётом структуры каталогов по дате.
    FreePBX MixMonitor пишет в: monitor/YYYY/MM/DD/filename.wav
    Имя файла содержит дату: out-79XXXXXXXXX-unknown-20260522-044922-...wav
    """
    basename = Path(filename).name

    # 1. Быстрый путь: извлекаем дату из имени файла
    dm = re.search(r"-(\d{4})(\d{2})(\d{2})-", basename)
    if dm:
        y, m, d = dm.groups()
        date_path = RECORDINGS_PATH / y / m / d / basename
        if date_path.exists():
            return date_path

    # 2. Прямые пути без датировки
    for candidate in [Path(filename), RECORDINGS_PATH / filename, RECORDINGS_PATH / basename]:
        if candidate.exists():
            return candidate

    # 3. Медленный рекурсивный поиск (fallback)
    matches = list(RECORDINGS_PATH.rglob(basename))
    return matches[0] if matches else None


@app.get("/api/recordings/search")
def search_recordings(
    phone:     str,
    date_from: Optional[str] = None,
    date_to:   Optional[str] = None,
    limit:     int = 50,
):
    if not phone:
        raise HTTPException(400, "Укажите номер телефона")

    date_from = date_from or (datetime.now() - timedelta(days=30)).strftime("%Y-%m-%d")
    date_to   = date_to   or datetime.now().strftime("%Y-%m-%d")
    phone_like = f"%{phone}%"

    sql = f"""
        SELECT uniqueid, calldate, src, dst, duration, billsec,
               disposition, recordingfile
        FROM {CDR_TABLE}
        WHERE (src LIKE %s OR dst LIKE %s)
          AND calldate BETWEEN %s AND %s
          AND recordingfile IS NOT NULL
          AND recordingfile != ''
        ORDER BY calldate DESC
        LIMIT %s
    """
    try:
        rows = mysql_query(
            sql, [phone_like, phone_like, date_from, f"{date_to} 23:59:59", limit]
        )
    except Exception as e:
        raise HTTPException(500, str(e))

    for row in rows:
        row["file_exists"] = bool(_find_file(row.get("recordingfile", "")))

    return {"recordings": rows, "count": len(rows)}


@app.get("/api/recordings/download/{uniqueid}")
def download_recording(uniqueid: str):
    try:
        rows = mysql_query(
            f"SELECT recordingfile FROM {CDR_TABLE} WHERE uniqueid=%s LIMIT 1",
            [uniqueid],
        )
    except Exception as e:
        raise HTTPException(500, str(e))

    if not rows:
        raise HTTPException(404, "Запись не найдена в CDR")

    path = _find_file(rows[0]["recordingfile"])
    if not path:
        raise HTTPException(404, "Файл записи не найден на диске")

    return FileResponse(str(path), media_type="audio/wav", filename=path.name)


@app.get("/api/recordings/download-bulk")
def download_bulk(phone: str, date_from: str = "", date_to: str = ""):
    result = search_recordings(phone, date_from or None, date_to or None, limit=200)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for rec in result["recordings"]:
            if rec.get("file_exists"):
                p = _find_file(rec["recordingfile"])
                if p:
                    zf.write(str(p), p.name)
    buf.seek(0)
    fname = f"recordings_{phone}_{date_from}.zip"
    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={"Content-Disposition": f"attachment; filename={fname}"},
    )


# ─── /api/quality ─────────────────────────────────────────────────────────────

PERIOD_MAP = {
    "15m": "15 MINUTE",
    "30m": "30 MINUTE",
    "1h":  "1 HOUR",
    "6h":  "6 HOUR",
    "24h": "24 HOUR",
    "7d":  "7 DAY",
    "30d": "30 DAY",
}


# Для тренда: предыдущий период равной длины (чтобы сравнивать яблоки с яблоками)
PREV_PERIOD_MAP = {
    "15m": ("30 MINUTE", "15 MINUTE"),
    "30m": ("60 MINUTE", "30 MINUTE"),
    "1h":  ("2 HOUR",    "1 HOUR"),
    "6h":  ("12 HOUR",   "6 HOUR"),
    "24h": ("48 HOUR",   "24 HOUR"),
    "7d":  ("14 DAY",    "7 DAY"),
    "30d": ("60 DAY",    "30 DAY"),
}


def _calc_stats(rows: list) -> dict:
    """Считаем метрики из строк disposition/count."""
    s = {"answered": 0, "no_answer": 0, "busy": 0, "failed": 0, "total": 0}
    for row in rows:
        d   = row["disposition"].upper()
        cnt = int(row["cnt"])
        s["total"] += cnt
        if d == "ANSWERED":    s["answered"]  = cnt
        elif d == "NO ANSWER": s["no_answer"] = cnt
        elif d == "BUSY":      s["busy"]      = cnt
        elif d == "FAILED":    s["failed"]    = cnt
    t = s["total"]
    s["answer_rate"]    = round(s["answered"]  / t * 100, 1) if t else 0
    s["no_answer_rate"] = round(s["no_answer"] / t * 100, 1) if t else 0
    s["busy_rate"]      = round(s["busy"]      / t * 100, 1) if t else 0
    s["failed_rate"]    = round(s["failed"]    / t * 100, 1) if t else 0
    s["fail_rate"]      = round((s["no_answer"] + s["failed"]) / t * 100, 1) if t else 0
    return s


@app.get("/api/quality/stats")
def quality_stats(period: str = "1h"):
    interval   = PERIOD_MAP.get(period, "1 HOUR")
    prev_start, prev_end = PREV_PERIOD_MAP.get(period, ("2 HOUR", "1 HOUR"))

    try:
        # Текущий период
        cur_rows = mysql_query(f"""
            SELECT disposition, COUNT(*) AS cnt FROM {CDR_TABLE}
            WHERE calldate >= DATE_SUB(NOW(), INTERVAL {interval})
            GROUP BY disposition
        """)
        # Предыдущий равный период — для стрелки тренда
        prev_rows = mysql_query(f"""
            SELECT disposition, COUNT(*) AS cnt FROM {CDR_TABLE}
            WHERE calldate >= DATE_SUB(NOW(), INTERVAL {prev_start})
              AND calldate <  DATE_SUB(NOW(), INTERVAL {prev_end})
            GROUP BY disposition
        """)
        # Средняя длительность отвеченных звонков
        dur_rows = mysql_query(f"""
            SELECT ROUND(AVG(billsec)) AS avg_dur,
                   MAX(billsec)        AS max_dur
            FROM {CDR_TABLE}
            WHERE calldate >= DATE_SUB(NOW(), INTERVAL {interval})
              AND disposition = 'ANSWERED'
              AND billsec > 0
        """)
    except Exception as e:
        logger.error(f"quality_stats error (period={period}): {type(e).__name__}: {e}")
        raise HTTPException(500, str(e))

    try:
        stats      = _calc_stats(cur_rows)
    except Exception as e:
        logger.error(f"_calc_stats error: {type(e).__name__}: {e}, cur_rows={cur_rows[:2]}")
        raise HTTPException(500, f"calc error: {e}")
    prev_stats = _calc_stats(prev_rows)

    # Тренд: насколько изменился % дозвона по сравнению с предыдущим периодом
    stats["trend"]            = round(stats["answer_rate"] - prev_stats["answer_rate"], 1)
    stats["prev_answer_rate"] = prev_stats["answer_rate"]
    stats["prev_total"]       = prev_stats["total"]

    # Средняя длительность разговора
    avg_dur = 0
    if dur_rows and dur_rows[0].get("avg_dur"):
        avg_dur = int(dur_rows[0]["avg_dur"] or 0)
    stats["avg_duration"] = avg_dur

    return {"stats": stats, "period": period}


@app.get("/api/quality/hourly")
def quality_hourly():
    """
    Распределение звонков по часам суток за последние 7 дней.
    Показывает пиковые часы нагрузки и средний % дозвона в каждый час.
    Используется для планирования ротации номеров.
    """
    try:
        rows = mysql_query(f"""
            SELECT HOUR(calldate) AS hour,
                   COUNT(*) AS total,
                   SUM(CASE WHEN disposition='ANSWERED' THEN 1 ELSE 0 END) AS answered
            FROM {CDR_TABLE}
            WHERE calldate >= DATE_SUB(NOW(), INTERVAL 7 DAY)
            GROUP BY HOUR(calldate)
            ORDER BY HOUR(calldate)
        """)
    except Exception as e:
        raise HTTPException(500, str(e))

    # Заполняем все 24 часа, даже если данных нет — иначе Chart.js пропустит их
    hourly = {i: {"hour": i, "total": 0, "answered": 0, "rate": 0} for i in range(24)}
    for row in rows:
        h = int(row["hour"])
        t = int(row["total"])
        a = int(row["answered"])
        hourly[h] = {
            "hour":     h,
            "total":    t,
            "answered": a,
            "rate":     round(a / t * 100, 1) if t else 0,
        }

    return {"hourly": list(hourly.values())}


@app.get("/api/quality/timeline")
def quality_timeline(period: str = "24h"):
    """
    Временная детализация для графика звонков.
    Для мелких интервалов (15м/30м) используем UNIX_TIMESTAMP чтобы
    округлить время до нужного шага — стандартный DATE_FORMAT этого не умеет.
    """
    configs = {
        # period: (SQL expression для группировки, интервал WHERE, подсказка для фронта)
        "15m": (
            "DATE_FORMAT(FROM_UNIXTIME(FLOOR(UNIX_TIMESTAMP(calldate)/900)*900),  '%H:%i')",
            "2 HOUR",
        ),
        "30m": (
            "DATE_FORMAT(FROM_UNIXTIME(FLOOR(UNIX_TIMESTAMP(calldate)/1800)*1800), '%H:%i')",
            "4 HOUR",
        ),
        "1h": (
            "DATE_FORMAT(calldate, '%H:00')",
            "12 HOUR",
        ),
        "24h": (
            "DATE_FORMAT(calldate, '%m-%d %H:00')",
            "24 HOUR",
        ),
        "7d": (
            "DATE_FORMAT(calldate, '%m-%d')",
            "7 DAY",
        ),
        "30d": (
            "DATE_FORMAT(calldate, '%Y-%m-%d')",
            "30 DAY",
        ),
    }
    date_expr, interval = configs.get(period, configs["24h"])

    try:
        rows = mysql_query(f"""
            SELECT {date_expr} AS period,
                   disposition,
                   COUNT(*) AS cnt
            FROM {CDR_TABLE}
            WHERE calldate >= DATE_SUB(NOW(), INTERVAL {interval})
            GROUP BY period, disposition
            ORDER BY period ASC
        """)
    except Exception as e:
        raise HTTPException(500, str(e))

    timeline: dict = {}
    for row in rows:
        p = row["period"]
        if p not in timeline:
            timeline[p] = {"period": p, "answered": 0, "no_answer": 0, "busy": 0, "failed": 0}
        d = row["disposition"].upper()
        if d == "ANSWERED":    timeline[p]["answered"]  += int(row["cnt"])
        elif d == "NO ANSWER": timeline[p]["no_answer"] += int(row["cnt"])
        elif d == "BUSY":      timeline[p]["busy"]      += int(row["cnt"])
        elif d == "FAILED":    timeline[p]["failed"]    += int(row["cnt"])

    return {"timeline": list(timeline.values()), "period": period}


# ─── /api/quality/errors — анализ лога Asterisk ──────────────────────────────

# Паттерны ошибок в логах Asterisk.
# Система пишет в VERBOSE-режиме, поэтому добавляем паттерны из диалплана.
# WARNING/ERROR/NOTICE уровни ищем в /var/log/asterisk/messages если есть.
ERROR_PATTERNS = {
    # Уровни WARNING/ERROR/NOTICE (стандартные)
    "registration_failed": (r"Registration.*?failed|Failed.*?register|Endpoint.*?failed",   "Ошибки регистрации"),
    "peer_unreachable":    (r"Peer.*?UNREACHABLE|qualify.*?UNREACHABLE|contact.*?removed",   "Пиры недоступны"),
    "sip_503":             (r"503 Service Unavailable|503 Server",                           "503 Unavailable"),
    "sip_486":             (r"486 Busy|User is busy",                                        "486 Busy"),
    "sip_404":             (r"404 Not Found|No matching endpoint",                           "404 Not Found"),
    "auth_fail":           (r"Authentication failed|Wrong password|401 Unauthorized",        "Ошибки авторизации"),
    "timeout":             (r"Request Timeout|408|RTP Read Timeout|RTP timeout",             "Таймауты / RTP"),
    "conn_refused":        (r"Connection refused|Connection reset|Transport error",          "Ошибки соединения"),
    # События диалплана randcool (VERBOSE уровень)
    "all_busy":            (r"allbusy|1\?allbusy",                                           "Все транки заняты"),
    "dial_failed":         (r"app_dial\.c:.*FAILED|DIALSTATUS.*FAILED|CHANUNAVAIL",         "Dial FAILED"),
}

# Дополнительный лог файл с WARNING/ERROR (часто отдельный на FreePBX)
ASTERISK_MESSAGES_LOG = Path("/var/log/asterisk/messages")


@app.get("/api/quality/errors")
def quality_errors(hours: int = 1, lines: int = 5000):
    cutoff = datetime.now() - timedelta(hours=hours)
    errors: dict = {k: [] for k in ERROR_PATTERNS}

    try:
        out, _ = run(f"tail -n {lines} {ASTERISK_LOG}")
        # Если есть отдельный файл с WARNING/ERROR — добавляем к анализу
        if ASTERISK_MESSAGES_LOG.exists():
            msg_out, _ = run(f"tail -n {lines // 2} {ASTERISK_MESSAGES_LOG}")
            out = out + "\n" + msg_out
    except Exception:
        out = ""

    for line in out.splitlines():
        # Формат Asterisk: [2024-01-15 14:30:00] NOTICE[1234]...
        ts_m = re.match(r"\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]", line)
        if ts_m:
            try:
                if datetime.strptime(ts_m.group(1), "%Y-%m-%d %H:%M:%S") < cutoff:
                    continue
            except ValueError:
                pass

        for key, (pattern, _label) in ERROR_PATTERNS.items():
            if re.search(pattern, line, re.IGNORECASE):
                errors[key].append(line.strip()[:300])
                break  # одна строка — одна категория

    summary = {k: len(v) for k, v in errors.items()}
    labels  = {k: v[1] for k, v in ERROR_PATTERNS.items()}
    # Возвращаем последние 30 строк каждой категории
    return {
        "summary":      summary,
        "labels":       labels,
        "errors":       {k: v[-30:] for k, v in errors.items()},
        "total":        sum(summary.values()),
        "period_hours": hours,
    }


# ─── Раздача статики и корневой маршрут ──────────────────────────────────────

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/")
def root():
    return FileResponse(str(STATIC_DIR / "index.html"))


# ─── Точка входа ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    # host="0.0.0.0" — доступен с любого IP, порт 8080
    uvicorn.run("app:app", host="0.0.0.0", port=8080, reload=False)
