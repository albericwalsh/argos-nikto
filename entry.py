import re
import csv
import io
import json
import os
import shutil
import tempfile
from dataclasses import dataclass, field
from reportlab.platypus import Table, TableStyle, Paragraph, Spacer
from reportlab.lib import colors
from reportlab.lib.units import mm

import docker
from docker.errors import DockerException

DOCKER_IMAGE = "frapsoft/nikto"

# Chemin du fichier CSV DANS le container (point de montage du volume)
_CONTAINER_OUTPUT_DIR  = "/tmp/nikto_out"
_CONTAINER_OUTPUT_FILE = f"{_CONTAINER_OUTPUT_DIR}/result.csv"

# ---------------------------------------------------------------------------
# Severité heuristique basée sur les mots-clés de la description Nikto
# ---------------------------------------------------------------------------
_HIGH_KEYWORDS   = ["sql injection", "xss", "remote code", "rce", "command injection",
                    "directory traversal", "path traversal", "arbitrary file", "backdoor",
                    "shell", "upload", "execute"]
_MEDIUM_KEYWORDS = ["password", "credential", "admin", "login", "default", "weak",
                    "authentication", "csrf", "open redirect", "ssrf", "htpasswd",
                    "config", "backup", ".bak", ".sql", ".env", "phpinfo"]
_LOW_KEYWORDS    = ["outdated", "deprecated", "version", "banner", "server", "disclose",
                    "information", "cookie", "header", "clickjack", "x-frame", "hsts",
                    "csp", "cors", "robots.txt", "sitemap"]

# Catégorie basée sur mots-clés
_CATEGORY_MAP = {
    "config":      ["config", "backup", ".bak", ".sql", "robots", "sitemap", "htaccess", "web.config"],
    "injection":   ["sql", "xss", "inject", "traversal", "rce", "shell", "command"],
    "disclosure":  ["disclose", "information", "banner", "version", "phpinfo", "error", "stack trace"],
    "auth":        ["auth", "login", "admin", "password", "credential", "htpasswd", "default"],
    "header":      ["header", "hsts", "csp", "x-frame", "cors", "cookie", "clickjack"],
    "outdated":    ["outdated", "deprecated", "old version", "eol"],
}


# Clés acceptées pour chaque champ, par ordre de préférence
_PORT_KEYS    = ["port", "ports", "PORT"]
_TARGET_KEYS  = ["target", "ip", "host", "address", "hostname", "ip_address"]
_OPTIONS_KEYS = ["options", "option", "args", "extra_options"]

_HTTP_SERVICE_NAMES = ["http", "https", "http-proxy", "http-alt", "www", "ssl/http", "http-mgmt", "http-wmap"]


@dataclass
class Finding:
    id:          str
    method:      str
    path:        str
    description: str
    severity:    str = "info"
    category:    str = "other"

    def to_dict(self) -> dict:
        return {
            "id":          self.id,
            "method":      self.method,
            "path":        self.path,
            "description": self.description,
            "severity":    self.severity,
            "category":    self.category,
        }


# ---------------------------------------------------------------------------
# utils
# ---------------------------------------------------------------------------

def _coerce_port_list(value) -> list[str]:
    """
    Transforme une valeur de port (scalaire, liste, JSON-string, ou résultat
    de step précédent) en liste de ports (str). Un seul port -> liste de 1.
    """
    if value is None:
        return []

    if isinstance(value, str):
        stripped = value.strip()
        if stripped and stripped[0] in "[{":
            try:
                value = json.loads(stripped)
            except (ValueError, TypeError):
                pass

    value = _to_dict(value)
    ports: list[str] = []

    if isinstance(value, (str, int, float)):
        sval = str(value).strip()
        if sval:
            for part in re.split(r"[,\s]+", sval):
                if part:
                    ports.append(part)
        return ports

    if isinstance(value, dict):
        port_val = _first_value(value, _PORT_KEYS)
        if port_val is not None:
            return _coerce_port_list(port_val)
        return ports

    if isinstance(value, (list, tuple)):
        http_ports = []
        other_ports = []
        for item in value:
            item_d = _to_dict(item)
            if isinstance(item_d, dict):
                port_val = item_d.get("port", _first_value(item_d, _PORT_KEYS))
                if port_val is None:
                    continue
                sval = str(port_val).strip()
                if not sval:
                    continue
                name = str(item_d.get("name", "")).lower()
                if name in _HTTP_SERVICE_NAMES:
                    http_ports.append(sval)
                else:
                    other_ports.append(sval)
            elif isinstance(item_d, (str, int, float)):
                sval = str(item_d).strip()
                if sval:
                    other_ports.append(sval)

        # Si on a des services identifiés HTTP/HTTPS, ne scanner que ceux-là
        # (Nikto est un scanner web — les autres ports le font bloquer indéfiniment)
        if http_ports:
            return http_ports
        return other_ports

    return ports

# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def _infer_severity(description: str) -> str:
    low = description.lower()
    if any(k in low for k in _HIGH_KEYWORDS):
        return "high"
    if any(k in low for k in _MEDIUM_KEYWORDS):
        return "medium"
    if any(k in low for k in _LOW_KEYWORDS):
        return "low"
    return "info"


def _infer_category(description: str) -> str:
    low = description.lower()
    for cat, keywords in _CATEGORY_MAP.items():
        if any(k in low for k in keywords):
            return cat
    return "other"


def parse_csv(csv_output: str) -> list[Finding]:
    """
    Parse le CSV généré par Nikto (-Format csv).

    Le CSV Nikto 2.x n'a PAS de ligne d'en-tête. Chaque ligne a la forme :
      "host","ip","port","httpmethod","uri","httpmethod2","osvdb","description"
    (le nombre/ordre exact de colonnes peut varier légèrement selon la version,
    donc on parse positionnellement avec des index de fallback)
    """
    findings: list[Finding] = []
    reader = csv.reader(io.StringIO(csv_output))

    for row in reader:
        if not row or len(row) < 2:
            continue

        row = [c.strip() for c in row]
        n = len(row)

        # Détection heuristique : si la première colonne ressemble à un host
        # (pas "OSVDB-" ni un verbe HTTP), on suppose le format standard.
        # Colonnes typiques (8) :
        #   0 host, 1 ip, 2 port, 3 method, 4 path, 5 method2(dup), 6 osvdb, 7 description
        host        = row[0] if n > 0 else ""
        ip          = row[1] if n > 1 else ""
        port_col    = row[2] if n > 2 else ""
        method      = row[3] if n > 3 else "GET"
        path        = row[4] if n > 4 else "/"
        osvdb_raw   = row[6] if n > 6 else ""
        description = row[7] if n > 7 else (row[-1] if n > 0 else "")

        # Si la ligne n'a que peu de colonnes, retombe sur la dernière comme description
        if n <= 4:
            description = row[-1]
            method = "GET"
            path = "/"

        if not description:
            continue

        method = (method or "GET").upper()
        if method not in ("GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "TRACE", "PATCH"):
            method = "GET"

        path = path or "/"

        osvdb = re.sub(r"[^0-9]", "", osvdb_raw) if osvdb_raw else ""
        finding_id = f"OSVDB-{osvdb}" if osvdb and osvdb != "0" else _generate_id(path, description)

        f = Finding(
            id          = finding_id,
            method      = method,
            path        = path,
            description = description,
            severity    = _infer_severity(description),
            category    = _infer_category(description),
        )
        findings.append(f)

    return findings


def parse_text(text_output: str) -> list[Finding]:
    """
    Fallback : parse la sortie texte standard de Nikto.
    Lignes de findings : '+ <METHOD> <path>: <description>'
    ou                   '+ OSVDB-XXXX: <METHOD> <path>: <description>'
    """
    findings: list[Finding] = []
    counter  = 0

    for line in text_output.splitlines():
        line = line.strip()
        if not line.startswith("+"):
            continue

        content = line.lstrip("+ ").strip()

        # Tentative d'extraction OSVDB
        osvdb_match = re.match(r"(OSVDB-\d+):\s*(.*)", content)
        if osvdb_match:
            finding_id = osvdb_match.group(1)
            content    = osvdb_match.group(2).strip()
        else:
            counter   += 1
            finding_id = f"NKT-{counter:04d}"

        # Extraction méthode + path
        method_path_match = re.match(r"(GET|POST|HEAD|PUT|DELETE|OPTIONS|TRACE)\s+(/\S*):\s*(.*)", content)
        if method_path_match:
            method      = method_path_match.group(1)
            path        = method_path_match.group(2)
            description = method_path_match.group(3).strip()
        else:
            # Pas de méthode/path explicite
            method      = "GET"
            path        = "/"
            description = content

        if not description:
            continue

        findings.append(Finding(
            id          = finding_id,
            method      = method,
            path        = path,
            description = description,
            severity    = _infer_severity(description),
            category    = _infer_category(description),
        ))

    return findings


def _generate_id(path: str, description: str) -> str:
    slug = re.sub(r"[^a-z0-9]", "-", (path + description[:20]).lower())
    slug = re.sub(r"-+", "-", slug).strip("-")[:20]
    return f"NKT-{slug}"


def print_results(findings: list[Finding]) -> None:
    print(f"\n{'ID':<18} {'SEV':<8} {'CAT':<12} {'METHOD':<7} {'PATH':<30} DESCRIPTION")
    print("-" * 110)
    for f in findings:
        print(f"{f.id:<18} {f.severity:<8} {f.category:<12} {f.method:<7} {f.path:<30} {f.description[:60]}")


# ---------------------------------------------------------------------------
# Docker runner
# ---------------------------------------------------------------------------

def _resolve_target_for_docker(target: str) -> str:
    """
    Sur Docker Desktop (Windows/macOS), 'localhost'/'127.0.0.1' à l'intérieur
    du container pointe vers le container lui-même, pas vers l'hôte.
    On remplace donc par 'host.docker.internal' qui est résolu par Docker Desktop.
    network_mode='host' n'est de toute façon pas supporté sur ces plateformes.
    """
    if target in ("localhost", "127.0.0.1", "0.0.0.0"):
        return "host.docker.internal"
    return target

def run_nikto(client, target: str, port: str, extra_options: list[str]) -> str:
    docker_target = _resolve_target_for_docker(target)

    cmd = ["-host", docker_target, "-Format", "csv", "-output", _CONTAINER_OUTPUT_FILE, "-nointeractive"]
    if port:
        cmd += ["-port", port]
    cmd += extra_options

    print(f"[nikto] Lancement : nikto {' '.join(cmd)}", flush=True)
    if docker_target != target:
        print(f"[nikto] Cible '{target}' résolue en '{docker_target}' pour l'accès depuis le container Docker.", flush=True)

    with tempfile.TemporaryDirectory() as host_dir:
        os.chmod(host_dir, 0o777)

        run_kwargs = dict(
            image    = DOCKER_IMAGE,
            command  = cmd,
            volumes  = {host_dir: {"bind": _CONTAINER_OUTPUT_DIR, "mode": "rw"}},
            extra_hosts = {"host.docker.internal": "host-gateway"},
            detach   = True,
        )

        container = client.containers.run(**run_kwargs)

        try:
            for line in container.logs(stream=True, follow=True):
                chunk = line.decode("utf-8", errors="replace") if isinstance(line, bytes) else str(line)
                print(f"[nikto:{port or 'default'}] {chunk}", end="", flush=True)

            result = container.wait()
            exit_code = result.get("StatusCode") if isinstance(result, dict) else result
            print(f"[nikto] Container terminé (exit code: {exit_code})", flush=True)

            logs_text = container.logs().decode("utf-8", errors="replace")
        finally:
            try:
                container.remove(force=True)
            except docker.errors.APIError:
                pass

        result_path = os.path.join(host_dir, "result.csv")
        print(f"[nikto] Recherche du fichier résultat : {result_path} (existe: {os.path.exists(result_path)})", flush=True)

        if os.path.exists(result_path):
            with open(result_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
            print(f"[nikto] Taille du CSV : {len(content)} caractères", flush=True)
            if content.strip():
                return content

        return logs_text


# ---------------------------------------------------------------------------
# Docker availability check
# ---------------------------------------------------------------------------

def check_docker() -> tuple[bool, str]:
    """
    Vérifie que Docker est installé et que le daemon est lancé/accessible.

    Retourne:
        (ok, message) — ok=True si Docker est prêt à l'emploi.
                         Si ok=False, message contient une explication
                         et des pistes de résolution.
    """
    # 1. Le binaire docker est-il dans le PATH ?
    if shutil.which("docker") is None:
        return False, (
            "Docker ne semble pas installé (binaire 'docker' introuvable dans le PATH). "
            "Installe Docker Desktop (Windows/macOS) ou Docker Engine (Linux), "
            "puis assure-toi qu'il est accessible depuis le terminal."
        )

    # 2. Le client Python peut-il se connecter au daemon ?
    try:
        client = docker.from_env()
        client.ping()
    except DockerException as e:
        msg = str(e)
        if "CreateFile" in msg or "pipe" in msg.lower():
            return False, (
                "Docker est installé mais le daemon n'est pas joignable (pipe Windows introuvable). "
                "Lance Docker Desktop et attends qu'il affiche 'Running', puis réessaie."
            )
        if "Connection refused" in msg or "/var/run/docker.sock" in msg:
            return False, (
                "Docker est installé mais le daemon n'est pas lancé (socket Linux introuvable). "
                "Démarre le service avec 'sudo systemctl start docker' ou lance Docker Desktop."
            )
        return False, f"Docker est installé mais inaccessible : {msg}"
    except Exception as e:
        return False, f"Erreur inattendue lors de la vérification de Docker : {e}"

    return True, "Docker est disponible."


# ---------------------------------------------------------------------------
# Extraction depuis le résultat d'un step précédent
# ---------------------------------------------------------------------------


from dataclasses import is_dataclass, asdict


def _to_dict(obj):
    """Convertit un dataclass en dict, laisse les dicts/autres tels quels."""
    if is_dataclass(obj) and not isinstance(obj, type):
        return asdict(obj)
    return obj


def _extract_port_preferring_http(obj) -> str | None:
    """
    Cas spécifique 'port' : si l'objet est une liste de services
    (style sortie nmap, dataclass ou dict), on privilégie le service
    dont 'name' est http/https/etc. Sinon, fallback sur le premier
    port trouvé.
    """
    if isinstance(obj, (list, tuple)):
        for item in obj:
            item = _to_dict(item)
            if isinstance(item, dict):
                name = str(item.get("name", "")).lower()
                port_val = item.get("port")
                if name in _HTTP_SERVICE_NAMES and port_val not in (None, "", []):
                    return port_val
    return None


def _first_value(obj, keys: list[str]):
    """
    Cherche récursivement la première valeur correspondant à une des clés
    données dans 'obj' (dict, list, dataclass, ou valeur scalaire).
    Retourne None si rien trouvé.
    """
    if obj is None:
        return None

    obj = _to_dict(obj)

    # Cas spécial : extraction de port depuis une liste de services nmap,
    # en privilégiant les services HTTP/HTTPS.
    if keys is _PORT_KEYS:
        preferred = _extract_port_preferring_http(obj)
        if preferred is not None:
            return preferred

    if isinstance(obj, dict):
        for k in keys:
            if k in obj and obj[k] not in (None, "", []):
                return obj[k]
        # Recherche en profondeur dans les valeurs imbriquées
        for v in obj.values():
            found = _first_value(v, keys)
            if found is not None:
                return found
        return None

    if isinstance(obj, (list, tuple)):
        for item in obj:
            found = _first_value(item, keys)
            if found is not None:
                return found
        return None

    return None


def _extract_from_result(result, keys: list[str]):
    """
    Extrait une valeur depuis le résultat d'un step précédent ($stepX.output).
    Gère : dict, list[dict], list[scalaire], scalaire brut.
    """
    if result is None:
        return None

    # Scalaire brut (ex: "3000" ou "10.105.1.69")
    if isinstance(result, (str, int, float)):
        return result

    return _first_value(result, keys)


def resolve_input(value, args: dict, keys: list[str], own_key: str):
    """
    Résout une valeur d'entrée qui peut être :
      - une valeur directe (string/number) déjà fournie dans args[own_key]
      - une chaîne JSON sérialisée (ex: '[{"port": 3000, ...}]')
      - le résultat d'un step précédent (dict/list injecté par le moteur
        via '$stepX.output'), dans lequel on cherche 'keys'

    Retourne la valeur résolue, ou None si rien d'utilisable trouvé.
    """
    # Tentative de désérialisation si c'est une chaîne JSON (liste/dict)
    if isinstance(value, str):
        stripped = value.strip()
        if stripped and stripped[0] in "[{":
            try:
                parsed = json.loads(stripped)
                value = parsed
            except (ValueError, TypeError):
                pass  # pas du JSON, on traite comme scalaire ci-dessous

    # Si la valeur est déjà un scalaire non vide, on la garde telle quelle
    if isinstance(value, (str, int, float)):
        sval = str(value).strip()
        if sval:
            return sval
        return None

    # Sinon (dict / list / None) -> on tente l'extraction
    extracted = _extract_from_result(value, keys)
    if extracted is not None:
        sval = str(extracted).strip()
        if sval:
            return sval

    return None


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def main(args: dict) -> list[dict]:
    """
    Point d'entrée du module Nikto.

    Paramètres (args):
        target  : str | dict | list — IP/host cible, ou résultat d'un step
                  précédent contenant 'target'/'ip'/'host'/'address'.
        port    : str | dict | list — Port, ou résultat d'un step précédent
                  contenant 'port'.
        options : str | dict | list — Options Nikto, ou résultat d'un step
                  précédent contenant 'options'.

    Retourne:
        list[dict] — Liste de findings sérialisés (chaque dict = un Finding.to_dict())
    """
    raw_target  = args.get("target")
    raw_port    = args.get("port")
    raw_options = args.get("options")

    print(f"[nikto] DEBUG raw_target  = {raw_target!r} (type={type(raw_target).__name__})")
    print(f"[nikto] DEBUG raw_port    = {raw_port!r} (type={type(raw_port).__name__})")
    print(f"[nikto] DEBUG raw_options = {raw_options!r} (type={type(raw_options).__name__})")

    target = resolve_input(raw_target, args, _TARGET_KEYS, "target")
    if not target:
        msg = (
            "Impossible de déterminer la cible ('target'). "
            "Aucune valeur 'target'/'ip'/'host'/'address' trouvée dans les arguments "
            "ou le résultat du step précédent."
        )
        print(f"[nikto] ERROR: {msg}")
        raise ValueError(f"[nikto] {msg}")

    ports = _coerce_port_list(raw_port)
    if not ports:
        ports = [""]  # aucun port spécifié -> un seul scan sans -port
    print(f"[nikto] DEBUG resolved target = {target!r} | ports = {ports!r}")


    options = resolve_input(raw_options, args, _OPTIONS_KEYS, "options")
    if options is None:
        options = raw_options if isinstance(raw_options, (str, list)) else ""

    # Normalisation des options en liste
    if isinstance(options, list):
        extra_options = options
    elif isinstance(options, str) and options:
        extra_options = options.split()
    else:
        extra_options = []

    # Vérification Docker AVANT toute tentative de scan
    docker_ok, docker_msg = check_docker()
    if not docker_ok:
        print(f"[nikto] ERROR: {docker_msg}")
        raise RuntimeError(f"[nikto] Docker indisponible : {docker_msg}")

    client = docker.from_env()

    all_findings: list[Finding] = []

    for p in ports:
        print(f"[nikto] === Scan du port {p!r} ===")
        raw_output = run_nikto(client, target, p, extra_options)

        findings = parse_csv(raw_output)
        if not findings:
            print(f"[nikto] CSV parse empty or failed pour port {p!r} — fallback text parser.")
            findings = parse_text(raw_output)

        # Marque le port scanné sur chaque finding pour distinguer les résultats
        for f in findings:
            if p:
                f.path = f"[:{p}]{f.path}"

        print_results(findings)
        print(f"[nikto] {len(findings)} finding(s) détecté(s) pour port {p!r}.")
        all_findings.extend(findings)

    print(f"\n[nikto] TOTAL: {len(all_findings)} finding(s) détecté(s) sur {len(ports)} port(s).")

    return [f.to_dict() for f in all_findings]


# ---------------------------------------------------------------------------
# PDF render hook
# ---------------------------------------------------------------------------

_SEV_COLORS = {
    "high":   "#ff4d4d",
    "medium": "#f5a623",
    "low":    "#4da6ff",
    "info":   "#6b6b78",
}

_SEV_BG = {
    "high":   "#1a0000",
    "medium": "#1a1000",
    "low":    "#001020",
    "info":   "#111114",
}


def pdf_render(step: dict, module: dict, styles: dict, page_width: float):
    """
    Retourne une liste de Flowables ReportLab pour le rendu PDF du module Nikto.
    Appelé par report_engine.generate_pdf() si la fonction est présente dans entry.py.
    """
    findings = step.get("output", []) or []

    if not findings:
        return [Paragraph("Aucune vulnérabilité détectée.", styles["small"])]

    C_BG      = colors.HexColor("#0d0d0f")
    C_SURFACE = colors.HexColor("#141416")
    C_BORDER  = colors.HexColor("#2a2a2e")
    C_TEXT    = colors.HexColor("#e8e8ec")
    C_MUTED   = colors.HexColor("#6b6b78")

    def sev_color(sev: str):
        return colors.HexColor(_SEV_COLORS.get(sev, "#6b6b78"))

    data = [["ID", "Sév.", "Catégorie", "Méthode", "Chemin", "Description"]]

    for f in findings:
        if isinstance(f, dict):
            fid   = f.get("id", "")
            sev   = f.get("severity", "info")
            cat   = f.get("category", "other")
            meth  = f.get("method", "GET")
            path  = f.get("path", "/")
            desc  = f.get("description", "")
        else:
            fid   = getattr(f, "id", "")
            sev   = getattr(f, "severity", "info")
            cat   = getattr(f, "category", "other")
            meth  = getattr(f, "method", "GET")
            path  = getattr(f, "path", "/")
            desc  = getattr(f, "description", "")

        sev_hex = _SEV_COLORS.get(sev, "#6b6b78")
        data.append([
            Paragraph(f'<font color="#e8e8ec"><b>{fid}</b></font>', styles["mono"]),
            Paragraph(f'<font color="{sev_hex}"><b>{sev.upper()}</b></font>', styles["mono"]),
            Paragraph(cat, styles["small"]),
            Paragraph(meth, styles["mono_mut"]),
            Paragraph(path[:40], styles["mono_mut"]),
            Paragraph(desc[:120], styles["small"]),
        ])

    col_w = [22*mm, 14*mm, 20*mm, 14*mm, 38*mm, page_width - 108*mm]
    tbl = Table(data, colWidths=col_w, repeatRows=1)
    tbl.setStyle(TableStyle([
        ("BACKGROUND",    (0, 0), (-1, 0), C_SURFACE),
        ("TEXTCOLOR",     (0, 0), (-1, 0), C_MUTED),
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",      (0, 0), (-1, -1), 8),
        ("FONTNAME",      (0, 1), (-1, -1), "Helvetica"),
        ("TEXTCOLOR",     (0, 1), (-1, -1), C_TEXT),
        ("BACKGROUND",    (0, 1), (-1, -1), C_BG),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_BG, colors.HexColor("#161618")]),
        ("GRID",          (0, 0), (-1, -1), 0.4, C_BORDER),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("RIGHTPADDING",  (0, 0), (-1, -1), 6),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("VALIGN",        (0, 0), (-1, -1), "MIDDLE"),
    ]))
    return [tbl]