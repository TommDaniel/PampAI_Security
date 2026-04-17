"""
PampaSec — Atualizador Automatico de Blacklist e Whitelist
===========================================================
Executa os coletores de blacklist e whitelist, compara com as listas
existentes na extensao, reporta diferencas (novas URLs / removidas),
e copia os JSONs atualizados para extensao-phishing/assets/.

Pode ser agendado via cron (Linux) ou Task Scheduler (Windows):
  # Diario as 03:00
  0 3 * * * cd /path/to/TCC && python scripts/atualizar_listas.py

Ou executado manualmente:
  python scripts/atualizar_listas.py [--dry-run] [--top N]

Flags:
  --dry-run   Mostra o que mudaria sem copiar os arquivos
  --top N     Quantidade de dominios Tranco/Majestic (default: 10000)
  --log FILE  Salva log da execucao em arquivo (append)
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone

# ============================================================
# Caminhos relativos a raiz do TCC
# ============================================================

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(SCRIPT_DIR)

BLACKLIST_DIR = os.path.join(ROOT_DIR, "blacklist")
WHITELIST_DIR = os.path.join(ROOT_DIR, "whitelist")
EXTENSION_ASSETS = os.path.join(ROOT_DIR, "extensao-phishing", "assets")

BLACKLIST_SCRIPT = os.path.join(BLACKLIST_DIR, "coletar_blacklist.py")
WHITELIST_SCRIPT = os.path.join(WHITELIST_DIR, "coletar_whitelist.py")

BLACKLIST_JSON = os.path.join(BLACKLIST_DIR, "blacklist.json")
WHITELIST_JSON = os.path.join(WHITELIST_DIR, "whitelist.json")

EXT_BLACKLIST_JSON = os.path.join(EXTENSION_ASSETS, "blacklist.json")
EXT_WHITELIST_JSON = os.path.join(EXTENSION_ASSETS, "whitelist.json")

HISTORY_FILE = os.path.join(ROOT_DIR, "scripts", "atualizacao_historico.json")


# ============================================================
# Helpers
# ============================================================

def load_json_set(path: str) -> set[str]:
    """Carrega um JSON (array de strings) como set."""
    if not os.path.isfile(path):
        return set()
    with open(path, encoding="utf-8") as f:
        return set(json.load(f))


def diff_sets(old: set[str], new: set[str]) -> tuple[set[str], set[str]]:
    """Retorna (adicionados, removidos)."""
    return new - old, old - new


def log(msg: str, log_file=None):
    """Imprime e opcionalmente escreve em arquivo de log."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    line = f"[{ts}] {msg}"
    print(line)
    if log_file:
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(line + "\n")


def save_history(entry: dict):
    """Salva historico de atualizacoes para auditoria."""
    history = []
    if os.path.isfile(HISTORY_FILE):
        with open(HISTORY_FILE, encoding="utf-8") as f:
            try:
                history = json.load(f)
            except json.JSONDecodeError:
                history = []

    history.append(entry)

    # Manter apenas as ultimas 100 execucoes
    history = history[-100:]

    with open(HISTORY_FILE, "w", encoding="utf-8") as f:
        json.dump(history, f, indent=2, ensure_ascii=False)


# ============================================================
# Execucao dos coletores
# ============================================================

def run_collector(script_path: str, cwd: str, extra_args: list[str] = None) -> bool:
    """Executa um script coletor e retorna True se sucesso."""
    cmd = [sys.executable, script_path] + (extra_args or [])
    log(f"  Executando: {' '.join(cmd)}")
    log(f"  Diretorio: {cwd}")

    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=600  # 10 min max
        )
        if result.stdout:
            for line in result.stdout.strip().split("\n"):
                log(f"    {line}")
        if result.returncode != 0:
            log(f"  ERRO (exit code {result.returncode})")
            if result.stderr:
                for line in result.stderr.strip().split("\n")[-10:]:
                    log(f"    STDERR: {line}")
            return False
        return True
    except subprocess.TimeoutExpired:
        log("  TIMEOUT (>10min)")
        return False
    except Exception as e:
        log(f"  EXCECAO: {e}")
        return False


# ============================================================
# Main
# ============================================================

def main():
    parser = argparse.ArgumentParser(description="PampaSec — Atualizador de listas")
    parser.add_argument("--dry-run", action="store_true",
                        help="Mostra diferencas sem copiar arquivos")
    parser.add_argument("--top", type=int, default=10000,
                        help="Top N dominios Tranco/Majestic (default: 10000)")
    parser.add_argument("--log", type=str, default=None,
                        help="Arquivo de log (append)")
    args = parser.parse_args()

    log_file = args.log
    timestamp = datetime.now(timezone.utc).isoformat()

    log("=" * 60, log_file)
    log("  PampaSec — Atualizador de Blacklist e Whitelist", log_file)
    log("=" * 60, log_file)

    # 1. Carregar listas atuais da extensao (antes da atualizacao)
    log("\n[1/5] Carregando listas atuais da extensao...", log_file)
    old_blacklist = load_json_set(EXT_BLACKLIST_JSON)
    old_whitelist = load_json_set(EXT_WHITELIST_JSON)
    log(f"  Blacklist atual: {len(old_blacklist):,} dominios", log_file)
    log(f"  Whitelist atual: {len(old_whitelist):,} dominios", log_file)

    # 2. Executar coletor de blacklist
    log("\n[2/5] Coletando blacklist...", log_file)
    bl_ok = run_collector(BLACKLIST_SCRIPT, BLACKLIST_DIR)
    if not bl_ok:
        log("  AVISO: Coleta de blacklist falhou. Mantendo lista atual.", log_file)

    # 3. Executar coletor de whitelist
    log("\n[3/5] Coletando whitelist...", log_file)
    wl_ok = run_collector(WHITELIST_SCRIPT, WHITELIST_DIR, ["--top", str(args.top)])
    if not wl_ok:
        log("  AVISO: Coleta de whitelist falhou. Mantendo lista atual.", log_file)

    # 4. Comparar e reportar diferencas
    log("\n[4/5] Comparando listas...", log_file)

    new_blacklist = load_json_set(BLACKLIST_JSON) if bl_ok else old_blacklist
    new_whitelist = load_json_set(WHITELIST_JSON) if wl_ok else old_whitelist

    bl_added, bl_removed = diff_sets(old_blacklist, new_blacklist)
    wl_added, wl_removed = diff_sets(old_whitelist, new_whitelist)

    log(f"\n  BLACKLIST:", log_file)
    log(f"    Antes: {len(old_blacklist):,} -> Depois: {len(new_blacklist):,}", log_file)
    log(f"    Novos dominios:    +{len(bl_added):,}", log_file)
    log(f"    Dominios removidos: -{len(bl_removed):,}", log_file)
    if bl_added and len(bl_added) <= 20:
        for d in sorted(bl_added):
            log(f"      + {d}", log_file)
    elif bl_added:
        for d in sorted(bl_added)[:10]:
            log(f"      + {d}", log_file)
        log(f"      ... e mais {len(bl_added) - 10}", log_file)

    log(f"\n  WHITELIST:", log_file)
    log(f"    Antes: {len(old_whitelist):,} -> Depois: {len(new_whitelist):,}", log_file)
    log(f"    Novos dominios:    +{len(wl_added):,}", log_file)
    log(f"    Dominios removidos: -{len(wl_removed):,}", log_file)
    if wl_added and len(wl_added) <= 20:
        for d in sorted(wl_added):
            log(f"      + {d}", log_file)
    elif wl_added:
        for d in sorted(wl_added)[:10]:
            log(f"      + {d}", log_file)
        log(f"      ... e mais {len(wl_added) - 10}", log_file)

    # Verificar conflitos (dominio em ambas as listas)
    conflicts = new_blacklist & new_whitelist
    if conflicts:
        log(f"\n  CONFLITOS (em ambas listas): {len(conflicts)}", log_file)
        for d in sorted(conflicts)[:10]:
            log(f"    ! {d}", log_file)
        log("    Whitelist tem prioridade na extensao.", log_file)

    # 5. Copiar para a extensao
    log("\n[5/5] Atualizando extensao...", log_file)

    if args.dry_run:
        log("  --dry-run: nenhum arquivo copiado.", log_file)
    else:
        copied = []
        if bl_ok and (bl_added or bl_removed):
            shutil.copy2(BLACKLIST_JSON, EXT_BLACKLIST_JSON)
            log(f"  Copiado: blacklist.json -> extensao ({len(new_blacklist):,} dominios)", log_file)
            copied.append("blacklist")
        elif not bl_added and not bl_removed:
            log("  Blacklist sem alteracoes — nao copiada.", log_file)

        if wl_ok and (wl_added or wl_removed):
            shutil.copy2(WHITELIST_JSON, EXT_WHITELIST_JSON)
            log(f"  Copiado: whitelist.json -> extensao ({len(new_whitelist):,} dominios)", log_file)
            copied.append("whitelist")
        elif not wl_added and not wl_removed:
            log("  Whitelist sem alteracoes — nao copiada.", log_file)

        if copied:
            log(f"\n  Listas atualizadas. Rebuild da extensao necessario:", log_file)
            log(f"    cd extensao-phishing && npm run build", log_file)

    # Salvar historico
    history_entry = {
        "timestamp": timestamp,
        "blacklist": {
            "success": bl_ok,
            "before": len(old_blacklist),
            "after": len(new_blacklist),
            "added": len(bl_added),
            "removed": len(bl_removed),
        },
        "whitelist": {
            "success": wl_ok,
            "before": len(old_whitelist),
            "after": len(new_whitelist),
            "added": len(wl_added),
            "removed": len(wl_removed),
        },
        "conflicts": len(conflicts) if conflicts else 0,
        "dry_run": args.dry_run,
    }
    save_history(history_entry)

    log("\n" + "=" * 60, log_file)
    log("  Atualizacao concluida.", log_file)
    log("=" * 60, log_file)


if __name__ == "__main__":
    main()
