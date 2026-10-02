"""MagAudit dependency check — the GitHub Action entry point.

POR QUE EXISTE
--------------
Es la puerta de entrada gratuita que recomendo el analisis externo del
2026-09-27 (docs/POSICIONAMIENTO.md). Corre entera en el runner del usuario:
su codigo no sale de alli, y solo los nombres de las dependencias nuevas van a
los registros publicos y a sus contadores de descargas.

QUE NO HACE, A PROPOSITO
------------------------
No decide nada. Toda la logica —que linea es una dependencia añadida, cual es
un paquete hermano del monorepo, cuando un paquete es FRESH o PHANTOM— esta en
`supply_chain.py`, y ese fichero se empaqueta **tal cual** desde el producto.
Lo unico que añade es contexto que la App no tiene: los manifiestos del
repositorio entero, via `nombres_internos_del_repo`, que solo puede quitar
avisos.
Una copia reescrita aqui repetiria los falsos positivos que ya se corrigieron
alli uno a uno (subidas de version leidas como altas, `workspace:*`,
`[project.scripts]`, `current_version`...). Este fichero solo consigue el diff,
llama al analisis y traduce el resultado a anotaciones de GitHub.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from typing import Callable, Optional

from src.github_app.supply_chain import (http_registry, nombres_internos_del_repo,
                                         scan_supply_chain)

# Que severidades hacen fallar el check. Por defecto, igual que la App: CRITICAL
# (el paquete no existe) y HIGH (publicado hace dias, casi sin uso).
FALLA_EN = {
    "critical": {"CRITICAL"},
    "high": {"CRITICAL", "HIGH"},
    "none": set(),
}


class SinDiff(Exception):
    """No se pudo calcular el diff del pull request."""


def _git(args: list, cwd: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True,
                          encoding="utf-8", errors="replace")


def diff_del_pr(evento: dict, cwd: str) -> str:
    """El diff del PR, con el mismo formato que la App recibe de GitHub.

    Tres puntos (`base...head`): lo que el PR añade desde que se separo de la
    rama base, que es exactamente lo que GitHub ensena como diff del PR. Si el
    checkout es superficial y falta historia, se pide antes de rendirse; si aun
    asi no se puede, se dice, en vez de analizar un diff equivocado.
    """
    pr = evento.get("pull_request") or {}
    base = (pr.get("base") or {}).get("sha")
    head = (pr.get("head") or {}).get("sha")
    if not base or not head:
        raise SinDiff("the event has no pull_request base/head")
    args = ["diff", "--no-color", "--no-ext-diff", "--unified=3", f"{base}...{head}"]
    r = _git(args, cwd)
    if r.returncode != 0:
        _git(["fetch", "--no-tags", "--quiet", "origin", base, head], cwd)
        if _git(["rev-parse", "--is-shallow-repository"], cwd).stdout.strip() == "true":
            _git(["fetch", "--no-tags", "--quiet", "--unshallow", "origin"], cwd)
        r = _git(args, cwd)
    if r.returncode != 0:
        raise SinDiff("could not compute the pull request diff. Check out the repository "
                      "with `fetch-depth: 0` (see the README).")
    return r.stdout


def _dato(s: str) -> str:
    """Escape para el mensaje de un comando de flujo de GitHub."""
    return str(s).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _propiedad(s: str) -> str:
    """Escape para una propiedad (file, title...) de un comando de flujo."""
    return _dato(s).replace(":", "%3A").replace(",", "%2C")


_NIVEL = {"CRITICAL": "error", "HIGH": "warning"}


def anotaciones(res: dict) -> list:
    """Una anotacion por hallazgo, sobre el fichero y la linea del PR."""
    lineas = []
    for f in res["findings"]:
        nivel = _NIVEL.get(f["severity"], "notice")
        titulo = f"{f['severity']}: {f['title']}"
        cuerpo = f"{f['why']} {f['remediation']}"
        lineas.append(f"::{nivel} file={_propiedad(f['file'])},line={int(f['line'])},"
                      f"title={_propiedad(titulo)}::{_dato(cuerpo)}")
    return lineas


def resumen(res: dict) -> str:
    """El resumen del job, en Markdown."""
    L = ["## MagAudit dependency check", ""]
    n = res.get("deps_scanned", 0)
    if not res["findings"]:
        L.append(f"{n} new dependenc{'y' if n == 1 else 'ies'} checked against the registries. "
                 "Nothing to report.")
    else:
        L += [f"{n} new dependenc{'y' if n == 1 else 'ies'} checked. "
              f"{len(res['findings'])} need a look:", "",
              "| Severity | Package | File | Why |", "|---|---|---|---|"]
        for f in res["findings"]:
            why = f["why"].replace("|", "\\|").replace("\n", " ")
            L.append(f"| {f['severity']} | `{f['snippet']}` | `{f['file']}:{f['line']}` | {why} |")
    L += ["", "Only package names left this runner, to the package registries and their "
          "download counters. Your code did not. "
          "[What else MagAudit checks](https://magsolutionsai.com/)"]
    return "\n".join(L) + "\n"


def main(entorno: Optional[dict] = None,
         registry: Optional[Callable] = None,
         escribir: Callable[[str], None] = print) -> int:
    e = entorno if entorno is not None else os.environ
    falla_en = FALLA_EN.get((e.get("MAGAUDIT_FAIL_ON") or "high").strip().lower())
    if falla_en is None:
        escribir("::error::fail-on must be one of: critical, high, none")
        return 2

    if e.get("GITHUB_EVENT_NAME") not in ("pull_request", "pull_request_target"):
        escribir("::notice::MagAudit dependency check only runs on pull requests.")
        return 0
    raiz = e.get("GITHUB_WORKSPACE") or os.getcwd()
    try:
        with open(e["GITHUB_EVENT_PATH"], encoding="utf-8") as fh:
            evento = json.load(fh)
        diff = diff_del_pr(evento, raiz)
    except (OSError, KeyError, ValueError, SinDiff) as exc:
        escribir(f"::error::{_dato(exc)}")
        return 2

    # Lo que la App no puede ver: el repositorio entero. Solo QUITA avisos
    # (paquetes que el repo define, o que instala desde una ruta o desde git).
    res = scan_supply_chain(diff, registry if registry is not None else http_registry(),
                            internos=nombres_internos_del_repo(raiz))
    for linea in anotaciones(res):
        escribir(linea)
    ruta = e.get("GITHUB_STEP_SUMMARY")
    if ruta:
        with open(ruta, "a", encoding="utf-8") as fh:
            fh.write(resumen(res))

    graves = [f for f in res["findings"] if f["severity"] in falla_en]
    return 1 if graves else 0


if __name__ == "__main__":
    sys.exit(main())
