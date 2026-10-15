#!/usr/bin/env python3
"""
Pruebas de la demo: levanta ambas apps en cada modo (HTTP, sin TLS) y verifica
que las vulnerabilidades funcionan en 'vuln' y quedan bloqueadas en 'fixed'.

Uso:
    tests/run.sh                 # crea venv con Flask y ejecuta esto
    python3 tests/test_demo.py   # si ya tienes Flask instalado

Sale con codigo 0 si todo pasa, 1 si algo falla.
"""
import http.client
import os
import re
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS = []


def req(port, method, path, cookie=None, body=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    headers = {}
    if cookie:
        headers["Cookie"] = cookie
    if body is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    c.request(method, path, body=body, headers=headers)
    r = c.getresponse()
    data = r.read().decode("utf-8", "replace")
    setc = r.getheader("Set-Cookie")
    c.close()
    return r.status, setc, data


def cookie_from(setc, name):
    m = re.search(rf"{name}=([^;]+)", setc or "")
    return f"{name}={m.group(1)}" if m else None


def check(label, cond):
    RESULTS.append(cond)
    print(("  PASS " if cond else "  FAIL ") + label)


def wait_up(port, path):
    for _ in range(40):
        try:
            req(port, "GET", path)
            return True
        except OSError:
            time.sleep(0.25)
    return False


def start(mode):
    for db in ("cola/cola.db", "penguin/penguin.db"):
        try:
            os.remove(os.path.join(ROOT, db))
        except FileNotFoundError:
            pass
    env = dict(os.environ, DEMO_MODE=mode)
    env.pop("TLS_CERT", None)
    env.pop("TLS_KEY", None)
    procs = [
        subprocess.Popen([sys.executable, os.path.join(ROOT, "cola", "app.py")],
                         env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL),
        subprocess.Popen([sys.executable, os.path.join(ROOT, "penguin", "app.py")],
                         env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL),
    ]
    if not (wait_up(8000, "/") and wait_up(8001, "/login")):
        raise RuntimeError("las apps no levantaron (falta Flask?)")
    return procs


def stop(procs):
    for p in procs:
        p.terminate()
    for p in procs:
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()


def run_penguin(mode):
    print(f"=== PENGUIN (CSRF) modo={mode} ===")
    st, _, _ = req(8001, "GET", "/login")
    check("sin sesion se muestra el login", st == 200)
    st, setc, _ = req(8001, "POST", "/login", body="usuario=pingu1&clave=hielo123")
    pc = cookie_from(setc, "pingu_sid")
    check("login 302 + cookie", st == 302 and pc is not None)
    if mode == "vuln":
        check("cookie SameSite=None + Secure",
              "SameSite=None" in (setc or "") and "Secure" in (setc or ""))
        st, setc, _ = req(8001, "GET", "/account/change-email?new=atacante@evil.cl", cookie=pc)
        check("GET del exploit no borra ni rota la cookie", st == 200 and setc is None)
        check_penguin_session(pc, "atacante@evil.cl", "GET del exploit")
        st, setc, _ = req(8001, "POST", "/account/change-email", cookie=pc, body="new=post@evil.cl")
        check("POST del exploit no borra ni rota la cookie", st == 302 and setc is None)
        check_penguin_session(pc, "post@evil.cl", "POST del exploit")
    else:
        check("cookie SameSite=Strict + HttpOnly",
              "SameSite=Strict" in (setc or "") and "HttpOnly" in (setc or ""))
        st, _, _ = req(8001, "GET", "/account/change-email?new=atacante@evil.cl", cookie=pc)
        check("GET rechazado (405)", st == 405)
        st, _, _ = req(8001, "POST", "/account/change-email", cookie=pc, body="new=atacante@evil.cl")
        check("POST sin token rechazado (403)", st == 403)
        _, _, cuenta = req(8001, "GET", "/cuenta", cookie=pc)
        m = re.search(r'name="csrf_token" value="([^"]+)"', cuenta)
        tok = m.group(1) if m else ""
        st, _, _ = req(8001, "POST", "/account/change-email", cookie=pc,
                       body=f"new=legit@correo.cl&csrf_token={tok}")
        _, _, body = req(8001, "GET", "/igloo", cookie=pc)
        check("POST con token valido funciona", st == 302 and "legit@correo.cl" in body)
        check("el correo nunca cambio al del atacante", "atacante@evil.cl" not in body)
        check_penguin_session(pc, "legit@correo.cl", "cambio autorizado")

    req(8001, "GET", "/logout", cookie=pc)
    st, _, _ = req(8001, "GET", "/igloo", cookie=pc)
    check("Salir sigue invalidando la sesion", st == 302)
    st, _, _ = req(8001, "GET", "/login", cookie=pc)
    check("despues de Salir se muestra el login", st == 200)


def check_penguin_session(cookie, email, label):
    st, _, body = req(8001, "GET", "/igloo", cookie=cookie)
    check(f"{label}: mismo sid conserva el iglu con el correo actualizado",
          st == 200 and "pingu1" in body and email in body)
    st, _, body = req(8001, "GET", "/cuenta", cookie=cookie)
    check(f"{label}: mismo sid conserva el acceso a la cuenta",
          st == 200 and email in body)
    st, setc, body = req(8001, "GET", "/login", cookie=cookie)
    check(f"{label}: login vuelve al iglu sin pedir credenciales ni rotar cookie",
          st == 302 and "/igloo" in body and setc is None)


def run_cola(mode):
    print(f"=== COLA (Broken Auth) modo={mode} ===")
    st, _, queue = req(8000, "GET", "/")
    check("cola fija con cinco usuarios y solo uno con acceso",
          st == 200 and all(f"estudiante{i}" in queue for i in range(1, 6))
          and queue.count("Con acceso") == 1 and queue.count("En espera") == 4)
    st, setc, _ = req(8000, "POST", "/login", body="usuario=estudiante1&clave=clave123")
    first_cookie = cookie_from(setc, "sid")
    st_dashboard, _, _ = req(8000, "GET", "/dashboard", cookie=first_cookie)
    check("primer usuario tiene acceso inmediato", st == 302 and st_dashboard == 200)
    req(8000, "GET", "/logout", cookie=first_cookie)
    _, _, queue_after = req(8000, "GET", "/")
    check("cerrar sesion y recargar no hace avanzar la cola", queue_after == queue)
    for user, password in (("estudiante2", "panda2024"), ("estudiante3", "clave345"),
                           ("estudiante4", "clave456"), ("estudiante5", "clave567")):
        st, setc, body = req(8000, "POST", "/login", body=f"usuario={user}&clave={password}")
        check(f"{user} sigue en espera al entrar directamente al login",
              st == 403 and setc is None and "sigue en espera" in body)
    _, setc, _ = req(8000, "POST", "/login", body="usuario=estudiante1&clave=clave123")
    sid_val = cookie_from(setc, "sid").split("=", 1)[1]
    _, setc2, _ = req(8000, "POST", "/login", cookie="sid=ZZZpreset",
                      body="usuario=estudiante1&clave=clave123")
    sid_preset = cookie_from(setc2, "sid").split("=", 1)[1]
    if mode == "vuln":
        check("sid predecible (= id usuario '1')", sid_val == "1")
        check("fixation: reutiliza el sid del cliente", sid_preset == "ZZZpreset")
        st, _, body = req(8000, "GET", "/whoami", cookie="sid=1")
        check("hijack: sid '1' da acceso", st == 200 and "estudiante1" in body)
    else:
        check("sid aleatorio largo (no predecible)", sid_val != "1" and len(sid_val) > 20)
        check("rotacion al login (!= cookie entrante)", sid_preset != "ZZZpreset" and len(sid_preset) > 20)
        st, _, _ = req(8000, "GET", "/whoami", cookie="sid=1")
        check("sid '1' NO da acceso (401)", st == 401)
        st, _, body = req(8000, "GET", "/whoami", cookie=f"sid={sid_val}")
        check("sid valido desde mismo origen funciona", st == 200 and "estudiante1" in body)


def main():
    for mode in ("vuln", "fixed"):
        procs = start(mode)
        try:
            run_penguin(mode)
            run_cola(mode)
        finally:
            stop(procs)
        print()
    for db in ("cola/cola.db", "penguin/penguin.db"):
        try:
            os.remove(os.path.join(ROOT, db))
        except FileNotFoundError:
            pass
    total, passed = len(RESULTS), sum(RESULTS)
    print(f"RESULTADO: {passed}/{total} " + ("TODO OK" if passed == total else "HAY FALLAS"))
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
