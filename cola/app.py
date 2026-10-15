"""
Demo Broken Authentication / Session Management.

Reproduce (en laboratorio aislado) el hecho real: un estudiante copio la cookie
de sesion de un companiero y ambos quedaron dentro del sistema de inscripcion
AL MISMO TIEMPO. El sistema real queda detras de una sala de espera (Queue-it);
aqui se replica la fachada de la sala de espera + la sesion vulnerable detras.

Un solo codigo, dos modos (env DEMO_MODE=vuln|fixed) para mostrar el ataque y
luego la correccion en vivo. NO apunta a ningun sistema real.
"""
import os
import sqlite3
import secrets
import time

from flask import (Flask, request, redirect, url_for, render_template,
                   make_response, jsonify, abort)

MODE = os.environ.get("DEMO_MODE", "vuln").lower()
PORT = 8000
COOKIE = "sid"
DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cola.db")

IDLE_TIMEOUT = 300       # 5 min sin actividad
ABSOLUTE_TIMEOUT = 1800  # 30 min de vida maxima

# Cola fija para la demo: solo el primer usuario tiene turno, incluso al salir.
QUEUE_USERS = (
    {"id": 1, "username": "estudiante1", "password": "clave123", "nombre": "Ana Diaz"},
    {"id": 2, "username": "estudiante2", "password": "panda2024", "nombre": "Luis Soto"},
    {"id": 3, "username": "estudiante3", "password": "clave345", "nombre": "Camila Rojas"},
    {"id": 4, "username": "estudiante4", "password": "clave456", "nombre": "Diego Perez"},
    {"id": 5, "username": "estudiante5", "password": "clave567", "nombre": "Sofia Torres"},
)

app = Flask(__name__)

# Almacen de sesiones en memoria: sid -> {uid, user, nombre, ip, ua, created, last}
SESSIONS = {}


def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c


def init_db():
    c = db()
    c.executescript(
        """
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY, username TEXT UNIQUE,
            password TEXT, nombre TEXT);
        CREATE TABLE IF NOT EXISTS ramos(
            id INTEGER PRIMARY KEY, uid INTEGER, sigla TEXT, nombre TEXT);
        """
    )
    if not c.execute("SELECT 1 FROM users").fetchone():
        c.executemany(
            "INSERT INTO ramos(uid,sigla,nombre) VALUES(?,?,?)",
            [(1, "IIC2113", "Diseno de Software"),
             (1, "MAT1610", "Calculo I"),
             (2, "IIC2233", "Programacion Avanzada")],
        )
    c.executemany(
        "INSERT OR IGNORE INTO users(id,username,password,nombre) "
        "VALUES(:id,:username,:password,:nombre)",
        QUEUE_USERS,
    )
    c.commit()
    c.close()


def new_sid(uid):
    # vuln: id predecible y adivinable (el del usuario). fixed: aleatorio de 256 bits.
    return str(uid) if MODE == "vuln" else secrets.token_urlsafe(32)


def current():
    sid = request.cookies.get(COOKIE)
    if not sid or sid not in SESSIONS:
        return None
    s = SESSIONS[sid]
    if MODE == "fixed":
        now = time.time()
        if now - s["created"] > ABSOLUTE_TIMEOUT or now - s["last"] > IDLE_TIMEOUT:
            SESSIONS.pop(sid, None)
            return None
        # sesion atada a la IP de origen -> una cookie robada desde otra maquina no sirve
        if s["ip"] != request.remote_addr:
            return None
        s["last"] = now
    return s


@app.route("/")
def sala_espera():
    return render_template("sala_espera.html", mode=MODE, queue=QUEUE_USERS)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form.get("usuario", "")
        p = request.form.get("clave", "")
        row = db().execute(
            "SELECT * FROM users WHERE username=? AND password=?", (u, p)
        ).fetchone()
        if not row:
            return render_template("login.html", mode=MODE, error="Credenciales invalidas")
        if row["username"] != QUEUE_USERS[0]["username"]:
            return render_template(
                "login.html", mode=MODE,
                error="Tu usuario sigue en espera. Solo el primer usuario de la cola tiene acceso.",
            ), 403

        now = time.time()
        if MODE == "vuln":
            # FIXATION: si ya viene un sid del cliente, se reutiliza; no se rota al loguear.
            sid = request.cookies.get(COOKIE) or new_sid(row["id"])
            SESSIONS[sid] = {"uid": row["id"], "user": row["username"],
                             "nombre": row["nombre"], "ip": None, "ua": None,
                             "created": now, "last": now}
            resp = make_response(redirect(url_for("dashboard")))
            # cookie sin HttpOnly / Secure / SameSite
            resp.set_cookie(COOKIE, sid)
        else:
            # rotacion de sesion al autenticar + atado a IP/UA + flags de cookie
            old = request.cookies.get(COOKIE)
            SESSIONS.pop(old, None)
            sid = new_sid(row["id"])
            SESSIONS[sid] = {"uid": row["id"], "user": row["username"],
                             "nombre": row["nombre"], "ip": request.remote_addr,
                             "ua": request.headers.get("User-Agent", ""),
                             "created": now, "last": now}
            resp = make_response(redirect(url_for("dashboard")))
            resp.set_cookie(COOKIE, sid, httponly=True, samesite="Strict",
                            secure=bool(os.environ.get("TLS_CERT")))
        return resp
    return render_template("login.html", mode=MODE)


@app.route("/dashboard")
def dashboard():
    s = current()
    if not s:
        return redirect(url_for("login"))
    ramos = db().execute("SELECT sigla,nombre FROM ramos WHERE uid=?", (s["uid"],)).fetchall()
    sid = request.cookies.get(COOKIE)
    return render_template("dashboard.html", mode=MODE, s=s, ramos=ramos, sid=sid)


@app.route("/whoami")
def whoami():
    # usado por el atacante (hijack.sh) para probar si la cookie copiada da acceso
    s = current()
    if not s:
        return jsonify(autenticado=False), 401
    return jsonify(autenticado=True, usuario=s["user"], nombre=s["nombre"],
                   ip_sesion=s["ip"], ip_peticion=request.remote_addr)


@app.route("/logout")
def logout():
    SESSIONS.pop(request.cookies.get(COOKIE), None)
    resp = make_response(redirect(url_for("sala_espera")))
    resp.delete_cookie(COOKIE)
    return resp


if __name__ == "__main__":
    init_db()
    cert, key = os.environ.get("TLS_CERT"), os.environ.get("TLS_KEY")
    ctx = (cert, key) if cert and key and os.path.exists(cert) else None
    print(f"[cola] DEMO_MODE={MODE} TLS={'on' if ctx else 'off'} :{PORT}")
    app.run(host="0.0.0.0", port=PORT, ssl_context=ctx, threaded=True)
