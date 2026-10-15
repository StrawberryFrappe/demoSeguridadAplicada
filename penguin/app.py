"""
Demo CSRF - "CRUD Penguin" (parodia de un juego infantil con backend de 2010).

El atacante logra que el navegador de la victima (con su sesion iniciada) cambie
el correo de recuperacion de la cuenta -> luego puede resetear la clave = robo de
cuenta. Se muestran dos variantes:
  - GET via <img>: con solo cargar una pagina se dispara el cambio.
  - POST auto-enviado: formulario oculto que se envia solo (variante realista 2026).

Dos modos (env DEMO_MODE=vuln|fixed). NO apunta a ningun sistema real.
"""
import os
import sqlite3
import secrets

from flask import (Flask, request, redirect, url_for, render_template,
                   make_response, abort, Response)

MODE = os.environ.get("DEMO_MODE", "vuln").lower()
PORT = 8001
COOKIE = "pingu_sid"
DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "penguin.db")

# gif transparente de 1x1 para que el <img> del atacante "cargue" sin levantar sospechas
PIXEL = (b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!\xf9\x04"
         b"\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;")

app = Flask(__name__)

# sid -> {uid, user, csrf}
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
            id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT,
            recovery_email TEXT, monedas INTEGER);
        """
    )
    if not c.execute("SELECT 1 FROM users").fetchone():
        c.execute("INSERT INTO users VALUES(1,'pingu1','hielo123','pingu1@correo.cl',4200)")
    c.commit()
    c.close()


def current():
    sid = request.cookies.get(COOKIE)
    return SESSIONS.get(sid) if sid else None


def set_session_cookie(resp, sid):
    if MODE == "vuln":
        # SameSite=None -> la cookie viaja en peticiones cross-site (habilita CSRF).
        # (None exige Secure; por eso el servidor corre en HTTPS en las VMs.)
        resp.set_cookie(COOKIE, sid, samesite="None", secure=True)
    else:
        resp.set_cookie(COOKIE, sid, httponly=True, samesite="Strict",
                        secure=bool(os.environ.get("TLS_CERT")))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET" and current():
        return redirect(url_for("igloo"))
    if request.method == "POST":
        row = db().execute(
            "SELECT * FROM users WHERE username=? AND password=?",
            (request.form.get("usuario", ""), request.form.get("clave", "")),
        ).fetchone()
        if not row:
            return render_template("login.html", mode=MODE, error="Datos incorrectos")
        sid = secrets.token_urlsafe(24)
        SESSIONS[sid] = {"uid": row["id"], "user": row["username"],
                         "csrf": secrets.token_urlsafe(24)}
        resp = make_response(redirect(url_for("igloo")))
        set_session_cookie(resp, sid)
        return resp
    return render_template("login.html", mode=MODE)


@app.route("/igloo")
def igloo():
    s = current()
    if not s:
        return redirect(url_for("login"))
    u = db().execute("SELECT * FROM users WHERE id=?", (s["uid"],)).fetchone()
    return render_template("igloo.html", mode=MODE, u=u)


@app.route("/cuenta")
def cuenta():
    s = current()
    if not s:
        return redirect(url_for("login"))
    u = db().execute("SELECT * FROM users WHERE id=?", (s["uid"],)).fetchone()
    return render_template("cuenta.html", mode=MODE, u=u, csrf=s["csrf"])


@app.route("/account/change-email", methods=["GET", "POST"])
def change_email():
    s = current()
    if not s:
        return redirect(url_for("login"))

    if MODE == "vuln":
        # VULNERABLE: acepta GET o POST, sin token anti-CSRF.
        new = request.values.get("new")
        if new:
            db_conn = db()
            db_conn.execute("UPDATE users SET recovery_email=? WHERE id=?", (new, s["uid"]))
            db_conn.commit()
            db_conn.close()
        if request.method == "GET":
            # responde una imagen -> el <img> del atacante no muestra nada roto
            return Response(PIXEL, mimetype="image/gif")
        return redirect(url_for("igloo"))

    # FIXED: solo POST + token anti-CSRF validado en servidor.
    if request.method != "POST":
        abort(405)
    if request.form.get("csrf_token") != s["csrf"]:
        abort(403, "Token CSRF invalido o ausente")
    new = request.form.get("new")
    if new:
        db_conn = db()
        db_conn.execute("UPDATE users SET recovery_email=? WHERE id=?", (new, s["uid"]))
        db_conn.commit()
        db_conn.close()
    return redirect(url_for("igloo"))


@app.route("/logout")
def logout():
    SESSIONS.pop(request.cookies.get(COOKIE), None)
    resp = make_response(redirect(url_for("login")))
    resp.delete_cookie(COOKIE)
    return resp


if __name__ == "__main__":
    init_db()
    cert, key = os.environ.get("TLS_CERT"), os.environ.get("TLS_KEY")
    ctx = (cert, key) if cert and key and os.path.exists(cert) else None
    print(f"[penguin] DEMO_MODE={MODE} TLS={'on' if ctx else 'off'} :{PORT}")
    app.run(host="0.0.0.0", port=PORT, ssl_context=ctx, threaded=True)
