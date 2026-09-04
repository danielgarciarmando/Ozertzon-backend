import os
import hashlib
import hmac
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

import psycopg2
from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse
from jose import JWTError, jwt
from passlib.hash import bcrypt
from pydantic import BaseModel

# ---- Sentry opcional y a prueba de versiones ----
SENTRY_DSN = os.environ.get("SENTRY_DSN")
if SENTRY_DSN:
    try:
        import sentry_sdk
        sentry_sdk.init(dsn=SENTRY_DSN, traces_sample_rate=0.1)
    except Exception as e:
        print(f"Sentry no inicializado (no bloqueante): {e}")

# ===== CONFIGURACIÓN =====
DB = os.environ.get("DATABASE_URL", "postgresql://ozertzon:ozertzon@db:5432/ozertzon")
JWT_SECRET = os.environ.get("JWT_SECRET", "OZ-JWT-SECRET-CHANGE-ME")
ALG = "HS256"
app = FastAPI(title="Ozertzon 360 API", version="3.2")

def conn():
    return psycopg2.connect(DB)

class Login(BaseModel):
    email: str
    password: str

@app.get("/healthz")
def healthz():
    return {"status": "ok", "version": "3.2"}

@app.post("/auth/login")
def login(b: Login):
    with conn() as c, c.cursor() as cur:
        cur.execute("SELECT id, password_hash, role, finca_id FROM users WHERE email=%s", (b.email,))
        row = cur.fetchone()
    if not row or not bcrypt.verify(b.password, row[1]):
        raise HTTPException(401, "Credenciales inválidas")
    token = jwt.encode({"sub": str(row[0]), "role": row[2], "finca": str(row[3]),
                        "exp": datetime.now(timezone.utc) + timedelta(hours=8)},
                       JWT_SECRET, algorithm=ALG)
    return {"access_token": token, "token_type": "bearer"}

def get_user(request: Request):
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(401, "Falta token")
    try:
        return jwt.decode(auth[7:], JWT_SECRET, algorithms=[ALG])
    except JWTError:
        raise HTTPException(401, "Token inválido")

def require_roles(*roles):
    def dep(user=Depends(get_user)):
        if user["role"] not in roles:
            raise HTTPException(403, "Sin permiso RBAC (TRD 2.4)")
        return user
    return dep

def resolve_id(cur, finca, entity, local):
    cur.execute("SELECT server_uuid FROM id_map WHERE finca_id=%s AND entity=%s AND client_id=%s",
                (finca, entity, str(local)))
    r = cur.fetchone()
    if r:
        return r[0]
    s = str(uuid.uuid4())
    cur.execute("INSERT INTO id_map(finca_id, entity, client_id, server_uuid) VALUES (%s,%s,%s,%s)",
                (finca, entity, str(local), s))
    return s

def apply_mutation(cur, finca, m):
    e, a, p = m.get("entity"), m.get("action"), m.get("payload", {})

    if e == "animals":
        au = resolve_id(cur, finca, "animals", p.get("id") or p.get("animal"))
        if a == "CREATE":
            cur.execute("""
                INSERT INTO animals(id, visual_tag_id, species, sex, breed, current_weight,
                    birth_date, sire_id, dam_id, repro_status, breeding_date,
                    pregnancy_confirmed_date, pregnancy_method, rearing, finca_id)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (id) DO NOTHING
            """, (au, p.get("tag", "?"), p.get("species", "OVINE"), p.get("sex", "F"),
                  p.get("breed", ""), p.get("kg"), p.get("birth_date"),
                  resolve_id(cur, finca, "animals", p.get("sire_id")) if p.get("sire_id") else None,
                  resolve_id(cur, finca, "animals", p.get("dam_id")) if p.get("dam_id") else None,
                  p.get("repro_status", "OPEN"), p.get("breeding_date"),
                  p.get("pregnancy_confirmed_date"), p.get("pregnancy_method", ""),
                  p.get("rearing", "MADRE"), finca))
        elif a == "UPDATE":
            cur.execute("""
                UPDATE animals SET
                    lot_id=(SELECT id FROM lots WHERE finca_id=%s AND name=%s),
                    breed=%s, current_weight=%s, repro_status=%s, breeding_date=%s,
                    pregnancy_confirmed_date=%s, pregnancy_method=%s, rearing=%s,
                    updated_at=NOW()
                WHERE id=%s
            """, (finca, p.get("lot", "L1"), p.get("breed", ""), p.get("kg"),
                  p.get("repro_status", "OPEN"), p.get("breeding_date"),
                  p.get("pregnancy_confirmed_date"), p.get("pregnancy_method", ""),
                  p.get("rearing", "MADRE"), au))

    elif e == "weight_events":
        au = resolve_id(cur, finca, "animals", p.get("animal"))
        cur.execute("""
            INSERT INTO weight_events(id, animal_id, weight_kg, date)
            VALUES (%s,%s,%s,%s)
            ON CONFLICT (id) DO NOTHING
        """, (uuid.uuid4(), au, p.get("kg"), p.get("date")))
        cur.execute("UPDATE animals SET current_weight=%s, updated_at=NOW() WHERE id=%s",
                    (p.get("kg"), au))

    elif e == "health_logs":
        au = resolve_id(cur, finca, "animals", p.get("animal"))
        cur.execute("""
            INSERT INTO health_logs(id, animal_id, protocol_name, famacha_score, applied_dose_ml,
                sync_hash, performed_by_user_id, date, withdrawal_until)
            VALUES (%s,%s,%s,%s,%s,%s,(SELECT id FROM users WHERE finca_id=%s LIMIT 1),%s,%s)
        """, (uuid.uuid4(), au, p.get("protocol", "Protocolo"), p.get("famacha"),
              p.get("dose"), (m.get("id") or "")[:64], finca, p.get("date"),
              p.get("withdrawal_until") or None))

    elif e == "protocols":
        if a == "CREATE":
            pid = resolve_id(cur, finca, "protocols", p.get("id"))
            item_uuid = resolve_id(cur, finca, "inventory_items", p.get("item_id")) if p.get("item_id") else None
            cur.execute("""
                INSERT INTO protocols(id, finca_id, name, product, dose_per_kg, concentration,
                    route, withdrawal_days, category, ptype, item_id)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (id) DO NOTHING
            """, (pid, finca, p.get("name"), p.get("product"), p.get("dose_per_kg"),
                  p.get("concentration"), p.get("route"), p.get("withdrawal_days", 0),
                  p.get("category"), p.get("ptype", "GENERAL"), item_uuid))
            for step in p.get("steps", []):
                cur.execute("""
                    INSERT INTO protocol_steps(protocol_id, day_offset, action)
                    VALUES (%s,%s,%s)
                """, (pid, step.get("day"), step.get("action")))
        elif a == "UPDATE":
            pid = resolve_id(cur, finca, "protocols", p.get("id"))
            item_uuid = resolve_id(cur, finca, "inventory_items", p.get("item_id")) if p.get("item_id") else None
            cur.execute("""
                UPDATE protocols SET
                    name=%s, product=%s, dose_per_kg=%s, concentration=%s, route=%s,
                    withdrawal_days=%s, category=%s, ptype=%s, item_id=%s
                WHERE id=%s
            """, (p.get("name"), p.get("product"), p.get("dose_per_kg"),
                  p.get("concentration"), p.get("route"), p.get("withdrawal_days", 0),
                  p.get("category"), p.get("ptype", "GENERAL"), item_uuid, pid))

    elif e == "feeding_logs":
        cur.execute("""
            INSERT INTO feeding_logs(id, finca_id, lot, feed_name, qty_kg, protein_pct, cost_per_kg, date)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
        """, (uuid.uuid4(), finca, p.get("lot"), p.get("feed"), p.get("qty"),
              p.get("protein"), p.get("cost"), p.get("date")))
    elif e == "feeding_plans":
        pid = resolve_id(cur, finca, "feeding_plans", p.get("id"))
        cur.execute("""
            INSERT INTO feeding_plans(id, finca_id, name, brand, feed_type, cost_per_kg,
                protein_pct, lot, start_date, end_date, active)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (id) DO NOTHING
        """, (pid, finca, p.get("name"), p.get("brand"), p.get("type"), p.get("cost"),
              p.get("protein"), p.get("lot"), p.get("start"), p.get("end"), p.get("active", True)))

    elif e == "lot_movements":
        au = resolve_id(cur, finca, "animals", p.get("animal"))
        cur.execute("""
            INSERT INTO lot_movements(id, finca_id, animal_id, from_lot, to_lot, date, reason)
            VALUES (%s,%s,%s,%s,%s,%s,%s)
        """, (uuid.uuid4(), finca, au, p.get("from"), p.get("to"), p.get("date"), p.get("reason")))

    elif e == "production_records":
        au = resolve_id(cur, finca, "animals", p.get("animal"))
        cur.execute("""
            INSERT INTO production_records(id, animal_id, type, qty, unit, unit_price, date)
            VALUES (%s,%s,%s,%s,%s,%s,%s)
        """, (uuid.uuid4(), au, p.get("type"), p.get("qty"), p.get("unit"),
              p.get("price"), p.get("date")))

    elif e == "dispositions":
        au = resolve_id(cur, finca, "animals", p.get("animal"))
        cur.execute("""
            INSERT INTO dispositions(id, animal_id, type, income, date, note)
            VALUES (%s,%s,%s,%s,%s,%s)
        """, (uuid.uuid4(), au, p.get("type"), p.get("income"), p.get("date"), p.get("note")))
        cur.execute("UPDATE animals SET active=FALSE WHERE id=%s", (au,))

    elif e == "purchase_orders":
        pid = resolve_id(cur, finca, "purchase_orders", p.get("id"))
        cur.execute("""
            INSERT INTO purchase_orders(id, finca_id, item_name, qty, supplier, status, date)
            VALUES (%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (id) DO NOTHING
        """, (pid, finca, p.get("item"), p.get("qty"), p.get("supplier"),
              p.get("status", "PENDIENTE"), p.get("date")))

    elif e == "incidents":
        iid = resolve_id(cur, finca, "incidents", p.get("id"))
        au = resolve_id(cur, finca, "animals", p.get("animal"))
        cur.execute("""
            INSERT INTO incidents(id, animal_id, type, severity, status, note, date, resolved_date)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (id) DO NOTHING
        """, (iid, au, p.get("type"), p.get("severity"), p.get("status", "ABIERTA"),
              p.get("note"), p.get("date"), p.get("resolved_date")))
        for note in p.get("notes", []):
            cur.execute("""
                INSERT INTO incident_notes(incident_id, note, date)
                VALUES (%s,%s,%s)
            """, (iid, note.get("text"), note.get("date")))

    elif e == "tasks":
        tid = resolve_id(cur, finca, "tasks", p.get("id"))
        cur.execute("""
            INSERT INTO tasks(id, finca_id, title, assigned_to, done, priority, started_at,
                completed_at, note, verified, due_date, source)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (id) DO NOTHING
        """, (tid, finca, p.get("title"), p.get("assigned"), p.get("done", False),
              p.get("priority"), p.get("started_at"), p.get("completed_at"),
              p.get("note"), p.get("verified", False), p.get("due_date"), p.get("source", "MANUAL")))

    elif e == "paddocks":
        pid = resolve_id(cur, finca, "paddocks", p.get("id"))
        cur.execute("""
            INSERT INTO paddocks(id, finca_id, name, area_ha, current_lot, since_date, biomass_base)
            VALUES (%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (id) DO NOTHING
        """, (pid, finca, p.get("name"), p.get("area"), p.get("lot"),
              p.get("since"), p.get("biomass", 800)))

    elif e == "rearing_milk_logs":
        au = resolve_id(cur, finca, "animals", p.get("animal"))
        donor = resolve_id(cur, finca, "animals", p.get("donor")) if p.get("donor") else None
        cur.execute("""
            INSERT INTO rearing_milk_logs(id, animal_id, date, liters, source, cost_per_liter, donor_animal_id)
            VALUES (%s,%s,%s,%s,%s,%s,%s)
        """, (uuid.uuid4(), au, p.get("date"), p.get("liters"), p.get("source"),
              p.get("cost"), donor))

@app.post("/api/v1/sync/delta")
async def sync_delta(request: Request, user=Depends(get_user)):
    raw = await request.body()
    with conn() as c, c.cursor() as cur:
        cur.execute("SELECT hmac_key FROM fincas WHERE id=%s", (user["finca"],))
        key = (cur.fetchone() or ["OZ-DEMO-KEY"])[0].encode()
    if not hmac.compare_digest(request.headers.get("X-OZ-Signature", ""),
                               hmac.new(key, raw, hashlib.sha256).hexdigest()):
        raise HTTPException(401, "Firma HMAC inválida (no-repudio TRD 2.4)")
    data = json.loads(raw)
    device_id = data.get("device_id", "unknown")
    applied, skipped, errors = [], 0, []
    with conn() as c, c.cursor() as cur:
        for m in data.get("mutations", []):
            mid = m.get("id") or str(uuid.uuid4())
            cur.execute("SELECT 1 FROM sync_ledger WHERE mutation_id=%s", (mid,))
            if cur.fetchone():
                skipped += 1
                continue
            try:
                apply_mutation(cur, user["finca"], m)
                cur.execute("""
                    INSERT INTO sync_ledger(mutation_id, finca_id, entity, action, payload, client_time, device_id)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)
                """, (mid, user["finca"], m.get("entity"), m.get("action"),
                      json.dumps(m.get("payload", {})), data.get("client_sync_time"), device_id))
                applied.append(mid)
            except Exception as ex:
                print(f"Error applying mutation {mid}: {ex}")
                errors.append({"id": mid, "entity": m.get("entity"), "error": str(ex)})
    return {"applied": applied, "skipped_idempotent": skipped, "errors": errors}

@app.get("/api/v1/sync/delta")
def pull(last_pulled_at: str, user=Depends(get_user)):
    with conn() as c, c.cursor() as cur:
        cur.execute("""
            SELECT mutation_id, entity, action, payload FROM sync_ledger
            WHERE finca_id=%s AND received_at > %s ORDER BY received_at
        """, (user["finca"], last_pulled_at))
        return {"mutations": [{"id": r[0], "entity": r[1], "action": r[2], "payload": r[3]}
                              for r in cur.fetchall()]}

@app.get("/api/v1/inventory/fefo")
def fefo(user=Depends(get_user)):
    with conn() as c, c.cursor() as cur:
        cur.execute("""
            SELECT b.id, i.name, b.batch_number, b.current_quantity, b.expiration_date
            FROM inventory_batches b JOIN inventory_items i ON i.id=b.item_id
            WHERE i.finca_id=%s AND b.current_quantity>0 ORDER BY b.expiration_date ASC
        """, (user["finca"],))
        return [{"id": str(r[0]), "item": r[1], "batch": r[2],
                 "qty": float(r[3]), "exp": r[4]} for r in cur.fetchall()]

@app.post("/api/v1/animals")
def create_animal(body: dict, user=Depends(require_roles("OWNER", "VET", "ADMIN"))):
    with conn() as c, c.cursor() as cur:
        cur.execute("""
            INSERT INTO animals(visual_tag_id, species, sex, finca_id)
            VALUES (%s,%s,%s,%s) RETURNING id
        """, (body.get("tag"), body.get("species", "OVINE"), body.get("sex", "F"), user["finca"]))
        return {"id": str(cur.fetchone()[0])}

@app.get("/auth/bootstrap")
def bootstrap_mobile():
    with conn() as c, c.cursor() as cur:
        cur.execute("SELECT id FROM fincas LIMIT 1")
        if cur.fetchone():
            return {"status": "La base de datos ya tiene datos."}
        cur.execute("INSERT INTO fincas(name) VALUES ('Hato San José') RETURNING id")
        f = cur.fetchone()[0]
        for n in ("L1", "L2"):
            cur.execute("INSERT INTO lots(finca_id, name) VALUES (%s,%s)", (f, n))
        cur.execute("""
            INSERT INTO users(email, password_hash, full_name, role, finca_id)
            VALUES (%s,%s,%s,%s,%s)
        """, ("demo@ozertzon.com", bcrypt.hash("Ozertzon2026!"),
              "Roberto Gómez, DVM", "OWNER", f))
        for proto in [
            ("Desparasitación TST", "Ivermectina", 0.05, 1.0, "SC", 14, "SANITARIO", "GENERAL"),
            ("Vacuna Clostridial", "Vacuna 8vías", 1.0, None, "IM", 0, "SANITARIO", "GENERAL"),
            ("Impulsor Vitamínico", "AD3E", 1.0, None, "IM", 0, "NUTRICIONAL", "GENERAL"),
        ]:
            cur.execute("""
                INSERT INTO protocols(finca_id, name, product, dose_per_kg, concentration,
                    route, withdrawal_days, category, ptype)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """, (f, *proto))
        cur.execute("""
            INSERT INTO protocols(finca_id, name, product, dose_per_kg, route, category, ptype)
            VALUES (%s,'Neonatal Completo','Mix',0.0,'SC','NEONATAL','NEONATAL') RETURNING id
        """, (f,))
        pid = cur.fetchone()[0]
        for day, action in [(0, "Calostro 10% PV"), (1, "Vitamina AD"), (8, "Descole+Castración")]:
            cur.execute("INSERT INTO protocol_steps(protocol_id, day_offset, action) VALUES (%s,%s,%s)",
                        (pid, day, action))
    return {"status": "¡Éxito! Datos de prueba creados. Ya puedes loguearte."}

@app.get("/debug/db")
def debug_db():
    import os as _os
    url = _os.environ.get("DATABASE_URL", "")
    try:
        with conn() as c, c.cursor() as cur:
            cur.execute("SELECT count(*) FROM fincas")
            n = cur.fetchone()[0]
        return {"status": "ok", "fincas": n, "url_set": bool(url), "version": "3.2"}
    except Exception as e:
        return {"status": "error", "url_set": bool(url),
                "url_prefix": url[:25], "detail": str(e)}

PAIR: dict = {}

@app.get("/pair", response_class=HTMLResponse)
def pair_page(code: str):
    cu = code.upper()
    h = "<html><body style='font-family:sans-serif;"
    h += "background:#0B2A1E;color:#fff;"
    h += "display:flex;align-items:center;"
    h += "justify-content:center;"
    h += "min-height:100vh;margin:0'>"
    h += "<form method='post'"
    h += " action='/auth/attach_login'"
    h += " style='background:#123B2A;padding:28px;"
    h += "border-radius:20px;display:flex;"
    h += "flex-direction:column;gap:12px;"
    h += "min-width:280px'>"
    h += "<h3 style='margin:0'>Vincular dispositivo</h3>"
    h += "<input type='hidden' name='code'"
    h += " value='" + cu + "'>"
    h += "<input name='email'"
    h += " placeholder='correo' required"
    h += " style='padding:12px;border-radius:10px;"
    h += "border:0'>"
    h += "<input name='password' type='password'"
    h += " placeholder='contraseña' required"
    h += " style='padding:12px;border-radius:10px;"
    h += "border:0'>"
    h += "<button style='padding:14px;"
    h += "border-radius:12px;border:0;"
    h += "background:#D97706;color:#fff;"
    h += "font-weight:700'>VINCULAR</button>"
    h += "</form></body></html>"
    return h

@app.post("/auth/attach_login")
def attach_login(code: str = Form(),
                 email: str = Form(),
                 password: str = Form()):
    with conn() as c, c.cursor() as cur:
        cur.execute(
            "SELECT id, password_hash, role,"
            " finca_id FROM users WHERE email=%s",
            (email,))
        row = cur.fetchone()
    if not row or not bcrypt.verify(password, row[1]):
        return HTMLResponse(
            "<h3 style='color:#C92A2A'>"
            "Credenciales inválidas</h3>",
            status_code=401)
    token = jwt.encode(
        {"sub": str(row[0]), "role": row[2],
         "finca": str(row[3]),
         "exp": datetime.now(timezone.utc)
         + timedelta(hours=8)},
        JWT_SECRET, algorithm=ALG)
    PAIR[code.upper()] = token
    return HTMLResponse(
        "<h3 style='color:#2F7D4F'>✔ Dispositivo"
        " vinculado. Cierra esta pestaña.</h3>")

@app.get("/auth/attach")
def attach(code: str, token: str = ""):
    code = code.upper()
    if token:
        PAIR[code] = token
        return {"status": "vinculado"}
    t = PAIR.pop(code, None)
    if not t:
        raise HTTPException(404, "pendiente")
    return {"access_token": t}

EXPECTED = {
    "animals": [
        ("breed", "TEXT"),
        ("birth_date", "DATE"),
        ("sire_id", "UUID"),
        ("dam_id", "UUID"),
        ("repro_status", "TEXT"),
        ("breeding_date", "DATE"),
        ("pregnancy_confirmed_date", "DATE"),
        ("pregnancy_method", "TEXT"),
        ("rearing", "TEXT"),
        ("active", "BOOLEAN"),
        ("updated_at", "TIMESTAMPTZ")],
    "health_logs": [
        ("date", "DATE"),
        ("withdrawal_until", "DATE")],
    "protocols": [("item_id", "UUID")],
    "sync_ledger": [("device_id", "TEXT")],
    "tasks": [
        ("due_date", "DATE"),
        ("source", "TEXT")],
    "rearing_milk_logs": [
        ("donor_animal_id", "UUID")],
}

@app.get("/debug/schema")
def schema_check():
    missing, sql = {}, []
    with conn() as c, c.cursor() as cur:
        for t, cols in EXPECTED.items():
            cur.execute(
                "SELECT column_name FROM"
                " information_schema.columns"
                " WHERE table_name=%s", (t,))
            have = set(r[0] for r in cur.fetchall())
            if not have:
                missing[t] = "TABLE_MISSING"
                continue
            for name, typ in cols:
                if name not in have:
                    missing.setdefault(t, [])
                    missing[t].append(name)
                    sql.append(
                        "ALTER TABLE " + t
                        + " ADD COLUMN IF NOT EXISTS "
                        + name + " " + typ + ";")
    return {"ok": not missing,
            "missing": missing, "sql": sql}
