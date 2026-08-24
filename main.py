import sentry_sdk
from sentry_sdk.integrations.fastapi import FastApiIntegration
from sentry_sdk.integrations.sqlalchemy import SqlalchemyIntegration

SENTRY_DSN = os.environ.get("SENTRY_DSN")
if SENTRY_DSN:
    sentry_sdk.init(
        dsn=SENTRY_DSN,
        environment=os.environ.get("ENVIRONMENT", "production"),
        traces_sample_rate=0.1,  # 10% de requests para performance
        integrations=[
            FastApiIntegration(),
            SqlalchemyIntegration(),
        ],
    )
import hashlib, hmac, json, os, uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

import psycopg2
from fastapi import Depends, FastAPI, HTTPException, Request
from jose import JWTError, jwt
from passlib.hash import bcrypt
from pydantic import BaseModel

DB = os.environ.get("DATABASE_URL", "postgresql://ozertzon:ozertzon@db:5432/ozertzon")
JWT_SECRET = os.environ.get("JWT_SECRET", "OZ-JWT-SECRET-CHANGE-ME")
ALG = "HS256"
app = FastAPI(title="Ozertzon 360 API", version="3.1")

def conn(): return psycopg2.connect(DB)

class Login(BaseModel):
    email: str
    password: str

@app.get("/healthz")
def healthz():
    return {"status": "ok", "version": "3.1"}

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
    """Resuelve client_id local → server UUID (id_map)"""
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
    """Aplica una mutación del cliente a la BD (Last-Write-Wins auditado)"""
    e, a, p = m.get("entity"), m.get("action"), m.get("payload", {})
    
    # ===== ANIMALES (con genealogía, repro, breed, rearing) =====
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
    
    # ===== PESAJES =====
    elif e == "weight_events":
        au = resolve_id(cur, finca, "animals", p.get("animal"))
        cur.execute("""
            INSERT INTO weight_events(id, animal_id, weight_kg, date)
            VALUES (%s,%s,%s,%s)
            ON CONFLICT (id) DO NOTHING
        """, (uuid.uuid4(), au, p.get("kg"), p.get("date")))
        cur.execute("UPDATE animals SET current_weight=%s, updated_at=NOW() WHERE id=%s",
                    (p.get("kg"), au))
    
    # ===== SANIDAD (health_logs) =====
    elif e == "health_logs":
        au = resolve_id(cur, finca, "animals", p.get("animal"))
        cur.execute("""
            INSERT INTO health_logs(id, animal_id, protocol_name, famacha_score, applied_dose_ml,
                sync_hash, performed_by_user_id, date)
            VALUES (%s,%s,%s,%s,%s,%s,(SELECT id FROM users WHERE finca_id=%s LIMIT 1),%s)
        """, (uuid.uuid4(), au, p.get("protocol", "Protocolo"), p.get("famacha"),
              p.get("dose"), (m.get("id") or "")[:64], finca, p.get("date")))
    
    # ===== PROTOCOLOS =====
    elif e == "protocols":
        if a == "CREATE":
            pid = resolve_id(cur, finca, "protocols", p.get("id"))
            cur.execute("""
                INSERT INTO protocols(id, finca_id, name, product, dose_per_kg, concentration,
                    route, withdrawal_days, category, ptype)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (id) DO NOTHING
            """, (pid, finca, p.get("name"), p.get("product"), p.get("dose_per_kg"),
                  p.get("concentration"), p.get("route"), p.get("withdrawal_days", 0),
                  p.get("category"), p.get("ptype", "GENERAL")))
            for step in p.get("steps", []):
                cur.execute("""
                    INSERT INTO protocol_steps(protocol_id, day_offset, action)
                    VALUES (%s,%s,%s)
                """, (pid, step.get("day"), step.get("action")))
    
    # ===== ALIMENTACIÓN =====
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
    
    # ===== MOVIMIENTOS DE LOTE =====
    elif e == "lot_movements":
        au = resolve_id(cur, finca, "animals", p.get("animal"))
        cur.execute("""
            INSERT INTO lot_movements(id, finca_id, animal_id, from_lot, to_lot, date, reason)
            VALUES (%s,%s,%s,%s,%s,%s,%s)
        """, (uuid.uuid4(), finca, au, p.get("from"), p.get("to"), p.get("date"), p.get("reason")))
    
    # ===== PRODUCCIÓN =====
    elif e == "production_records":
        au = resolve_id(cur, finca, "animals", p.get("animal"))
        cur.execute("""
            INSERT INTO production_records(id, animal_id, type, qty, unit, unit_price, date)
            VALUES (%s,%s,%s,%s,%s,%s,%s)
        """, (uuid.uuid4(), au, p.get("type"), p.get("qty"), p.get("unit"),
              p.get("price"), p.get("date")))
    
    # ===== DISPOSICIONES (salidas) =====
    elif e == "dispositions":
        au = resolve_id(cur, finca, "animals", p.get("animal"))
        cur.execute("""
            INSERT INTO dispositions(id, animal_id, type, income, date, note)
            VALUES (%s,%s,%s,%s,%s,%s)
        """, (uuid.uuid4(), au, p.get("type"), p.get("income"), p.get("date"), p.get("note")))
        cur.execute("UPDATE animals SET active=FALSE WHERE id=%s", (au,))
    
    # ===== PEDIDOS =====
    elif e == "purchase_orders":
        pid = resolve_id(cur, finca, "purchase_orders", p.get("id"))
        cur.execute("""
            INSERT INTO purchase_orders(id, finca_id, item_name, qty, supplier, status, date)
            VALUES (%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (id) DO NOTHING
        """, (pid, finca, p.get("item"), p.get("qty"), p.get("supplier"),
              p.get("status", "PENDIENTE"), p.get("date")))
    
    # ===== INCIDENCIAS =====
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
    
    # ===== TAREAS =====
    elif e == "tasks":
        tid = resolve_id(cur, finca, "tasks", p.get("id"))
        cur.execute("""
            INSERT INTO tasks(id, finca_id, title, assigned_to, done, priority, started_at,
                completed_at, note, verified, due_date, source)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (id) DO NOTHING
        """, (tid, finca, p.get("title"), p.get("assigned"), p.get("done", False),
              p.get("priority"), p.get("started_at"), p.get("completed_at"),
              p.get("note"), p.get("verified", False), p.get("due_date"), p.get("source")))
    
    # ===== POTREROS =====
    elif e == "paddocks":
        pid = resolve_id(cur, finca, "paddocks", p.get("id"))
        cur.execute("""
            INSERT INTO paddocks(id, finca_id, name, area_ha, current_lot, since_date, biomass_base)
            VALUES (%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (id) DO NOTHING
        """, (pid, finca, p.get("name"), p.get("area"), p.get("lot"),
              p.get("since"), p.get("biomass", 800)))
    
    # ===== TETERO =====
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
    applied, skipped = [], 0
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
                    INSERT INTO sync_ledger(mutation_id, finca_id, entity, action, payload, client_time)
                    VALUES (%s,%s,%s,%s,%s,%s)
                """, (mid, user["finca"], m.get("entity"), m.get("action"),
                      json.dumps(m.get("payload", {})), data.get("client_sync_time")))
                applied.append(mid)
            except Exception as ex:
                # Log error pero no rompas el batch
                print(f"Error applying mutation {mid}: {ex}")
    return {"applied": applied, "skipped_idempotent": skipped}

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
    """Endpoint GET para sembrar la BD completa desde el navegador del celular"""
    with conn() as c, c.cursor() as cur:
        cur.execute("SELECT id FROM fincas LIMIT 1")
        if cur.fetchone():
            return {"status": "La base de datos ya tiene datos."}
        
        cur.execute("INSERT INTO fincas(name) VALUES ('Hato San José') RETURNING id")
        f = cur.fetchone()[0]
        
        # Lotes iniciales
        for n in ("L1", "L2"):
            cur.execute("INSERT INTO lots(finca_id, name) VALUES (%s,%s)", (f, n))
        
        # Usuario demo
        cur.execute("""
            INSERT INTO users(email, password_hash, full_name, role, finca_id)
            VALUES (%s,%s,%s,%s,%s)
        """, ("demo@ozertzon.com", bcrypt.hash("Ozertzon2026!"),
              "Roberto Gómez, DVM", "OWNER", f))
        
        # Protocolos de catálogo
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
        
        # Protocolo NEONATAL con pasos
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
        return {"status": "ok", "fincas": n, "url_set": bool(url), "version": "3.1"}
    except Exception as e:
        return {"status": "error", "url_set": bool(url),
                "url_prefix": url[:25], "detail": str(e)}

PAIR: dict = {}  # demo en memoria (RFC 8628 simplificado)

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
