import hashlib, hmac, json, os, uuid
from datetime import datetime, timedelta, timezone

import psycopg2
from fastapi import Depends, FastAPI, HTTPException, Request
from jose import JWTError, jwt
from passlib.hash import bcrypt
from pydantic import BaseModel

DB = os.environ.get("DATABASE_URL", "postgresql://ozertzon:ozertzon@db:5432/ozertzon")
JWT_SECRET = os.environ.get("JWT_SECRET", "OZ-JWT-SECRET-CHANGE-ME")
ALG = "HS256"
app = FastAPI(title="Ozertzon 360 API", version="1.0")

def conn(): return psycopg2.connect(DB)

class Login(BaseModel):
    email: str; password: str

@app.get("/healthz")
def healthz(): return {"status": "ok"}

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
    if not auth.startswith("Bearer "): raise HTTPException(401, "Falta token")
    try: return jwt.decode(auth[7:], JWT_SECRET, algorithms=[ALG])
    except JWTError: raise HTTPException(401, "Token inválido")

def require_roles(*roles):
    def dep(user=Depends(get_user)):
        if user["role"] not in roles: raise HTTPException(403, "Sin permiso RBAC (TRD 2.4)")
        return user
    return dep

def resolve_id(cur, finca, entity, local):
    cur.execute("SELECT server_uuid FROM id_map WHERE finca_id=%s AND entity=%s AND client_id=%s",
                (finca, entity, str(local)))
    r = cur.fetchone()
    if r: return r[0]
    s = str(uuid.uuid4())
    cur.execute("INSERT INTO id_map(finca_id, entity, client_id, server_uuid) VALUES (%s,%s,%s,%s)",
                (finca, entity, str(local), s))
    return s

def apply_mutation(cur, finca, m):
    e, a, p = m.get("entity"), m.get("action"), m.get("payload", {})
    if e == "animals":
        au = resolve_id(cur, finca, "animals", p.get("id") or p.get("animal"))
        if a == "CREATE":
            cur.execute("INSERT INTO animals(id, visual_tag_id, species, sex, current_weight, finca_id) "
                        "VALUES (%s,%s,%s,%s,%s,%s) ON CONFLICT (id) DO NOTHING",
                        (au, p.get("tag", "?"), p.get("species", "OVINE"), p.get("sex", "F"), p.get("kg"), finca))
        elif a == "UPDATE":
            cur.execute("UPDATE animals SET lot_id=(SELECT id FROM lots WHERE finca_id=%s AND name=%s), "
                        "updated_at=NOW() WHERE id=%s", (finca, p.get("lot", "L1"), au))
    elif e == "weight_events":  # Last-Write-Wins auditado (TRD 2.2)
        au = resolve_id(cur, finca, "animals", p.get("animal"))
        cur.execute("UPDATE animals SET current_weight=%s, updated_at=NOW() WHERE id=%s", (p.get("kg"), au))
    elif e == "health_logs":
        au = resolve_id(cur, finca, "animals", p.get("animal"))
        cur.execute("INSERT INTO health_logs(id, animal_id, protocol_name, famacha_score, applied_dose_ml, "
                    "sync_hash, performed_by_user_id) VALUES (%s,%s,%s,%s,%s,%s,"
                    "(SELECT id FROM users WHERE finca_id=%s LIMIT 1))",
                    (uuid.uuid4(), au, p.get("protocol", "Protocolo"), p.get("famacha"),
                     p.get("dose"), (m.get("id") or "")[:64], finca))

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
            if cur.fetchone(): skipped += 1; continue
            apply_mutation(cur, user["finca"], m)
            cur.execute("INSERT INTO sync_ledger(mutation_id, finca_id, entity, action, payload, client_time) "
                        "VALUES (%s,%s,%s,%s,%s,%s)",
                        (mid, user["finca"], m.get("entity"), m.get("action"),
                         json.dumps(m.get("payload", {})), data.get("client_sync_time")))
            applied.append(mid)
    return {"applied": applied, "skipped_idempotent": skipped}

@app.get("/api/v1/sync/delta")
def pull(last_pulled_at: str, user=Depends(get_user)):
    with conn() as c, c.cursor() as cur:
        cur.execute("SELECT mutation_id, entity, action, payload FROM sync_ledger "
                    "WHERE finca_id=%s AND received_at > %s ORDER BY received_at",
                    (user["finca"], last_pulled_at))
        return {"mutations": [{"id": r[0], "entity": r[1], "action": r[2], "payload": r[3]} for r in cur.fetchall()]}

@app.get("/api/v1/inventory/fefo")
def fefo(user=Depends(get_user)):
    with conn() as c, c.cursor() as cur:
        cur.execute("SELECT b.id, i.name, b.batch_number, b.current_quantity, b.expiration_date "
                    "FROM inventory_batches b JOIN inventory_items i ON i.id=b.item_id "
                    "WHERE i.finca_id=%s AND b.current_quantity>0 ORDER BY b.expiration_date ASC", (user["finca"],))
        return [{"id": str(r[0]), "item": r[1], "batch": r[2], "qty": float(r[3]), "exp": r[4]} for r in cur.fetchall()]

@app.post("/api/v1/animals")
def create_animal(body: dict, user=Depends(require_roles("OWNER", "VET", "ADMIN"))):
    with conn() as c, c.cursor() as cur:
        cur.execute("INSERT INTO animals(visual_tag_id, species, sex, finca_id) VALUES (%s,%s,%s,%s) RETURNING id",
                    (body.get("tag"), body.get("species", "OVINE"), body.get("sex", "F"), user["finca"]))
        return {"id": str(cur.fetchone()[0])}
      # ... (todo el código anterior de main.py) ...

@app.get("/auth/bootstrap")
def bootstrap_mobile():
    """Endpoint GET para sembrar la BD desde el navegador del celular"""
    with conn() as c, c.cursor() as cur:
        cur.execute("SELECT id FROM fincas LIMIT 1")
        if cur.fetchone(): return {"status": "La base de datos ya tiene datos."}
        
        cur.execute("INSERT INTO fincas(name) VALUES ('Hato San José') RETURNING id")
        f = cur.fetchone()[0]
        for n in ("L1", "L2"): 
            cur.execute("INSERT INTO lots(finca_id, name) VALUES (%s,%s)", (f, n))
            
        from passlib.hash import bcrypt
        cur.execute("INSERT INTO users(email, password_hash, full_name, role, finca_id) "
                    "VALUES (%s,%s,%s,%s,%s)",
                    ("demo@ozertzon.com", bcrypt.hash("Ozertzon2026!"),
                     "Roberto Gómez, DVM", "OWNER", f))
    return {"status": "¡Éxito! Datos de prueba creados. Ya puedes loguearte."}
@app.get("/debug/db")
def debug_db():
    import os as _os
    url = _os.environ.get("DATABASE_URL", "")
    try:
        with conn() as c, c.cursor() as cur:
            cur.execute("SELECT count(*) FROM fincas")
            n = cur.fetchone()[0]
        return {"status": "ok", "fincas": n, "url_set": bool(url)}
    except Exception as e:
        return {"status": "error", "url_set": bool(url),
                "url_prefix": url[:25], "detail": str(e)}
