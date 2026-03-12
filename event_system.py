"""
University Event Management Platform — v3
FastAPI + SQLite + JWT + RBAC + Team Participation System
"""
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, validator
from typing import Optional
from datetime import datetime, date, timedelta
import sqlite3, uuid, hashlib, hmac, base64, json, os, re, random, string

app = FastAPI(title="UniEvents API", version="3.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
SECRET_KEY = os.environ.get("SECRET_KEY", "uni-events-secret-key-v3")
DB_PATH = "university_events_v3.db"

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def _now(): return datetime.utcnow().isoformat()
def _hash(pw): return hashlib.sha256(pw.encode()).hexdigest()
def _code(n=6): return ''.join(random.choices(string.ascii_uppercase+string.digits, k=n))

def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','student')),
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS events (
            id TEXT PRIMARY KEY, title TEXT NOT NULL, description TEXT NOT NULL,
            venue TEXT NOT NULL, event_date TEXT NOT NULL, registration_deadline TEXT NOT NULL,
            parent_event_id TEXT REFERENCES events(id) ON DELETE CASCADE,
            capacity INTEGER NOT NULL CHECK(capacity>0),
            status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','expired','cancelled')),
            participation_type TEXT NOT NULL DEFAULT 'individual' CHECK(participation_type IN ('individual','team','both')),
            min_team_size INTEGER NOT NULL DEFAULT 2,
            max_team_size INTEGER NOT NULL DEFAULT 4,
            created_by TEXT NOT NULL REFERENCES users(id), created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS teams (
            id TEXT PRIMARY KEY, team_name TEXT NOT NULL, event_id TEXT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
            leader_id TEXT NOT NULL REFERENCES users(id), join_code TEXT UNIQUE NOT NULL,
            description TEXT DEFAULT '', created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS team_members (
            id TEXT PRIMARY KEY, team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
            student_id TEXT NOT NULL REFERENCES users(id),
            role TEXT NOT NULL DEFAULT 'member' CHECK(role IN ('leader','member')),
            joined_at TEXT NOT NULL, UNIQUE(team_id, student_id)
        );
        CREATE TABLE IF NOT EXISTS registrations (
            id TEXT PRIMARY KEY, event_id TEXT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
            student_id TEXT REFERENCES users(id), team_id TEXT REFERENCES teams(id),
            registration_timestamp TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'registered' CHECK(status IN ('registered','cancelled'))
        );
    """)
    conn.commit()
    if not conn.execute("SELECT id FROM users WHERE role='admin' LIMIT 1").fetchone():
        admin_id = str(uuid.uuid4())
        conn.execute("INSERT INTO users VALUES (?,?,?,?,?,?)", (admin_id,"Admin User","admin@university.edu",_hash("admin123"),"admin",_now()))
        stu_id = str(uuid.uuid4())
        conn.execute("INSERT INTO users VALUES (?,?,?,?,?,?)", (stu_id,"Demo Student","student@university.edu",_hash("student123"),"student",_now()))
        stu2_id = str(uuid.uuid4())
        conn.execute("INSERT INTO users VALUES (?,?,?,?,?,?)", (stu2_id,"Alice Smith","alice@university.edu",_hash("alice123"),"student",_now()))
        today = date.today()
        fest_id = str(uuid.uuid4())
        def ins(eid,title,desc,venue,d,dl,par,cap,pt,mn,mx):
            conn.execute("INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (eid,title,desc,venue,str(today+timedelta(days=d)),str(today+timedelta(days=dl)),par,cap,"active",pt,mn,mx,admin_id,_now()))
        ins(fest_id,"Tech Fest 2026","Annual technology festival","Main Auditorium",30,25,None,500,"individual",2,4)
        hack_id = str(uuid.uuid4())
        ins(hack_id,"Hackathon","24-hour coding challenge","Tech Block",30,24,fest_id,80,"team",2,4)
        ins(str(uuid.uuid4()),"Coding Contest","Competitive algorithm contest","Tech Block",30,24,fest_id,80,"individual",2,4)
        robo_id = str(uuid.uuid4())
        ins(robo_id,"Robotics Challenge","Design, build and battle robots","Robotics Lab",30,24,fest_id,60,"team",3,5)
        ins(str(uuid.uuid4()),"AI Workshop","Hands-on machine learning workshop","CS Lab",30,24,fest_id,40,"both",2,3)
        cult_id = str(uuid.uuid4())
        ins(cult_id,"Cultural Fest","Arts, music, dance and culture","Open Amphitheatre",45,40,None,400,"individual",2,4)
        ins(str(uuid.uuid4()),"Dance Competition","Group dance showcase","Amphitheatre Stage",45,38,cult_id,60,"team",3,6)
        ins(str(uuid.uuid4()),"Singing Competition","Open mic and solo","Amphitheatre Stage",45,38,cult_id,60,"individual",2,4)
        ins(str(uuid.uuid4()),"Blood Donation Camp","Save lives — donate blood","Medical Block",7,6,None,200,"individual",2,4)
        conn.commit()
    conn.close()

def _b64(s): return base64.urlsafe_b64encode(s).rstrip(b'=').decode()
def _unb64(s):
    s += '='*(-len(s)%4)
    return base64.urlsafe_b64decode(s)

def create_token(uid, role):
    h = _b64(json.dumps({"alg":"HS256","typ":"JWT"}).encode())
    p = _b64(json.dumps({"sub":uid,"role":role,"exp":(datetime.utcnow()+timedelta(hours=24)).timestamp()}).encode())
    s = _b64(hmac.new(SECRET_KEY.encode(),f"{h}.{p}".encode(),"sha256").digest())
    return f"{h}.{p}.{s}"

def verify_token(tok):
    try:
        h,p,s = tok.split(".")
        exp = _b64(hmac.new(SECRET_KEY.encode(),f"{h}.{p}".encode(),"sha256").digest())
        if not hmac.compare_digest(s,exp): raise ValueError
        d = json.loads(_unb64(p))
        if d["exp"]<datetime.utcnow().timestamp(): raise ValueError
        return d
    except: raise HTTPException(401,"Invalid or expired token.")

bearer = HTTPBearer()
def get_current_user(c: HTTPAuthorizationCredentials=Depends(bearer)): return verify_token(c.credentials)
def require_admin(u=Depends(get_current_user)):
    if u["role"]!="admin": raise HTTPException(403,"Admin access required.")
    return u

def auto_expire(conn):
    today = date.today().isoformat()
    conn.execute("UPDATE events SET status='expired' WHERE status='active' AND (event_date<? OR registration_deadline<?)",(today,today))
    conn.commit()

# Pydantic Models
class RegisterUser(BaseModel):
    name: str = Field(...,min_length=2); email: str; password: str = Field(...,min_length=6); role: str = "student"
    @validator("email") 
    def ve(cls,v):
        if not re.match(r"[^@]+@[^@]+\.[^@]+",v): raise ValueError("Invalid email")
        return v.lower()

class LoginUser(BaseModel):
    email: str; password: str

class EventCreate(BaseModel):
    title: str = Field(...,min_length=3); description: str = Field(...,min_length=10)
    venue: str; event_date: str; registration_deadline: str
    parent_event_id: Optional[str] = None
    capacity: int = Field(...,gt=0,le=50000)
    participation_type: str = "individual"; min_team_size: int = 2; max_team_size: int = 4

class EventUpdate(BaseModel):
    title: Optional[str]=None; description: Optional[str]=None; venue: Optional[str]=None
    event_date: Optional[str]=None; registration_deadline: Optional[str]=None
    capacity: Optional[int]=Field(None,gt=0); status: Optional[str]=None
    participation_type: Optional[str]=None; min_team_size: Optional[int]=None; max_team_size: Optional[int]=None

class TeamCreate(BaseModel):
    team_name: str = Field(...,min_length=2,max_length=60); event_id: str; description: str = ""

class TeamJoin(BaseModel):
    join_code: str = Field(...,min_length=4,max_length=10)

class TeamLeave(BaseModel):
    team_id: str

# ── AUTH ──────────────────────────────────────────────────────────────────────
@app.post("/auth/register", status_code=201)
def register(p: RegisterUser):
    conn = get_db()
    if conn.execute("SELECT id FROM users WHERE email=?",(p.email,)).fetchone():
        conn.close(); raise HTTPException(409,"Email already registered.")
    uid = str(uuid.uuid4())
    conn.execute("INSERT INTO users VALUES (?,?,?,?,?,?)",(uid,p.name,p.email,_hash(p.password),p.role,_now()))
    conn.commit(); conn.close()
    return {"id":uid,"message":"Registered."}

@app.post("/auth/login")
def login(p: LoginUser):
    conn = get_db()
    u = conn.execute("SELECT * FROM users WHERE email=?",(p.email.lower(),)).fetchone(); conn.close()
    if not u or u["password_hash"]!=_hash(p.password): raise HTTPException(401,"Invalid credentials.")
    return {"token":create_token(u["id"],u["role"]),"role":u["role"],"name":u["name"],"id":u["id"]}

@app.get("/auth/me")
def me(u=Depends(get_current_user)):
    conn = get_db()
    row = conn.execute("SELECT id,name,email,role FROM users WHERE id=?",(u["sub"],)).fetchone(); conn.close()
    if not row: raise HTTPException(404,"Not found")
    return dict(row)

# ── ADMIN ─────────────────────────────────────────────────────────────────────
@app.get("/admin/events")
def admin_list(admin=Depends(require_admin)):
    conn = get_db(); auto_expire(conn)
    rows = conn.execute("""
        SELECT e.*,
          (SELECT COUNT(*) FROM registrations r WHERE r.event_id=e.id AND r.status='registered' AND r.student_id IS NOT NULL) as ind_registered,
          (SELECT COUNT(*) FROM registrations r WHERE r.event_id=e.id AND r.status='registered' AND r.team_id IS NOT NULL) as team_reg_count,
          (SELECT COUNT(*) FROM teams t WHERE t.event_id=e.id) as team_count,
          u.name as creator_name
        FROM events e LEFT JOIN users u ON u.id=e.created_by ORDER BY e.event_date ASC
    """).fetchall()
    conn.close()
    result = []
    for r in rows:
        d = dict(r); d["registered"] = d["ind_registered"] + d["team_reg_count"]; result.append(d)
    return result

@app.post("/admin/events/create", status_code=201)
def create_event(p: EventCreate, admin=Depends(require_admin)):
    conn = get_db()
    if p.parent_event_id and not conn.execute("SELECT id FROM events WHERE id=?",(p.parent_event_id,)).fetchone():
        conn.close(); raise HTTPException(404,"Parent event not found.")
    eid = str(uuid.uuid4())
    conn.execute("INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (eid,p.title,p.description,p.venue,p.event_date,p.registration_deadline,
         p.parent_event_id,p.capacity,"active",p.participation_type,p.min_team_size,p.max_team_size,admin["sub"],_now()))
    conn.commit(); conn.close()
    return {"id":eid,"message":"Event created."}

@app.put("/admin/events/update/{eid}")
def update_event(eid: str, p: EventUpdate, admin=Depends(require_admin)):
    conn = get_db()
    if not conn.execute("SELECT id FROM events WHERE id=?",(eid,)).fetchone():
        conn.close(); raise HTTPException(404,"Event not found.")
    upd = {k:v for k,v in p.dict().items() if v is not None}
    if upd:
        conn.execute(f"UPDATE events SET {','.join(f'{k}=?' for k in upd)} WHERE id=?",(*upd.values(),eid))
        conn.commit()
    conn.close(); return {"message":"Updated."}

@app.delete("/admin/events/delete/{eid}")
def delete_event(eid: str, admin=Depends(require_admin)):
    conn = get_db()
    ev = conn.execute("SELECT * FROM events WHERE id=?",(eid,)).fetchone()
    if not ev: conn.close(); raise HTTPException(404,"Not found.")
    if ev["status"]=="expired": conn.close(); raise HTTPException(400,"Cannot delete expired events.")
    conn.execute("DELETE FROM events WHERE id=?",(eid,)); conn.commit(); conn.close()
    return {"message":"Deleted."}

@app.get("/admin/events/{eid}/participants")
def get_participants(eid: str, admin=Depends(require_admin)):
    conn = get_db()
    rows = conn.execute("""
        SELECT u.name,u.email,r.registration_timestamp,r.status,'individual' as type
        FROM registrations r JOIN users u ON u.id=r.student_id
        WHERE r.event_id=? AND r.student_id IS NOT NULL ORDER BY r.registration_timestamp
    """,(eid,)).fetchall()
    conn.close(); return [dict(r) for r in rows]

@app.get("/admin/events/{eid}/teams")
def get_event_teams(eid: str, admin=Depends(require_admin)):
    conn = get_db()
    teams = conn.execute("""
        SELECT t.*,u.name as leader_name,
          (SELECT status FROM registrations r WHERE r.team_id=t.id LIMIT 1) as reg_status,
          (SELECT COUNT(*) FROM team_members tm WHERE tm.team_id=t.id) as member_count
        FROM teams t JOIN users u ON u.id=t.leader_id WHERE t.event_id=? ORDER BY t.created_at
    """,(eid,)).fetchall()
    result = []
    for t in teams:
        td = dict(t)
        members = conn.execute("SELECT u.name,u.email,tm.role,tm.joined_at FROM team_members tm JOIN users u ON u.id=tm.student_id WHERE tm.team_id=?",(t["id"],)).fetchall()
        td["members"] = [dict(m) for m in members]
        result.append(td)
    conn.close(); return result

@app.get("/admin/teams/{tid}")
def admin_get_team(tid: str, admin=Depends(require_admin)):
    conn = get_db()
    t = conn.execute("SELECT t.*,u.name as leader_name,e.title as event_title FROM teams t JOIN users u ON u.id=t.leader_id JOIN events e ON e.id=t.event_id WHERE t.id=?",(tid,)).fetchone()
    if not t: conn.close(); raise HTTPException(404,"Not found.")
    td = dict(t)
    members = conn.execute("SELECT u.name,u.email,tm.role,tm.joined_at FROM team_members tm JOIN users u ON u.id=tm.student_id WHERE tm.team_id=?",(tid,)).fetchall()
    td["members"] = [dict(m) for m in members]
    conn.close(); return td

# ── STUDENT EVENTS ────────────────────────────────────────────────────────────
@app.get("/events")
def list_events(u=Depends(get_current_user)):
    conn = get_db(); auto_expire(conn)
    rows = conn.execute("""
        SELECT e.*, (SELECT COUNT(*) FROM registrations r WHERE r.event_id=e.id AND r.status='registered') as registered
        FROM events e WHERE e.status='active' ORDER BY e.event_date ASC
    """).fetchall(); conn.close()
    return [dict(r) for r in rows]

@app.get("/events/{eid}")
def get_event(eid: str, u=Depends(get_current_user)):
    conn = get_db()
    ev = conn.execute("SELECT e.*,(SELECT COUNT(*) FROM registrations r WHERE r.event_id=e.id AND r.status='registered') as registered FROM events e WHERE e.id=?",(eid,)).fetchone()
    if not ev: conn.close(); raise HTTPException(404,"Not found.")
    result = dict(ev)
    subs = conn.execute("SELECT e.*,(SELECT COUNT(*) FROM registrations r WHERE r.event_id=e.id AND r.status='registered') as registered FROM events e WHERE e.parent_event_id=? AND e.status='active'",(eid,)).fetchall()
    result["sub_events"] = [dict(s) for s in subs]; conn.close()
    return result

@app.post("/events/{eid}/register", status_code=201)
def register_individual(eid: str, u=Depends(get_current_user)):
    conn = get_db()
    ev = conn.execute("SELECT * FROM events WHERE id=?",(eid,)).fetchone()
    if not ev: conn.close(); raise HTTPException(404,"Not found.")
    if ev["status"]!="active": conn.close(); raise HTTPException(400,"Event not active.")
    if ev["participation_type"]=="team": conn.close(); raise HTTPException(400,"This is a team-only event. Please register as a team.")
    today = date.today().isoformat()
    if ev["registration_deadline"]<today: conn.close(); raise HTTPException(400,"Registration deadline has passed.")
    count = conn.execute("SELECT COUNT(*) as c FROM registrations WHERE event_id=? AND status='registered'",(eid,)).fetchone()["c"]
    if count>=ev["capacity"]: conn.close(); raise HTTPException(409,"Event is at full capacity.")
    if conn.execute("SELECT id FROM registrations WHERE student_id=? AND event_id=? AND status='registered'",(u["sub"],eid)).fetchone():
        conn.close(); raise HTTPException(409,"Already registered.")
    conn.execute("INSERT INTO registrations VALUES (?,?,?,?,?,?)",(str(uuid.uuid4()),eid,u["sub"],None,_now(),"registered"))
    conn.commit(); conn.close()
    return {"message":"Registered successfully!"}

@app.delete("/events/{eid}/register")
def cancel_reg(eid: str, u=Depends(get_current_user)):
    conn = get_db()
    reg = conn.execute("SELECT id FROM registrations WHERE student_id=? AND event_id=? AND status='registered'",(u["sub"],eid)).fetchone()
    if not reg: conn.close(); raise HTTPException(404,"Registration not found.")
    conn.execute("UPDATE registrations SET status='cancelled' WHERE id=?",(reg["id"],))
    conn.commit(); conn.close(); return {"message":"Cancelled."}

@app.get("/student/registrations")
def my_regs(u=Depends(get_current_user)):
    conn = get_db()
    ind = conn.execute("""
        SELECT e.id,e.title,e.venue,e.event_date,e.status as event_status,e.participation_type,
               r.registration_timestamp,r.status as reg_status,p.title as parent_title,
               'individual' as reg_type,NULL as team_name,NULL as team_id
        FROM registrations r JOIN events e ON e.id=r.event_id
        LEFT JOIN events p ON p.id=e.parent_event_id
        WHERE r.student_id=? ORDER BY r.registration_timestamp DESC
    """,(u["sub"],)).fetchall()
    team_rows = conn.execute("""
        SELECT e.id,e.title,e.venue,e.event_date,e.status as event_status,e.participation_type,
               r.registration_timestamp,r.status as reg_status,p.title as parent_title,
               'team' as reg_type,t.team_name,t.id as team_id
        FROM team_members tm JOIN teams t ON t.id=tm.team_id
        JOIN registrations r ON r.team_id=t.id AND r.event_id=t.event_id
        JOIN events e ON e.id=t.event_id
        LEFT JOIN events p ON p.id=e.parent_event_id
        WHERE tm.student_id=? ORDER BY r.registration_timestamp DESC
    """,(u["sub"],)).fetchall()
    conn.close()
    return [dict(r) for r in ind]+[dict(r) for r in team_rows]

# ── TEAMS ─────────────────────────────────────────────────────────────────────
@app.post("/teams/create", status_code=201)
def create_team(p: TeamCreate, u=Depends(get_current_user)):
    conn = get_db()
    ev = conn.execute("SELECT * FROM events WHERE id=?",(p.event_id,)).fetchone()
    if not ev: conn.close(); raise HTTPException(404,"Event not found.")
    if ev["status"]!="active": conn.close(); raise HTTPException(400,"Event is not active.")
    if ev["participation_type"]=="individual": conn.close(); raise HTTPException(400,"This event only supports individual registration.")
    today = date.today().isoformat()
    if ev["registration_deadline"]<today: conn.close(); raise HTTPException(400,"Registration deadline has passed.")
    if conn.execute("SELECT tm.id FROM team_members tm JOIN teams t ON t.id=tm.team_id WHERE tm.student_id=? AND t.event_id=?",(u["sub"],p.event_id)).fetchone():
        conn.close(); raise HTTPException(409,"You are already in a team for this event.")
    code = _code()
    while conn.execute("SELECT id FROM teams WHERE join_code=?",(code,)).fetchone(): code = _code()
    tid = str(uuid.uuid4())
    conn.execute("INSERT INTO teams VALUES (?,?,?,?,?,?,?)",(tid,p.team_name,p.event_id,u["sub"],code,p.description,_now()))
    conn.execute("INSERT INTO team_members VALUES (?,?,?,?,?)",(str(uuid.uuid4()),tid,u["sub"],"leader",_now()))
    conn.commit(); conn.close()
    return {"id":tid,"join_code":code,"message":f"Team '{p.team_name}' created! Share code: {code}"}

@app.post("/teams/join")
def join_team(p: TeamJoin, u=Depends(get_current_user)):
    conn = get_db()
    team = conn.execute("SELECT * FROM teams WHERE join_code=?",(p.join_code.upper(),)).fetchone()
    if not team: conn.close(); raise HTTPException(404,"Invalid team code.")
    ev = conn.execute("SELECT * FROM events WHERE id=?",(team["event_id"],)).fetchone()
    if not ev or ev["status"]!="active": conn.close(); raise HTTPException(400,"Event is not active.")
    if ev["registration_deadline"]<date.today().isoformat(): conn.close(); raise HTTPException(400,"Registration deadline has passed.")
    if conn.execute("SELECT tm.id FROM team_members tm JOIN teams t ON t.id=tm.team_id WHERE tm.student_id=? AND t.event_id=?",(u["sub"],team["event_id"])).fetchone():
        conn.close(); raise HTTPException(409,"You are already in a team for this event.")
    count = conn.execute("SELECT COUNT(*) as c FROM team_members WHERE team_id=?",(team["id"],)).fetchone()["c"]
    if count>=ev["max_team_size"]: conn.close(); raise HTTPException(409,f"Team is full (max {ev['max_team_size']}).")
    conn.execute("INSERT INTO team_members VALUES (?,?,?,?,?)",(str(uuid.uuid4()),team["id"],u["sub"],"member",_now()))
    conn.commit(); conn.close()
    return {"team_id":team["id"],"team_name":team["team_name"],"message":f"Joined '{team['team_name']}'!"}

@app.get("/teams/{tid}")
def get_team(tid: str, u=Depends(get_current_user)):
    conn = get_db()
    t = conn.execute("SELECT t.*,u.name as leader_name,e.title as event_title,e.min_team_size,e.max_team_size,e.participation_type FROM teams t JOIN users u ON u.id=t.leader_id JOIN events e ON e.id=t.event_id WHERE t.id=?",(tid,)).fetchone()
    if not t: conn.close(); raise HTTPException(404,"Not found.")
    td = dict(t)
    members = conn.execute("SELECT u.id,u.name,u.email,tm.role,tm.joined_at FROM team_members tm JOIN users u ON u.id=tm.student_id WHERE tm.team_id=?",(tid,)).fetchall()
    td["members"] = [dict(m) for m in members]
    reg = conn.execute("SELECT status,registration_timestamp FROM registrations WHERE team_id=?",(tid,)).fetchone()
    td["registration"] = dict(reg) if reg else None
    conn.close(); return td

@app.delete("/teams/leave")
def leave_team(p: TeamLeave, u=Depends(get_current_user)):
    conn = get_db()
    tm = conn.execute("SELECT * FROM team_members WHERE team_id=? AND student_id=?",(p.team_id,u["sub"])).fetchone()
    if not tm: conn.close(); raise HTTPException(404,"You are not in this team.")
    if conn.execute("SELECT id FROM registrations WHERE team_id=? AND status='registered'",(p.team_id,)).fetchone():
        conn.close(); raise HTTPException(400,"Cannot leave a team that is already registered.")
    if tm["role"]=="leader":
        others = conn.execute("SELECT id FROM team_members WHERE team_id=? AND student_id!=?",(p.team_id,u["sub"])).fetchall()
        if others: conn.close(); raise HTTPException(400,"Transfer leadership before leaving, or disband once alone.")
        conn.execute("DELETE FROM teams WHERE id=?",(p.team_id,))
    else:
        conn.execute("DELETE FROM team_members WHERE team_id=? AND student_id=?",(p.team_id,u["sub"]))
    conn.commit(); conn.close(); return {"message":"Left team."}

@app.post("/teams/{tid}/register-event", status_code=201)
def register_team(tid: str, u=Depends(get_current_user)):
    conn = get_db()
    team = conn.execute("SELECT * FROM teams WHERE id=?",(tid,)).fetchone()
    if not team: conn.close(); raise HTTPException(404,"Team not found.")
    if team["leader_id"]!=u["sub"]: conn.close(); raise HTTPException(403,"Only the team leader can register.")
    ev = conn.execute("SELECT * FROM events WHERE id=?",(team["event_id"],)).fetchone()
    if not ev or ev["status"]!="active": conn.close(); raise HTTPException(400,"Event not active.")
    if ev["registration_deadline"]<date.today().isoformat(): conn.close(); raise HTTPException(400,"Deadline passed.")
    count = conn.execute("SELECT COUNT(*) as c FROM team_members WHERE team_id=?",(tid,)).fetchone()["c"]
    if count<ev["min_team_size"]: conn.close(); raise HTTPException(400,f"Need at least {ev['min_team_size']} members (have {count}).")
    if count>ev["max_team_size"]: conn.close(); raise HTTPException(400,f"Too many members (max {ev['max_team_size']}).")
    if conn.execute("SELECT id FROM registrations WHERE team_id=? AND event_id=? AND status='registered'",(tid,team["event_id"])).fetchone():
        conn.close(); raise HTTPException(409,"Team already registered.")
    old = conn.execute("SELECT id FROM registrations WHERE team_id=? AND event_id=?",(tid,team["event_id"])).fetchone()
    if old:
        conn.execute("UPDATE registrations SET status='registered',registration_timestamp=? WHERE id=?",(_now(),old["id"]))
    else:
        conn.execute("INSERT INTO registrations VALUES (?,?,?,?,?,?)",(str(uuid.uuid4()),team["event_id"],None,tid,_now(),"registered"))
    conn.commit(); conn.close()
    return {"message":f"Team '{team['team_name']}' registered!"}

@app.get("/student/teams")
def my_teams(u=Depends(get_current_user)):
    conn = get_db()
    rows = conn.execute("""
        SELECT t.*,e.title as event_title,e.min_team_size,e.max_team_size,e.registration_deadline,
               ul.name as leader_name,tm.role as my_role,
               (SELECT COUNT(*) FROM team_members x WHERE x.team_id=t.id) as member_count,
               (SELECT status FROM registrations r WHERE r.team_id=t.id AND r.event_id=t.event_id LIMIT 1) as reg_status
        FROM team_members tm JOIN teams t ON t.id=tm.team_id
        JOIN events e ON e.id=t.event_id JOIN users ul ON ul.id=t.leader_id
        WHERE tm.student_id=? ORDER BY t.created_at DESC
    """,(u["sub"],)).fetchall()
    result = []
    for r in rows:
        td = dict(r)
        members = conn.execute("SELECT u.name,u.email,tm.role FROM team_members tm JOIN users u ON u.id=tm.student_id WHERE tm.team_id=?",(r["id"],)).fetchall()
        td["members"] = [dict(m) for m in members]
        result.append(td)
    conn.close(); return result

# ── SERVE ─────────────────────────────────────────────────────────────────────
if os.path.exists("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
def root():
    if os.path.exists("static/index.html"): return FileResponse("static/index.html")
    return {"message":"UniEvents API v3. See /docs"}

if __name__=="__main__":
    init_db()
    import uvicorn
    uvicorn.run("event_system:app", host="0.0.0.0", port=8000, reload=True)