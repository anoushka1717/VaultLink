import os, sqlite3, uuid, hashlib, secrets, json
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from cryptography.fernet import Fernet, InvalidToken

BASE = Path(__file__).resolve().parent
STORE = BASE / 'storage'; STORE.mkdir(exist_ok=True)
DB = BASE / 'vaultlink.db'
KEY_FILE = BASE / '.vaultkey'
if KEY_FILE.exists(): key = KEY_FILE.read_bytes().strip()
else:
    key = Fernet.generate_key(); KEY_FILE.write_bytes(key); os.chmod(KEY_FILE, 0o600)
cipher = Fernet(key)
app = FastAPI(title='VaultLink Demo', version='0.1')
app.mount('/static', StaticFiles(directory=BASE/'static'), name='static')
MAX_BYTES = 5*1024*1024

def db():
    con=sqlite3.connect(DB); con.row_factory=sqlite3.Row; return con

def init():
    with db() as c:
        c.execute('''CREATE TABLE IF NOT EXISTS files(id TEXT PRIMARY KEY, name TEXT, size INTEGER, path TEXT, created TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS shares(id TEXT PRIMARY KEY, file_id TEXT, token_hash TEXT, pass_hash TEXT, expires TEXT, revoked INTEGER DEFAULT 0, created TEXT, accesses INTEGER DEFAULT 0)''')
        c.execute('''CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT, share_id TEXT, event TEXT, created TEXT, detail TEXT)''')
init()
def now(): return datetime.now(timezone.utc)
def iso(dt): return dt.isoformat()
def token_hash(t): return hashlib.sha256(t.encode()).hexdigest()
def pass_hash(p): return hashlib.sha256(p.encode()).hexdigest()
def event(sid, ev, detail=''):
    with db() as c: c.execute('INSERT INTO events(share_id,event,created,detail) VALUES(?,?,?,?)',(sid,ev,iso(now()),detail))
def get_share(token):
    with db() as c: row=c.execute('SELECT s.*,f.name,f.size,f.path FROM shares s JOIN files f ON f.id=s.file_id WHERE token_hash=?',(token_hash(token),)).fetchone()
    if not row: raise HTTPException(404,'Share link not found')
    if row['revoked']: raise HTTPException(403,'This share link has been revoked')
    if datetime.fromisoformat(row['expires']) <= now(): raise HTTPException(403,'This share link has expired')
    return row

@app.get('/', response_class=HTMLResponse)
def home():
    return (BASE/'static/index.html').read_text(encoding='utf-8')

@app.post('/api/upload')
async def upload(file: UploadFile=File(...)):
    data=await file.read(MAX_BYTES+1)
    if not file.filename or not data: raise HTTPException(400,'Choose a non-empty file')
    if len(data)>MAX_BYTES: raise HTTPException(413,'Demo limit is 5 MB')
    fid=uuid.uuid4().hex; stored=fid+'.enc'; (STORE/stored).write_bytes(cipher.encrypt(data))
    with db() as c: c.execute('INSERT INTO files VALUES(?,?,?,?,?)',(fid,file.filename[:200],len(data),stored,iso(now())))
    return {'id':fid,'name':file.filename,'size':len(data),'message':'Encrypted and stored'}

@app.post('/api/share')
def create_share(file_id: str=Form(...), hours: int=Form(24), passcode: str=Form(...)):
    if hours not in [1,6,12,24,48,72]: raise HTTPException(400,'Choose a supported expiry')
    if len(passcode)<4 or len(passcode)>64: raise HTTPException(400,'Passcode must be 4–64 characters')
    with db() as c: f=c.execute('SELECT * FROM files WHERE id=?',(file_id,)).fetchone()
    if not f: raise HTTPException(404,'File not found')
    token=secrets.token_urlsafe(32); sid=uuid.uuid4().hex; expiry=iso(now()+timedelta(hours=hours))
    with db() as c: c.execute('INSERT INTO shares VALUES(?,?,?,?,?,?,?,?)',(sid,file_id,token_hash(token),pass_hash(passcode),expiry,0,iso(now()),0))
    event(sid,'Share created',f'Expires in {hours} hours')
    # Demo risk score: policy is scored from settings, not file content.
    risk=35 if hours<=24 else 55
    return {'share_id':sid,'token':token,'url':f'/share/{token}','expires':expiry,'risk_score':risk,'risk_label':'Lower risk' if risk<50 else 'Moderate risk','recommendations':['Share only with intended recipient','Do not send passcode in the same channel as the link','Revocation cannot erase copies already downloaded']}

@app.get('/api/files')
def files():
    with db() as c: rows=c.execute('SELECT * FROM files ORDER BY created DESC').fetchall()
    return [dict(id=r['id'],name=r['name'],size=r['size'],created=r['created']) for r in rows]

@app.get('/api/shares')
def shares():
    with db() as c: rows=c.execute('SELECT s.*,f.name FROM shares s JOIN files f ON f.id=s.file_id ORDER BY s.created DESC').fetchall()
    out=[]
    for r in rows:
        expired=datetime.fromisoformat(r['expires'])<=now()
        state='Revoked' if r['revoked'] else ('Expired' if expired else 'Active')
        out.append(dict(id=r['id'],name=r['name'],expires=r['expires'],state=state,accesses=r['accesses'],created=r['created']))
    return out

@app.post('/api/revoke/{sid}')
def revoke(sid:str):
    with db() as c:
        r=c.execute('SELECT id,revoked FROM shares WHERE id=?',(sid,)).fetchone()
        if not r: raise HTTPException(404,'Share not found')
        c.execute('UPDATE shares SET revoked=1 WHERE id=?',(sid,))
    event(sid,'Revoked','Owner disabled this share'); return {'message':'Share revoked'}

@app.get('/api/events')
def events():
    with db() as c: rows=c.execute('SELECT e.*,f.name FROM events e JOIN shares s ON s.id=e.share_id JOIN files f ON f.id=s.file_id ORDER BY e.created DESC LIMIT 100').fetchall()
    return [dict(file=r['name'],event=r['event'],created=r['created'],detail=r['detail']) for r in rows]

@app.get('/api/share/{token}')
def share_info(token:str):
    r=get_share(token); event(r['id'],'Link opened','Recipient opened share page')
    return {'name':r['name'],'expires':r['expires']}

@app.post('/api/share/{token}/verify')
def verify(token:str, passcode:str=Form(...)):
    r=get_share(token)
    if not secrets.compare_digest(pass_hash(passcode),r['pass_hash']):
        event(r['id'],'Verification failed','Incorrect passcode'); raise HTTPException(403,'Incorrect passcode')
    event(r['id'],'Verification passed','Passcode accepted')
    return {'verified':True}

@app.get('/api/share/{token}/download')
def download(token:str, passcode:str):
    r=get_share(token)
    if not secrets.compare_digest(pass_hash(passcode),r['pass_hash']):
        event(r['id'],'Download denied','Verification failed'); raise HTTPException(403,'Incorrect passcode')
    try: data=cipher.decrypt((STORE/r['path']).read_bytes())
    except (InvalidToken,FileNotFoundError): raise HTTPException(500,'Stored file could not be decrypted')
    temp=STORE/(uuid.uuid4().hex+'.tmp'); temp.write_bytes(data)
    with db() as c: c.execute('UPDATE shares SET accesses=accesses+1 WHERE id=?',(r['id'],))
    event(r['id'],'File downloaded','Authorized download')
    # Response cleanup is intentionally omitted in this short demo; temporary plaintext is removed manually after testing.
    return FileResponse(temp,filename=r['name'],media_type='application/octet-stream')

@app.get('/', response_class=HTMLResponse)
def home(): return (BASE/'static/index.html').read_text(encoding='utf-8')
@app.get('/share/{token}', response_class=HTMLResponse)
def recipient(token: str):
    return (BASE/'static/recipient.html').read_text(encoding='utf-8').replace('TOKEN_PLACEHOLDER', token)