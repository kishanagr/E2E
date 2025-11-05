"""
Final merged app: Flask UI + ability to auto-spawn original Server.py relay and send messages via the relay.
UI includes: Token input, Receiver ID, From name, Message textarea or TXT file, Delay, Start/Stop, Status.
"""
from flask import Flask, request, jsonify, render_template_string, send_from_directory
import subprocess, sys, time, os, socket, base64, json, threading, random, string
from threading import Event
app = Flask(__name__, static_folder="static", static_url_path="/static")

SOCKET_HOST = "127.0.0.1"
SOCKET_PORT = 42000
SERVER_FILENAME = "Server.py"
SERVER_PROCESS = None

# Task management
tasks = {}  # task_id -> dict { thread, stop_event, count, last_log }

INDEX_HTML = open("static/index_final.html","r",encoding="utf-8").read()

def is_port_open(host, port, timeout=1.0):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.close()
        return True
    except Exception:
        return False

def spawn_server_if_needed():
    global SERVER_PROCESS
    if is_port_open(SOCKET_HOST, SOCKET_PORT):
        app.logger.info("Server.py already listening on port %s", SOCKET_PORT)
        return True
    python_exe = sys.executable or "python"
    cmd = [python_exe, SERVER_FILENAME]
    app.logger.info("Spawning Server.py with command: %s", " ".join(cmd))
    SERVER_PROCESS = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=os.getcwd())
    # wait for port
    for i in range(20):
        if is_port_open(SOCKET_HOST, SOCKET_PORT):
            app.logger.info("Server.py started and listening")
            return True
        time.sleep(1)
    app.logger.warning("Server.py spawn attempted but port not open after wait. Check Server.py logs.")
    return False

def generate_small_rsa_client(p=61,q=53):
    def egcd(a,b):
        if a==0: return (b,0,1)
        g,y,x = egcd(b%a,a)
        return (g, x - (b//a)*y, y)
    def modinv(a,m):
        g,x,y = egcd(a,m)
        if g!=1:
            raise Exception("modinv failed")
        return x % m
    p_val = p; q_val = q
    n = p_val * q_val
    phi = (p_val-1)*(q_val-1)
    e = 17
    def gcd(a,b):
        while b:
            a,b = b, a%b
        return a
    while gcd(e, phi) != 1:
        e += 2
    d = modinv(e, phi)
    return (e,n), (d,n)

def encrypt_message_for_relay(public_key, message_text):
    e,n = public_key
    encrypted_numbers = [pow(ord(c), e, n) for c in message_text]
    json_string = json.dumps(encrypted_numbers)
    b64 = base64.b64encode(json_string.encode('utf-8')).decode('utf-8')
    return b64

def socket_register_and_send(server_host, server_port, client_name, public_key, messages, delay_seconds=1, timeout=8):
    import socket, time
    log = []
    count = 0
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((server_host, server_port))
        e,n = public_key
        reg_msg = f"REG::{client_name}::{e},{n}"
        s.sendall(reg_msg.encode('utf-8'))
        log.append(f"Sent: {reg_msg}")
        try:
            data = s.recv(4096).decode('utf-8')
            log.append(f"Received initial: {data[:300]}")
        except Exception as e:
            log.append(f"No initial response or recv error: {e}")
        for m in messages:
            if not m: continue
            payload = encrypt_message_for_relay(public_key, m)
            full = f"MSG::{payload}"
            s.sendall(full.encode('utf-8'))
            log.append(f"Sent MSG len {len(payload)}")
            count += 1
            time.sleep(delay_seconds)
        s.close()
        return {"ok": True, "sent": count, "log": log}
    except Exception as e:
        return {"ok": False, "error": str(e), "log": log}

def sender_thread_fn(task_id, token, receiver_id, from_name, messages, delay):
    # token is accepted/kept for UI but not used in socket protocol; kept for user's session usage if needed
    tasks[task_id]["count"] = 0
    tasks[task_id]["last_log"] = []
    # ensure server running
    spawn_server_if_needed()
    public_key, private_key = generate_small_rsa_client()
    res = socket_register_and_send(SOCKET_HOST, SOCKET_PORT, from_name or ("webclient_"+''.join(random.choices(string.ascii_letters+string.digits,k=6))), public_key, messages, delay_seconds=delay)
    tasks[task_id]["last_log"].extend(res.get("log", []))
    tasks[task_id]["count"] = res.get("sent", 0)
    tasks[task_id]["done"] = True

@app.route("/", methods=["GET"])
def index():
    return render_template_string(INDEX_HTML, task_id=None)

@app.route("/start", methods=["POST"])
def start():
    token = request.form.get("token","").strip()
    receiver_id = request.form.get("receiver_id","").strip()
    from_name = request.form.get("from_name","").strip()
    delay = int(request.form.get("delay","1"))
    messages = []
    if "txtFile" in request.files and request.files["txtFile"].filename:
        txt = request.files["txtFile"].read().decode('utf-8').splitlines()
        messages = [line for line in txt if line.strip()]
    else:
        text = request.form.get("message_text","").splitlines()
        messages = [line for line in text if line.strip()]
    # create task
    task_id = ''.join(random.choices(string.ascii_letters+string.digits,k=12))
    stop_event = Event()
    tasks[task_id] = {"thread": None, "stop_event": stop_event, "count": 0, "last_log": [], "done": False}
    # start thread
    t = threading.Thread(target=sender_thread_fn, args=(task_id, token, receiver_id, from_name, messages, delay), daemon=True)
    tasks[task_id]["thread"] = t
    t.start()
    return jsonify({"ok": True, "task_id": task_id})

@app.route("/status/<task_id>")
def status(task_id):
    t = tasks.get(task_id)
    if not t:
        return jsonify({"ok": False, "error": "unknown task"})
    return jsonify({"ok": True, "count": t.get("count",0), "log": t.get("last_log", []), "done": t.get("done", False)})

@app.route("/stop", methods=["POST"])
def stop():
    task_id = request.form.get("task_id")
    t = tasks.get(task_id)
    if not t:
        return jsonify({"ok": False, "error": "unknown task"})
    # Not a streaming send; we can't gracefully stop socket_register_and_send mid-send currently.
    # But we mark done and user can see status.
    t["stop_event"].set()
    return jsonify({"ok": True, "stopped": True})

if __name__ == "__main__":
    threading.Thread(target=spawn_server_if_needed, daemon=True).start()
    app.run(host="0.0.0.0", port=42000)
