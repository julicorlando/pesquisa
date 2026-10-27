import os
import re
import json
import hmac
import hashlib
import unicodedata
import smtplib
import secrets
from datetime import datetime, timezone
from email.message import EmailMessage
from functools import wraps
from urllib.parse import urlparse

from flask import Flask, request, redirect, url_for, render_template, flash, abort, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///pesquisa.db").replace("postgres://", "postgresql://", 1)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("COOKIE_SECURE", "0") == "1"
app.config["WTF_CSRF_TIME_LIMIT"] = None
db = SQLAlchemy(app)
csrf = CSRFProtect(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
limiter = Limiter(get_remote_address, app=app, default_limits=["250 per hour"], storage_uri=os.environ.get("RATELIMIT_STORAGE_URI", "memory://"))

SECTORS = ["Comercial", "Marketing", "Limpeza", "Manutenção", "Zeladoria", "Lago", "Parque das Aves", "Administrativo", "Estacionamento", "TI"]
ROLES = ["master", "auditoria", "comercial", "marketing", "operacional", "administrativo", "estacionamento", "ti"]
ROLE_SECTORS = {
    "comercial": ["Comercial"], "marketing": ["Marketing"],
    "operacional": ["Limpeza", "Manutenção", "Zeladoria", "Lago", "Parque das Aves"],
    "administrativo": ["Administrativo"], "estacionamento": ["Estacionamento"], "ti": ["TI"]
}
FACES = ["😠", "🙁", "😐", "😊", "😄"]
FACE_NAMES = ["Muito insatisfeito", "Insatisfeito", "Regular", "Satisfeito", "Muito satisfeito"]

def now():
    return datetime.now(timezone.utc)

def clean_name(v):
    v = unicodedata.normalize("NFKD", (v or "").strip().casefold())
    return re.sub(r"\s+", " ", "".join(c for c in v if not unicodedata.combining(c)))

def cnpj_digits(v):
    return re.sub(r"\D", "", v or "")

def valid_cnpj(value):
    d = cnpj_digits(value)
    if len(d) != 14 or len(set(d)) == 1:
        return False
    def digit(base, weights):
        k = sum(int(x) * w for x, w in zip(base, weights)) % 11
        return "0" if k < 2 else str(11 - k)
    return d[12] == digit(d[:12], [5,4,3,2,9,8,7,6,5,4,3,2]) and d[13] == digit(d[:13], [6,5,4,3,2,9,8,7,6,5,4,3,2])

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(90), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(30), nullable=False, default="auditoria")
    active = db.Column(db.Boolean, default=True)
    def get_id(self):
        return str(self.id)
    @property
    def is_active(self):
        return self.active

class Survey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    slug = db.Column(db.String(120), unique=True, nullable=False)
    description = db.Column(db.Text, default="")
    target = db.Column(db.String(30), default="lojista")
    active = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime(timezone=True), default=now)
    questions = db.relationship("Question", backref="survey", order_by="Question.position", cascade="all,delete-orphan")

class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    survey_id = db.Column(db.Integer, db.ForeignKey("survey.id"), nullable=False)
    sector = db.Column(db.String(50), nullable=False)
    text = db.Column(db.Text, nullable=False)
    position = db.Column(db.Integer, default=0)
    active = db.Column(db.Boolean, default=True)

class Merchant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    store_name = db.Column(db.String(180), nullable=False)
    cnpj = db.Column(db.String(14), unique=True, nullable=False)
    owner_name = db.Column(db.String(180), nullable=False)
    enabled = db.Column(db.Boolean, default=True)

class Response(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    survey_id = db.Column(db.Integer, db.ForeignKey("survey.id"), nullable=False)
    merchant_id = db.Column(db.Integer, db.ForeignKey("merchant.id"), nullable=True)
    store_name = db.Column(db.String(180))
    owner_name = db.Column(db.String(180))
    email = db.Column(db.String(255))
    cnpj = db.Column(db.String(14))
    submitted_at = db.Column(db.DateTime(timezone=True), default=now)
    email_sent = db.Column(db.Boolean, default=False)
    answers = db.relationship("Answer", backref="response", cascade="all,delete-orphan")

class Answer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    response_id = db.Column(db.Integer, db.ForeignKey("response.id"), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey("question.id"), nullable=False)
    rating = db.Column(db.Integer, nullable=False)

class Audit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    actor = db.Column(db.String(100), nullable=False)
    event = db.Column(db.String(100), nullable=False)
    detail = db.Column(db.Text, default="")
    ip_hash = db.Column(db.String(64))
    created_at = db.Column(db.DateTime(timezone=True), default=now)

def log(event, detail="", actor=None):
    salt = app.config["SECRET_KEY"].encode()
    address = (request.remote_addr or "") if request else ""
    ip_hash = hmac.new(salt, address.encode(), hashlib.sha256).hexdigest()[:24]
    db.session.add(Audit(actor=actor or (current_user.username if current_user.is_authenticated else "publico"), event=event, detail=detail[:1500], ip_hash=ip_hash))

@login_manager.user_loader
def load_user(uid):
    try:
        return db.session.get(User, int(uid))
    except (TypeError, ValueError):
        return None

def roles(*allowed):
    def outer(fn):
        @wraps(fn)
        @login_required
        def inner(*args, **kwargs):
            if current_user.role not in allowed:
                abort(403)
            return fn(*args, **kwargs)
        return inner
    return outer

@app.context_processor
def globals_for_templates():
    return {"sectors": SECTORS, "faces": FACES, "face_names": FACE_NAMES, "csrf": csrf}

@app.route("/")
def index():
    surveys = Survey.query.filter_by(active=True).order_by(Survey.id.desc()).all()
    return render_template("index.html", surveys=surveys)

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("8 per minute")
def login():
    if request.method == "POST":
        user = User.query.filter_by(username=request.form.get("username", "")).first()
        if user and user.active and check_password_hash(user.password_hash, request.form.get("password", "")):
            login_user(user)
            log("login")
            db.session.commit()
            return redirect(url_for("dashboard"))
        log("login_fail")
        db.session.commit()
        flash("Credenciais inválidas.", "error")
    return render_template("login.html")

@app.post("/logout")
@login_required
def logout():
    log("logout")
    db.session.commit()
    logout_user()
    return redirect(url_for("index"))

@app.route("/dashboard")
@login_required
def dashboard():
    accessible = SECTORS if current_user.role in ("master", "auditoria") else ROLE_SECTORS.get(current_user.role, [])
    # Agregação no banco e limiar mínimo contra reidentificação de respostas.
    rows = (db.session.query(Survey.title, Question.sector, db.func.count(Answer.id), db.func.avg(Answer.rating))
            .join(Question, Question.survey_id == Survey.id)
            .outerjoin(Answer, Answer.question_id == Question.id)
            .filter(Question.sector.in_(accessible))
            .group_by(Survey.id, Question.sector).order_by(Survey.id.desc()).all()) if accessible else []
    stats = [{"survey": a, "sector": b, "count": int(c), "avg": round(float(d), 2) if c >= 3 and d is not None else None} for a,b,c,d in rows]
    log("dashboard_view", ",".join(accessible))
    db.session.commit()
    return render_template("dashboard.html", stats=stats, surveys=Survey.query.all() if current_user.role == "master" else [])

@app.route("/admin/surveys", methods=["GET", "POST"])
@roles("master")
def manage_surveys():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        slug = re.sub(r"[^a-z0-9-]", "-", request.form.get("slug", "").lower()).strip("-")
        if not title or not slug or Survey.query.filter_by(slug=slug).first():
            flash("Informe título e slug exclusivo.", "error")
        else:
            s = Survey(title=title[:200], slug=slug[:120], description=request.form.get("description", "")[:2000],
                       target=request.form.get("target") if request.form.get("target") in ("lojista", "publico") else "lojista")
            db.session.add(s)
            log("survey_create", slug)
            db.session.commit()
            return redirect(url_for("edit_survey", sid=s.id))
    return render_template("surveys.html", surveys=Survey.query.order_by(Survey.id.desc()).all())

@app.route("/admin/surveys/<int:sid>", methods=["GET", "POST"])
@roles("master")
def edit_survey(sid):
    survey = db.get_or_404(Survey, sid)
    if request.method == "POST":
        kind = request.form.get("kind")
        if kind == "settings":
            survey.title = request.form.get("title", survey.title)[:200]
            survey.description = request.form.get("description", "")[:2000]
            survey.target = request.form.get("target") if request.form.get("target") in ("lojista", "publico") else survey.target
            survey.active = request.form.get("active") == "on"
            log("survey_update", str(sid))
        elif kind == "question":
            sector = request.form.get("sector")
            text = request.form.get("text", "").strip()
            if sector in SECTORS and text:
                db.session.add(Question(survey_id=sid, sector=sector, text=text[:1000], position=len(survey.questions)+1))
                log("question_create", str(sid))
        elif kind == "edit_question":
            q = db.get_or_404(Question, int(request.form.get("question_id", 0)))
            if q.survey_id != sid:
                abort(403)
            if request.form.get("delete") == "yes":
                if Answer.query.filter_by(question_id=q.id).first():
                    q.active = False
                else:
                    db.session.delete(q)
                log("question_remove", str(q.id))
            else:
                q.text = request.form.get("text", q.text)[:1000]
                q.active = request.form.get("active") == "on"
                log("question_update", str(q.id))
        db.session.commit()
        return redirect(url_for("edit_survey", sid=sid))
    return render_template("edit_survey.html", survey=survey)

@app.route("/admin/merchants", methods=["GET", "POST"])
@roles("master")
def merchants():
    if request.method == "POST":
        name, owner = request.form.get("store_name", "").strip(), request.form.get("owner_name", "").strip()
        cnpj = cnpj_digits(request.form.get("cnpj"))
        if not name or not owner or not valid_cnpj(cnpj):
            flash("Informe loja, responsável e CNPJ válido.", "error")
        elif Merchant.query.filter_by(cnpj=cnpj).first():
            flash("CNPJ já cadastrado.", "error")
        else:
            db.session.add(Merchant(store_name=name[:180], owner_name=owner[:180], cnpj=cnpj))
            log("merchant_create", "cadastro aprovado")
            db.session.commit()
            return redirect(url_for("merchants"))
    return render_template("merchants.html", merchants=Merchant.query.order_by(Merchant.store_name).all())

@app.post("/admin/merchants/<int:mid>/toggle")
@roles("master")
def toggle_merchant(mid):
    m = db.get_or_404(Merchant, mid)
    m.enabled = not m.enabled
    log("merchant_toggle", str(mid))
    db.session.commit()
    return redirect(url_for("merchants"))

@app.route("/admin/users", methods=["GET", "POST"])
@roles("master")
def users():
    if request.method == "POST":
        username, password, role = request.form.get("username", "").strip(), request.form.get("password", ""), request.form.get("role")
        if len(password) < 12 or role not in ROLES or not username or User.query.filter_by(username=username).first():
            flash("Usuário exclusivo, perfil válido e senha com pelo menos 12 caracteres.", "error")
        else:
            db.session.add(User(username=username[:90], password_hash=generate_password_hash(password), role=role))
            log("user_create", username + ":" + role)
            db.session.commit()
            return redirect(url_for("users"))
    return render_template("users.html", users=User.query.order_by(User.username).all(), roles=ROLES)

@app.post("/admin/users/<int:uid>/toggle")
@roles("master")
def toggle_user(uid):
    u = db.get_or_404(User, uid)
    if u.id == current_user.id:
        abort(400)
    u.active = not u.active
    log("user_toggle", str(uid))
    db.session.commit()
    return redirect(url_for("users"))

@app.get("/admin/responses")
@roles("master")
def admin_responses():
    records = Response.query.order_by(Response.submitted_at.desc()).limit(500).all()
    log("pii_access", "response_list")
    db.session.commit()
    return render_template("responses.html", records=records)

@app.get("/admin/responses/<int:rid>")
@roles("master")
def response_detail(rid):
    record = db.get_or_404(Response, rid)
    log("pii_access", "response:" + str(rid))
    db.session.commit()
    return render_template("response_detail.html", record=record, answers=[(db.session.get(Question, a.question_id), a.rating) for a in record.answers])

@app.get("/audit")
@roles("master", "auditoria")
def audit():
    logs = Audit.query.order_by(Audit.id.desc()).limit(500).all()
    return render_template("audit.html", logs=logs)

@app.route("/p/<slug>", methods=["GET", "POST"])
@limiter.limit("40 per hour")
def public_survey(slug):
    s = Survey.query.filter_by(slug=slug, active=True).first_or_404()
    questions = [q for q in s.questions if q.active]
    if not questions:
        abort(404)
    if request.method == "POST":
        if request.form.get("stage") == "identity":
            info = {k: request.form.get(k, "").strip()[:255] for k in ("store_name", "email", "owner_name", "cnpj")}
            authorized = s.target == "publico"
            matched = None
            if s.target == "lojista":
                d = cnpj_digits(info["cnpj"])
                matched = Merchant.query.filter_by(cnpj=d, enabled=True).first() if valid_cnpj(d) else None
                authorized = bool(matched and hmac.compare_digest(clean_name(info["owner_name"]), clean_name(matched.owner_name)))
            if not authorized:
                log("audience_denied", "survey:" + str(s.id))
                db.session.commit()
                return render_template("thanks.html", sent=False)
            if s.target == "lojista" and (not info["store_name"] or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", info["email"])):
                flash("Preencha nome da loja e e-mail válido.", "error")
            else:
                token = secrets.token_urlsafe(20)
                session["survey_state"] = {"survey": s.id, "token": token, "identity": info, "merchant_id": matched.id if matched else None}
                return redirect(url_for("answer_survey", slug=slug))
    return render_template("identity.html", survey=s)

@app.route("/p/<slug>/responder", methods=["GET", "POST"])
@limiter.limit("80 per hour")
def answer_survey(slug):
    s = Survey.query.filter_by(slug=slug, active=True).first_or_404()
    state = session.get("survey_state") or {}
    if state.get("survey") != s.id:
        return redirect(url_for("public_survey", slug=slug))
    questions = [q for q in s.questions if q.active]
    if not questions:
        abort(404)
    if request.method == "POST":
        ratings = {}
        for q in questions:
            raw = request.form.get("q_" + str(q.id), "")
            if raw not in ("1", "2", "3", "4", "5"):
                flash("Responda todas as perguntas antes de confirmar.", "error")
                return render_template("answer.html", survey=s, questions=questions, values=request.form)
            ratings[q.id] = int(raw)
        if request.form.get("confirm") != "yes":
            flash("Confirme suas respostas na última etapa.", "error")
            return render_template("answer.html", survey=s, questions=questions, values=request.form)
        # Revalidação no servidor da lista de acesso, inclusive após voltar pelo navegador.
        merchant = db.session.get(Merchant, state.get("merchant_id")) if state.get("merchant_id") else None
        if s.target == "lojista" and (not merchant or not merchant.enabled or
            cnpj_digits(state["identity"].get("cnpj")) != merchant.cnpj or
            not hmac.compare_digest(clean_name(state["identity"].get("owner_name")), clean_name(merchant.owner_name))):
            log("audience_denied", "survey:" + str(s.id))
            db.session.commit()
            session.pop("survey_state", None)
            return render_template("thanks.html", sent=False)
        identity = state["identity"]
        resp = Response(survey_id=s.id, merchant_id=merchant.id if merchant else None,
                        store_name=identity.get("store_name"), email=identity.get("email"),
                        owner_name=identity.get("owner_name"), cnpj=cnpj_digits(identity.get("cnpj")))
        db.session.add(resp)
        db.session.flush()
        for q in questions:
            db.session.add(Answer(response_id=resp.id, question_id=q.id, rating=ratings[q.id]))
        log("survey_submitted", "survey:" + str(s.id))
        db.session.commit()
        session.pop("survey_state", None)
        sent = send_receipt(resp, s, questions, ratings)
        if sent:
            resp.email_sent = True
            db.session.commit()
        return render_template("thanks.html", sent=sent)
    return render_template("answer.html", survey=s, questions=questions, values={})

def send_receipt(resp, survey, questions, ratings):
    host = os.environ.get("SMTP_HOST")
    if not host or not resp.email:
        return False
    msg = EmailMessage()
    msg["Subject"] = "Obrigado por participar — " + survey.title
    msg["From"] = os.environ.get("SMTP_FROM", "pesquisa@example.invalid")
    msg["To"] = resp.email
    lines = ["Obrigado por participar da pesquisa!", "", survey.title, "",
             "Segue o comprovante das suas avaliações:"]
    lines += [q.sector + " — " + q.text + ": " + str(ratings[q.id]) + "/5" for q in questions]
    msg.set_content("\n".join(lines))
    try:
        port = int(os.environ.get("SMTP_PORT", "587"))
        with smtplib.SMTP(host, port, timeout=12) as smtp:
            if os.environ.get("SMTP_TLS", "1") == "1":
                smtp.starttls()
            if os.environ.get("SMTP_USER"):
                smtp.login(os.environ["SMTP_USER"], os.environ.get("SMTP_PASSWORD", ""))
            smtp.send_message(msg)
        return True
    except Exception:
        app.logger.exception("Falha ao enviar recibo de pesquisa")
        return False

@app.cli.command("init-db")
def init_db():
    db.create_all()
    print("Tabelas criadas.")

@app.cli.command("create-master")
def create_master():
    db.create_all()
    username = os.environ.get("MASTER_USERNAME")
    password = os.environ.get("MASTER_PASSWORD")
    if not username or not password or len(password) < 12:
        raise SystemExit("Defina MASTER_USERNAME e MASTER_PASSWORD (mínimo 12 caracteres).")
    if User.query.filter_by(username=username).first():
        raise SystemExit("Usuário já existe.")
    db.session.add(User(username=username, password_hash=generate_password_hash(password), role="master"))
    db.session.commit()
    print("Master criado.")

if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")


DEFAULT_QUESTIONS = {
 "Comercial": [
  "Como você avalia o atendimento e a disponibilidade da equipe comercial?",
  "As condições comerciais e orientações contratuais são comunicadas com clareza?",
  "Como você avalia o suporte comercial às demandas da sua loja?",
  "Como você avalia a agilidade nas respostas do setor Comercial?"
 ],
 "Marketing": [
  "Como você avalia a divulgação das campanhas promocionais do shopping?",
  "Como você avalia a comunicação antecipada das ações de marketing aos lojistas?",
  "As campanhas realizadas contribuem para atrair visitantes ao shopping?",
  "Como você avalia as oportunidades de participação dos lojistas nas campanhas?"
 ],
 "Limpeza": [
  "Como você avalia a limpeza dos corredores e áreas comuns?",
  "Como você avalia a limpeza e conservação dos banheiros?",
  "Como você avalia a frequência de limpeza nas áreas comuns?",
  "Como você avalia a agilidade no atendimento às solicitações de limpeza?"
 ],
 "Manutenção": [
  "Como você avalia a conservação da estrutura física do shopping?",
  "Como você avalia a iluminação das áreas comuns?",
  "Como você avalia a agilidade no atendimento às solicitações de manutenção?",
  "Como você avalia a qualidade das soluções realizadas pela Manutenção?"
 ],
 "Zeladoria": [
  "Como você avalia a organização e conservação geral das áreas comuns?",
  "Como você avalia o atendimento prestado pela Zeladoria?",
  "Como você avalia a clareza das orientações operacionais recebidas?",
  "Como você avalia o acompanhamento e encaminhamento de demandas pela Zeladoria?"
 ],
 "Lago": [
  "Como você avalia a limpeza e conservação do lago?",
  "Como você avalia a aparência e paisagismo da área do lago?",
  "Como você avalia a segurança e a sinalização no entorno do lago?",
  "Como você avalia a contribuição do lago para a experiência dos visitantes?"
 ],
 "Parque das Aves": [
  "Como você avalia a limpeza e conservação do Parque das Aves?",
  "Como você percebe as condições de cuidado e bem-estar das aves?",
  "Como você avalia a segurança e organização do espaço?",
  "Como você avalia a contribuição do Parque das Aves para a experiência dos visitantes?"
 ],
 "Administrativo": [
  "Como você avalia o atendimento prestado pela Administração?",
  "Como você avalia a clareza dos comunicados administrativos?",
  "Como você avalia a agilidade nas respostas às demandas dos lojistas?",
  "Como você avalia a transparência e organização dos processos administrativos?"
 ],
 "Estacionamento": [
  "Como você avalia a organização e sinalização do estacionamento?",
  "Como você avalia a limpeza e conservação do estacionamento?",
  "Como você avalia a facilidade de entrada e saída dos veículos?",
  "Como você avalia o funcionamento dos equipamentos e cancelas?",
  "Como você avalia o atendimento da equipe de estacionamento?"
 ],
 "TI": [
  "Como você avalia a facilidade de conexão ao Mall Wi-Fi público?",
  "Como você avalia a estabilidade do Mall Wi-Fi público?",
  "Como você avalia a velocidade do Mall Wi-Fi público?",
  "Como você avalia o funcionamento dos recursos tecnológicos do estacionamento percebidos pelos usuários?"
 ]
}

@app.cli.command("seed-survey")
def seed_survey():
    db.create_all()
    slug = "satisfacao-lojistas-shopping-carpina"
    survey = Survey.query.filter_by(slug=slug).first()
    if survey:
        print("Pesquisa já existe; nenhuma pergunta duplicada.")
        return
    survey = Survey(title="Pesquisa de Satisfação dos Lojistas — Shopping Carpina",
                    slug=slug, description="Avalie os serviços oferecidos pelo Shopping Carpina. Uma nota de 1 a 5 por pergunta.",
                    target="lojista", active=False)
    db.session.add(survey)
    db.session.flush()
    order = 0
    for sector, texts in DEFAULT_QUESTIONS.items():
        for question_text in texts:
            order += 1
            db.session.add(Question(survey_id=survey.id, sector=sector, text=question_text, position=order))
    db.session.commit()
    print("Pesquisa criada com", order, "perguntas. Cadastre lojistas e abra-a no Master.")
