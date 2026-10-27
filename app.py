import os
import re
import base64
import csv
import io
import json
import hmac
import hashlib
import unicodedata
import smtplib
import secrets
import random
import calendar
import zipfile
from collections import Counter
from datetime import datetime, timezone, timedelta
from zoneinfo import ZoneInfo
from email.message import EmailMessage
from functools import wraps
from urllib.parse import urlparse

from flask import Flask, request, redirect, url_for, render_template, flash, abort, session, jsonify, send_file, has_request_context
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import inspect, text

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

SECTORS = ["Geral", "Comercial", "Marketing", "Limpeza", "Manutenção", "Zeladoria", "Lago", "Parque das Aves", "Administrativo", "Estacionamento", "TI"]
ROLES = ["master", "auditoria", "comercial", "marketing", "operacional", "administrativo", "estacionamento", "ti"]
ROLE_SECTORS = {
    "comercial": ["Geral", "Comercial"], "marketing": ["Geral", "Marketing"],
    "operacional": ["Geral", "Limpeza", "Manutenção", "Zeladoria", "Lago", "Parque das Aves"],
    "administrativo": ["Geral", "Administrativo"], "estacionamento": ["Geral", "Estacionamento"], "ti": ["Geral", "TI"]
}
FACES = ["😠", "🙁", "😐", "😊", "😄"]
FACE_NAMES = ["Muito insatisfeito", "Insatisfeito", "Regular", "Satisfeito", "Muito satisfeito"]

def now():
    return datetime.now(timezone.utc)

RECIFE_TZ = ZoneInfo("America/Recife")

def parse_local_datetime(value):
    value = (value or "").strip()
    if not value:
        return None
    return datetime.strptime(value, "%Y-%m-%dT%H:%M").replace(tzinfo=RECIFE_TZ).astimezone(timezone.utc)

def as_utc(value):
    if value is None:
        return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)

def survey_is_open(survey):
    current = now()
    return bool(survey.active and (survey.starts_at is None or as_utc(survey.starts_at) <= current)
                and (survey.ends_at is None or as_utc(survey.ends_at) >= current))

def local_datetime_input(value):
    value = as_utc(value)
    return value.astimezone(RECIFE_TZ).strftime("%Y-%m-%dT%H:%M") if value else ""

app.jinja_env.filters["local_datetime_input"] = local_datetime_input

def format_device_datetime(value, zone_name):
    if not value:
        return "Não informado pelo dispositivo"
    try:
        zone = ZoneInfo(zone_name) if zone_name else timezone.utc
    except (ValueError, KeyError):
        zone = timezone.utc
    return as_utc(value).astimezone(zone).strftime("%d/%m/%Y %H:%M:%S")

app.jinja_env.filters["device_datetime"] = format_device_datetime

def clean_name(v):
    v = unicodedata.normalize("NFKD", (v or "").strip().casefold())
    return re.sub(r"\s+", " ", "".join(c for c in v if not unicodedata.combining(c)))

COMMENT_THEMES = {
    "Estacionamento": ("estacionamento", "vaga", "carro", "cancela", "ticket"),
    "Atendimento": ("atendimento", "atendente", "funcionario", "equipe", "demora", "fila"),
    "Limpeza": ("limpeza", "suj", "lixo", "banheiro", "conservacao"),
    "Segurança": ("seguranca", "seguro", "risco", "vigilante", "furto"),
    "Acessibilidade": ("acessibilidade", "rampa", "cadeirante", "elevador", "mobilidade"),
    "Pagamento": ("pagamento", "pagar", "pix", "cartao", "preco", "cobranca"),
    "Infraestrutura": ("estrutura", "ar condicionado", "temperatura", "iluminacao", "wifi", "internet", "manutencao"),
    "Alimentação": ("comida", "alimentacao", "restaurante", "praca de alimentacao", "lanchonete"),
}

def classify_comment(value):
    normalized = clean_name(value)
    matches = [theme for theme, words in COMMENT_THEMES.items() if any(clean_name(word) in normalized for word in words)]
    return matches or ["Outros"]

def cnpj_digits(v):
    return re.sub(r"\D", "", v or "")

def valid_cpf(value):
    d = re.sub(r"\D", "", value or "")
    if len(d) != 11 or len(set(d)) == 1:
        return False
    for i in (9, 10):
        digit = (sum(int(d[j]) * (i + 1 - j) for j in range(i)) * 10) % 11
        if digit == 10:
            digit = 0
        if int(d[i]) != digit:
            return False
    return True

def parse_choices(value):
    options = [line.strip() for line in (value or "").splitlines() if line.strip()]
    if not 2 <= len(options) <= 20 or any(len(item) > 200 for item in options):
        return None
    if len({item.casefold() for item in options}) != len(options):
        return None
    return options

def branch_value_valid(question, value):
    if not question or not value:
        return False
    if question.answer_type == "rating":
        return value in ("1", "2", "3", "4", "5") or (value == "na" and question.allow_na)
    if question.answer_type == "nps":
        return value in tuple(str(n) for n in range(11))
    return question.answer_type == "single" and value in question.choice_options

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

class FirstAccessToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    token_hash = db.Column(db.String(64), unique=True, nullable=False)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False)
    used_at = db.Column(db.DateTime(timezone=True))
    created_at = db.Column(db.DateTime(timezone=True), default=now)
    user = db.relationship("User")

class SMTPConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    host = db.Column(db.String(255), default="")
    port = db.Column(db.Integer, default=587)
    tls = db.Column(db.Boolean, default=True)
    username = db.Column(db.String(255), default="")
    from_address = db.Column(db.String(255), default="")
    master_alert_email = db.Column(db.String(255), default="")
    password_encrypted = db.Column(db.Text)
    updated_at = db.Column(db.DateTime(timezone=True), default=now)

class Survey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    slug = db.Column(db.String(120), unique=True, nullable=False)
    description = db.Column(db.Text, default="")
    target = db.Column(db.String(30), default="lojista")
    active = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime(timezone=True), default=now)
    identity_type = db.Column(db.String(8), nullable=False, default="none")
    whatsapp_mode = db.Column(db.String(12), nullable=False, default="none")
    followup_enabled = db.Column(db.Boolean, nullable=False, default=True)
    shuffle_questions = db.Column(db.Boolean, nullable=False, default=False)
    starts_at = db.Column(db.DateTime(timezone=True))
    ends_at = db.Column(db.DateTime(timezone=True))
    response_limit = db.Column(db.String(20), nullable=False, default="none")
    automatic_reminders = db.Column(db.Boolean, nullable=False, default=False)
    reminder_delay_days = db.Column(db.Integer, nullable=False, default=3)
    questions = db.relationship("Question", backref="survey", order_by="Question.position", cascade="all,delete-orphan")

class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    survey_id = db.Column(db.Integer, db.ForeignKey("survey.id"), nullable=False)
    sector = db.Column(db.String(50), nullable=False)
    text = db.Column(db.Text, nullable=False)
    position = db.Column(db.Integer, default=0)
    active = db.Column(db.Boolean, default=True)
    optional = db.Column(db.Boolean, nullable=False, default=False)
    allow_na = db.Column(db.Boolean, nullable=False, default=True)
    answer_type = db.Column(db.String(20), nullable=False, default="rating")
    notice = db.Column(db.Text, default="")
    choices = db.Column(db.Text, nullable=False, default="[]")
    branch_question_id = db.Column(db.Integer, db.ForeignKey("question.id"), nullable=True)
    branch_value = db.Column(db.String(255), nullable=False, default="")
    @property
    def choice_options(self):
        try:
            items = json.loads(self.choices or "[]")
            return [str(item) for item in items if isinstance(item, str)] if isinstance(items, list) else []
        except (TypeError, ValueError):
            return []

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
    device_submitted_at = db.Column(db.DateTime(timezone=True))
    device_timezone = db.Column(db.String(80), default="")
    email_sent = db.Column(db.Boolean, default=False)
    answers = db.relationship("Answer", backref="response", cascade="all,delete-orphan")

class RespondentIdentity(db.Model):
    """Dados identificáveis, armazenados sem relação com respostas individuais."""
    id = db.Column(db.Integer, primary_key=True)
    survey_id = db.Column(db.Integer, db.ForeignKey("survey.id"), nullable=False)
    document_type = db.Column(db.String(8), nullable=False, default="none")
    document_number = db.Column(db.String(18), default="")
    eligibility_cnpj = db.Column(db.String(14), default="")
    token_hash = db.Column(db.String(64), unique=True, nullable=True)
    store_name = db.Column(db.String(180), default="")
    owner_name = db.Column(db.String(180), default="")
    email = db.Column(db.String(255), default="")
    whatsapp_number = db.Column(db.String(20), default="")
    submitted_at = db.Column(db.DateTime(timezone=True), default=now)

class Answer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    response_id = db.Column(db.Integer, db.ForeignKey("response.id"), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey("question.id"), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    answer_text = db.Column(db.Text)

class Audit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    actor = db.Column(db.String(100), nullable=False)
    event = db.Column(db.String(100), nullable=False)
    detail = db.Column(db.Text, default="")
    ip_hash = db.Column(db.String(64))
    created_at = db.Column(db.DateTime(timezone=True), default=now)

class SystemIncident(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    component = db.Column(db.String(40), nullable=False)
    summary = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=now)
    resolved_at = db.Column(db.DateTime(timezone=True))

class ActionPlan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    survey_id = db.Column(db.Integer, db.ForeignKey("survey.id"), nullable=False)
    sector = db.Column(db.String(50), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, default="")
    owner = db.Column(db.String(120), default="")
    priority = db.Column(db.String(10), default="media")
    status = db.Column(db.String(20), default="aberto")
    due_date = db.Column(db.Date)
    baseline_average = db.Column(db.Float)
    reviewed_average = db.Column(db.Float)
    reviewed_at = db.Column(db.DateTime(timezone=True))
    review_notes = db.Column(db.Text, default="")
    created_at = db.Column(db.DateTime(timezone=True), default=now)

class ParticipantFollowup(db.Model):
    """Solicitações de retorno, isoladas e sem referência à resposta individual."""
    id = db.Column(db.Integer, primary_key=True)
    survey_id = db.Column(db.Integer, db.ForeignKey("survey.id"), nullable=False)
    email = db.Column(db.String(255), nullable=False, default="")
    whatsapp = db.Column(db.String(20), nullable=False, default="")
    topic = db.Column(db.String(1000), nullable=False)
    status = db.Column(db.String(20), nullable=False, default="pendente")
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=now)
    contacted_at = db.Column(db.DateTime(timezone=True))

class SurveyAlert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    alert_key = db.Column(db.String(255), unique=True, nullable=False)
    survey_id = db.Column(db.Integer, db.ForeignKey("survey.id"), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey("question.id"), nullable=False)
    sector = db.Column(db.String(50), nullable=False)
    alert_type = db.Column(db.String(30), nullable=False)
    period_key = db.Column(db.String(20), nullable=False)
    summary = db.Column(db.String(500), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=now)
    action_plan_id = db.Column(db.Integer, db.ForeignKey("action_plan.id"))

class AlertSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True, default=1)
    nps_drop_points = db.Column(db.Integer, nullable=False, default=10)
    low_score_threshold = db.Column(db.Integer, nullable=False, default=3)
    low_score_max = db.Column(db.Integer, nullable=False, default=2)
    minimum_sample = db.Column(db.Integer, nullable=False, default=3)
    updated_at = db.Column(db.DateTime(timezone=True), default=now)

class SectorGoal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    survey_id = db.Column(db.Integer, db.ForeignKey("survey.id"), nullable=True)
    sector = db.Column(db.String(50), nullable=False)
    period_key = db.Column(db.String(7), nullable=False)
    metric = db.Column(db.String(12), nullable=False)
    target = db.Column(db.Float, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=now)
    survey = db.relationship("Survey")

class ReportSchedule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    recipient_email = db.Column(db.String(255), nullable=False)
    sector = db.Column(db.String(50), nullable=False)
    frequency = db.Column(db.String(10), nullable=False)
    weekday = db.Column(db.Integer, nullable=False, default=0)
    month_day = db.Column(db.Integer, nullable=False, default=1)
    send_hour = db.Column(db.Integer, nullable=False, default=8)
    active = db.Column(db.Boolean, nullable=False, default=True)
    last_sent_period = db.Column(db.String(20), default="")
    created_at = db.Column(db.DateTime(timezone=True), default=now)

class SurveyInvite(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    survey_id = db.Column(db.Integer, db.ForeignKey("survey.id"), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    reminder_sent_at = db.Column(db.DateTime(timezone=True))
    response_token_hash = db.Column(db.String(64), default="")
    responded_at = db.Column(db.DateTime(timezone=True))
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=now)
    __table_args__ = (db.UniqueConstraint("survey_id", "email", name="uq_survey_invite_email"),)

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

@app.template_filter("choice_values")
def choice_values(value):
    try:
        choices = json.loads(value or "[]")
        return ", ".join(str(item) for item in choices) if isinstance(choices, list) else ""
    except (TypeError, ValueError):
        return ""

@app.context_processor
def globals_for_templates():
    return {"sectors": SECTORS, "faces": FACES, "face_names": FACE_NAMES, "csrf": csrf}

@app.route("/")
def index():
    surveys = [s for s in Survey.query.filter_by(active=True).order_by(Survey.id.desc()).all() if survey_is_open(s)]
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

def dashboard_data(accessible):
    query = (db.session.query(
                Survey.id, Survey.title, Question.sector, Question.answer_type,
                db.func.count(Answer.id), db.func.avg(Answer.rating),
                db.func.sum(db.case((Answer.rating >= 9, 1), else_=0)),
                db.func.sum(db.case((Answer.rating <= 6, 1), else_=0)),
                db.func.sum(db.case((db.and_(Answer.rating >= 7, Answer.rating <= 8), 1), else_=0)))
             .join(Question, Question.survey_id == Survey.id)
             .outerjoin(Answer, db.and_(Answer.question_id == Question.id,
                 db.or_(db.and_(Question.answer_type == "rating", Answer.rating.between(1, 5)),
                        db.and_(Question.answer_type == "nps", Answer.rating.between(0, 10)))))
             .outerjoin(Response, Response.id == Answer.response_id)
             .filter(Question.answer_type.in_(("rating", "nps")), Question.sector.in_(accessible)))
    survey_id = request.args.get("survey", type=int)
    sector = request.args.get("sector", "")
    date_from = request.args.get("from", "")
    date_to = request.args.get("to", "")
    if survey_id:
        query = query.filter(Survey.id == survey_id)
    if sector in accessible:
        query = query.filter(Question.sector == sector)
    try:
        if date_from:
            query = query.filter(Response.submitted_at >= datetime.strptime(date_from, "%Y-%m-%d").replace(tzinfo=timezone.utc))
        if date_to:
            query = query.filter(Response.submitted_at < datetime.strptime(date_to, "%Y-%m-%d").replace(tzinfo=timezone.utc) + timedelta(days=1))
    except ValueError:
        date_from = date_to = ""
    rows = query.group_by(Survey.id, Question.sector, Question.answer_type).order_by(Survey.id.desc()).all()
    stats = []
    for sid, title, sec, kind, count, average, promoters, detractors, passives in rows:
        count = int(count or 0)
        nps_score = round(((int(promoters or 0) - int(detractors or 0)) / count) * 100) if count >= 3 and kind == "nps" else None
        stats.append({"survey": title, "survey_id": sid, "sector": sec, "type": kind, "count": count,
                      "avg": round(float(average), 2) if count >= 3 and kind == "rating" and average is not None else None,
                      "nps": nps_score, "promoters": int(promoters or 0), "detractors": int(detractors or 0), "passives": int(passives or 0)})
    trend_query = (db.session.query(
            db.func.extract("year", Response.submitted_at), db.func.extract("month", Response.submitted_at),
            Survey.title, Question.sector, Question.answer_type, db.func.count(Answer.id), db.func.avg(Answer.rating),
            db.func.sum(db.case((Answer.rating >= 9, 1), else_=0)),
            db.func.sum(db.case((Answer.rating <= 6, 1), else_=0)))
        .join(Question, Question.survey_id == Survey.id)
        .join(Answer, Answer.question_id == Question.id)
        .join(Response, Response.id == Answer.response_id)
        .filter(Question.answer_type.in_(("rating", "nps")), Question.sector.in_(accessible)))
    if survey_id:
        trend_query = trend_query.filter(Survey.id == survey_id)
    if sector in accessible:
        trend_query = trend_query.filter(Question.sector == sector)
    if date_from:
        trend_query = trend_query.filter(Response.submitted_at >= datetime.strptime(date_from, "%Y-%m-%d").replace(tzinfo=timezone.utc))
    if date_to:
        trend_query = trend_query.filter(Response.submitted_at < datetime.strptime(date_to, "%Y-%m-%d").replace(tzinfo=timezone.utc) + timedelta(days=1))
    trend_rows = trend_query.group_by(db.func.extract("year", Response.submitted_at), db.func.extract("month", Response.submitted_at), Survey.id, Question.sector, Question.answer_type).order_by(db.func.extract("year", Response.submitted_at), db.func.extract("month", Response.submitted_at)).all()
    trends = []
    for year, month, title, sec, kind, count, average, promoters, detractors in trend_rows:
        count = int(count or 0)
        trends.append({"month": "%04d-%02d" % (int(year), int(month)), "survey": title, "sector": sec,
            "type": kind, "count": count, "avg": round(float(average), 2) if count >= 3 and kind == "rating" and average is not None else None,
            "nps": round(((int(promoters or 0) - int(detractors or 0)) / count) * 100) if count >= 3 and kind == "nps" else None})
    return stats, survey_id, sector, date_from, date_to, trends

def dashboard_question_details(survey_id, accessible, sector, date_from, date_to, role):
    if not survey_id or not accessible:
        return []
    query = Question.query.filter_by(survey_id=survey_id).filter(Question.sector.in_(accessible))
    if sector in accessible:
        query = query.filter(Question.sector == sector)
    questions = query.order_by(Question.position, Question.id).all()
    details = []
    for question in questions:
        answers_query = (db.session.query(Answer, Response.submitted_at, Response.device_submitted_at, Response.device_timezone)
            .join(Response, Response.id == Answer.response_id)
            .filter(Response.survey_id == survey_id, Answer.question_id == question.id))
        if date_from:
            answers_query = answers_query.filter(Response.submitted_at >= datetime.strptime(date_from, "%Y-%m-%d").replace(tzinfo=timezone.utc))
        if date_to:
            answers_query = answers_query.filter(Response.submitted_at < datetime.strptime(date_to, "%Y-%m-%d").replace(tzinfo=timezone.utc) + timedelta(days=1))
        rows = answers_query.order_by(Response.submitted_at.desc()).all()
        item = {"question": question, "count": len(rows), "distribution": [], "open_answers": [], "hidden_text": False,
                "distribution_suppressed": len(rows) < 3}
        if question.answer_type in ("rating", "nps"):
            labels = range(1, 6) if question.answer_type == "rating" else range(0, 11)
            counts = {value: 0 for value in labels}
            not_applicable = 0
            for answer, *_ in rows:
                if question.answer_type == "rating" and answer.rating == 0:
                    not_applicable += 1
                elif answer.rating in counts:
                    counts[answer.rating] += 1
            item["distribution"] = [{"label": str(value), "count": counts[value]} for value in counts]
            item["not_applicable"] = not_applicable
            valid_count = sum(counts.values())
            item["average"] = round(sum(value * count for value, count in counts.items()) / valid_count, 2) if question.answer_type == "rating" and valid_count >= 3 else None
            item["nps"] = round((sum(counts[value] for value in range(9, 11)) - sum(counts[value] for value in range(0, 7))) / valid_count * 100) if question.answer_type == "nps" and valid_count >= 3 else None
        elif question.answer_type in ("single", "multiple"):
            counts = {option: 0 for option in question.choice_options}
            for answer, *_ in rows:
                try:
                    selected = json.loads(answer.answer_text or "[]")
                except (TypeError, ValueError):
                    selected = []
                for value in selected if isinstance(selected, list) else []:
                    if value in counts:
                        counts[value] += 1
            item["distribution"] = [{"label": option, "count": count} for option, count in counts.items()]
        elif question.answer_type == "open":
            if role == "master" or question.sector == "Geral":
                item["open_answers"] = [{"text": answer.answer_text, "themes": classify_comment(answer.answer_text), "submitted_at": submitted_at,
                    "device_submitted_at": device_at, "device_timezone": device_zone}
                    for answer, submitted_at, device_at, device_zone in rows if answer.answer_text]
            else:
                item["hidden_text"] = True
        details.append(item)
    return details

def evaluate_survey_alerts(survey_id):
    survey = db.session.get(Survey, survey_id)
    if not survey:
        return
    current = now()
    recent_start = current - timedelta(days=30)
    prior_start = current - timedelta(days=60)
    settings = db.session.get(AlertSettings, 1)
    minimum_sample = settings.minimum_sample if settings else 3
    low_score_threshold = settings.low_score_threshold if settings else 3
    low_score_max = settings.low_score_max if settings else 2
    nps_drop_points = settings.nps_drop_points if settings else 10
    period_key = current.astimezone(RECIFE_TZ).strftime("%Y-%m")
    questions = Question.query.filter_by(survey_id=survey_id, active=True).filter(Question.answer_type.in_(('rating', 'nps'))).all()
    for question in questions:
        q = (db.session.query(Answer.rating, Response.submitted_at)
            .join(Response, Response.id == Answer.response_id)
            .filter(Answer.question_id == question.id, Response.survey_id == survey_id))
        recent = [int(row.rating) for row in q.filter(Response.submitted_at >= recent_start).all()]
        alert_type, summary = None, ""
        if question.answer_type == "rating":
            low = sum(1 for value in recent if 1 <= value <= low_score_max)
            if low >= low_score_threshold:
                alert_type = "low_scores"
                summary = "%s avaliações baixas (nota 1 a %s) nos últimos 30 dias em %s." % (low, low_score_max, question.sector)
        else:
            prior = [int(row.rating) for row in q.filter(Response.submitted_at >= prior_start, Response.submitted_at < recent_start).all()]
            if len(recent) >= minimum_sample and len(prior) >= minimum_sample:
                current_nps = round((sum(value >= 9 for value in recent) - sum(value <= 6 for value in recent)) / len(recent) * 100)
                prior_nps = round((sum(value >= 9 for value in prior) - sum(value <= 6 for value in prior)) / len(prior) * 100)
                if prior_nps - current_nps >= nps_drop_points:
                    alert_type = "nps_decline"
                    summary = "NPS caiu %s pontos nos últimos 30 dias em %s (%s → %s)." % (prior_nps - current_nps, question.sector, prior_nps, current_nps)
        if alert_type:
            key = "%s:%s:%s:%s" % (survey_id, question.id, alert_type, period_key)
            if not SurveyAlert.query.filter_by(alert_key=key).first():
                db.session.add(SurveyAlert(alert_key=key, survey_id=survey_id, question_id=question.id,
                    sector=question.sector, alert_type=alert_type, period_key=period_key, summary=summary))

def comparison_metric_map(survey_id, accessible, sector, start_at=None, end_at=None):
    if not survey_id or not accessible:
        return {}
    query = Question.query.filter_by(survey_id=survey_id, active=True).filter(Question.sector.in_(accessible)).filter(Question.answer_type.in_(('rating', 'nps')))
    if sector in accessible:
        query = query.filter(Question.sector == sector)
    result = {}
    for question in query.all():
        answers_query = (db.session.query(Answer.rating).join(Response, Response.id == Answer.response_id)
            .filter(Answer.question_id == question.id, Response.survey_id == survey_id))
        if start_at:
            answers_query = answers_query.filter(Response.submitted_at >= start_at)
        if end_at:
            answers_query = answers_query.filter(Response.submitted_at < end_at)
        values = [int(row[0]) for row in answers_query.all() if row[0] is not None]
        if question.answer_type == "rating":
            values = [value for value in values if 1 <= value <= 5]
            metric = round(sum(values) / len(values), 2) if len(values) >= 3 else None
        else:
            values = [value for value in values if 0 <= value <= 10]
            metric = round((sum(value >= 9 for value in values) - sum(value <= 6 for value in values)) / len(values) * 100) if len(values) >= 3 else None
        key = (question.sector, clean_name(question.text), question.answer_type)
        result[key] = {"question": question, "metric": metric, "count": len(values)}
    return result

def dashboard_comparisons(survey_id, compare_survey_id, accessible, sector):
    if not survey_id or not accessible:
        return {"period": [], "survey": [], "period_label": ""}
    local_now = now().astimezone(RECIFE_TZ)
    current_start_local = local_now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    if local_now.month == 1:
        prior_year, prior_month = local_now.year - 1, 12
    else:
        prior_year, prior_month = local_now.year, local_now.month - 1
    prior_day = min(local_now.day, calendar.monthrange(prior_year, prior_month)[1])
    prior_start_local = current_start_local.replace(year=prior_year, month=prior_month)
    prior_end_local = prior_start_local.replace(day=prior_day, hour=local_now.hour, minute=local_now.minute, second=local_now.second, microsecond=local_now.microsecond)
    current = comparison_metric_map(survey_id, accessible, sector, current_start_local.astimezone(timezone.utc), now())
    prior = comparison_metric_map(survey_id, accessible, sector, prior_start_local.astimezone(timezone.utc), prior_end_local.astimezone(timezone.utc))
    period_rows = []
    for key, value in current.items():
        other = prior.get(key)
        if other and value["metric"] is not None and other["metric"] is not None:
            diff = round(value["metric"] - other["metric"], 2)
            period_rows.append({"question": value["question"], "current": value["metric"], "previous": other["metric"], "difference": diff,
                "direction": "melhorou" if diff > 0 else "piorou" if diff < 0 else "estável", "kind": value["question"].answer_type})
    survey_rows = []
    if compare_survey_id and compare_survey_id != survey_id:
        left = comparison_metric_map(survey_id, accessible, sector)
        right = comparison_metric_map(compare_survey_id, accessible, sector)
        for key, value in left.items():
            other = right.get(key)
            if other and value["metric"] is not None and other["metric"] is not None:
                diff = round(value["metric"] - other["metric"], 2)
                survey_rows.append({"question": value["question"], "current": value["metric"], "previous": other["metric"], "difference": diff,
                    "direction": "melhorou" if diff > 0 else "piorou" if diff < 0 else "estável", "kind": value["question"].answer_type})
    label = "%s/%s até %s versus %s/%s até %s" % (current_start_local.month, current_start_local.year, local_now.day,
        prior_start_local.month, prior_start_local.year, prior_end_local.day)
    return {"period": period_rows, "survey": survey_rows, "period_label": label}

def dashboard_goal_results(accessible, selected_survey, selected_sector, date_from):
    if date_from:
        try:
            selected_date = datetime.strptime(date_from, "%Y-%m-%d").date()
        except ValueError:
            selected_date = now().astimezone(RECIFE_TZ).date()
    else:
        selected_date = now().astimezone(RECIFE_TZ).date()
    period_key = selected_date.strftime("%Y-%m")
    month_start = selected_date.replace(day=1)
    start_at = datetime.combine(month_start, datetime.min.time(), RECIFE_TZ).astimezone(timezone.utc)
    next_month = (month_start.replace(day=28) + timedelta(days=4)).replace(day=1)
    end_at = datetime.combine(next_month, datetime.min.time(), RECIFE_TZ).astimezone(timezone.utc)
    query = SectorGoal.query.filter_by(period_key=period_key).filter(SectorGoal.sector.in_(accessible))
    if selected_sector in accessible:
        query = query.filter(SectorGoal.sector == selected_sector)
    if selected_survey:
        query = query.filter(db.or_(SectorGoal.survey_id.is_(None), SectorGoal.survey_id == selected_survey))
    goals = query.order_by(SectorGoal.sector, SectorGoal.metric).all() if accessible else []
    results = []
    for goal in goals:
        questions = Question.query.filter_by(sector=goal.sector, active=True,
            answer_type="nps" if goal.metric == "nps" else "rating")
        if goal.survey_id:
            questions = questions.filter_by(survey_id=goal.survey_id)
        elif selected_survey:
            questions = questions.filter_by(survey_id=selected_survey)
        questions = questions.all()
        ratings = (db.session.query(Answer.rating).join(Response, Response.id == Answer.response_id)
            .filter(Answer.question_id.in_([q.id for q in questions]) if questions else db.false())
            .filter(Response.submitted_at >= start_at, Response.submitted_at < end_at).all())
        values = [int(row[0]) for row in ratings if row[0] is not None and (goal.metric == "nps" or int(row[0]) > 0)]
        if len(values) < 3:
            current_value = None
        elif goal.metric == "nps":
            current_value = round((sum(v >= 9 for v in values) - sum(v <= 6 for v in values)) / len(values) * 100)
        else:
            current_value = round(sum(values) / len(values), 2)
        if current_value is None:
            progress = 0
        elif goal.metric == "nps":
            progress = 100 if goal.target <= -100 else round(max(0, min(100, (current_value + 100) / (goal.target + 100) * 100)))
        else:
            progress = 100 if goal.target <= 0 and current_value >= goal.target else round(max(0, min(100, current_value / goal.target * 100))) if goal.target > 0 else 0
        results.append({"goal": goal, "value": current_value, "count": len(values), "progress": progress,
            "met": current_value is not None and current_value >= goal.target})
    return period_key, results

def xlsx_column(index):
    result = ""
    while index:
        index, remainder = divmod(index - 1, 26)
        result = chr(65 + remainder) + result
    return result

def make_xlsx(sheets):
    def xml_text(value):
        value = "" if value is None else str(value)
        value = "".join(ch for ch in value if ch in "\t\n\r" or ord(ch) >= 32)
        return (value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;").replace("'", "&apos;"))
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as book:
        book.writestr("[Content_Types].xml", '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>' + "".join('<Override PartName="/xl/worksheets/sheet%d.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>' % i for i in range(1, len(sheets) + 1)) + '</Types>')
        book.writestr("_rels/.rels", '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>')
        book.writestr("xl/workbook.xml", '<?xml version="1.0" encoding="UTF-8"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>' + "".join('<sheet name="%s" sheetId="%d" r:id="rId%d"/>' % (xml_text(name[:31]), i, i) for i, (name, _) in enumerate(sheets, 1)) + '</sheets></workbook>')
        book.writestr("xl/_rels/workbook.xml.rels", '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' + "".join('<Relationship Id="rId%d" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet%d.xml"/>' % (i, i) for i in range(1, len(sheets) + 1)) + '</Relationships>')
        for sheet_index, (_, rows) in enumerate(sheets, 1):
            row_xml = []
            for row_number, row in enumerate(rows, 1):
                cells = []
                for col_number, value in enumerate(row, 1):
                    reference = "%s%d" % (xlsx_column(col_number), row_number)
                    if isinstance(value, (int, float)) and not isinstance(value, bool):
                        cells.append('<c r="%s"><v>%s</v></c>' % (reference, value))
                    else:
                        cells.append('<c r="%s" t="inlineStr"><is><t xml:space="preserve">%s</t></is></c>' % (reference, xml_text(value)))
                row_xml.append('<row r="%d">%s</row>' % (row_number, "".join(cells)))
            book.writestr("xl/worksheets/sheet%d.xml" % sheet_index, '<?xml version="1.0" encoding="UTF-8"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>' + "".join(row_xml) + '</sheetData></worksheet>')
    output.seek(0)
    return output

@app.route("/admin/followups", methods=["GET", "POST"])
@roles("master")
def participant_followups():
    if request.method == "POST":
        item = db.get_or_404(ParticipantFollowup, request.form.get("followup_id", type=int))
        item.status = "contatado"
        item.contacted_at = now()
        log("participant_followup_contacted", "followup:%s" % item.id)
        db.session.commit()
        flash("Solicitação marcada como contatada.", "success")
        return redirect(url_for("participant_followups"))
    records = ParticipantFollowup.query.order_by(ParticipantFollowup.created_at.desc()).limit(500).all()
    survey_titles = {item.id: item.title for item in Survey.query.all()}
    return render_template("participant_followups.html", records=records, survey_titles=survey_titles)


@app.get("/api/participation")
@login_required
def participation_api():
    accessible = SECTORS if current_user.role in ("master", "auditoria") else ROLE_SECTORS.get(current_user.role, [])
    surveys = Survey.query.filter(Survey.questions.any(Question.sector.in_(accessible))).order_by(Survey.title).all() if accessible else []
    result = []
    for survey in surveys:
        tracked = SurveyInvite.query.filter_by(survey_id=survey.id).filter(
            SurveyInvite.response_token_hash != "", SurveyInvite.reminder_sent_at.isnot(None)).count()
        completed = SurveyInvite.query.filter_by(survey_id=survey.id).filter(
            SurveyInvite.response_token_hash != "", SurveyInvite.responded_at.isnot(None)).count()
        responses = Response.query.filter_by(survey_id=survey.id).count()
        result.append({"id": survey.id, "title": survey.title, "responses": responses, "invited": tracked,
            "completed": completed, "rate": round(completed / tracked * 100, 1) if tracked else 0})
    return jsonify({"surveys": result})


@app.route("/dashboard")
@login_required
def dashboard():
    accessible = SECTORS if current_user.role in ("master", "auditoria") else ROLE_SECTORS.get(current_user.role, [])
    stats, selected_survey, selected_sector, date_from, date_to, trends = dashboard_data(accessible)
    question_details = dashboard_question_details(selected_survey, accessible, selected_sector, date_from, date_to, current_user.role)
    surveys = Survey.query.filter(Survey.questions.any(Question.sector.in_(accessible))).order_by(Survey.title).all() if accessible else []
    survey_ids = {survey.id for survey in surveys}
    if selected_survey not in survey_ids:
        selected_survey = None
        question_details = []
    compare_survey = request.args.get("compare_survey", type=int)
    if compare_survey not in survey_ids or compare_survey == selected_survey:
        compare_survey = None
    for survey in surveys:
        evaluate_survey_alerts(survey.id)
    alerts = (SurveyAlert.query.filter(SurveyAlert.action_plan_id.is_(None), SurveyAlert.sector.in_(accessible))
        .order_by(SurveyAlert.created_at.desc()).limit(50).all()) if accessible else []
    participation = {}
    for survey in surveys:
        tracked = SurveyInvite.query.filter_by(survey_id=survey.id).filter(
            SurveyInvite.response_token_hash != "", SurveyInvite.reminder_sent_at.isnot(None)).count()
        completed = SurveyInvite.query.filter_by(survey_id=survey.id).filter(
            SurveyInvite.response_token_hash != "", SurveyInvite.responded_at.isnot(None)).count()
        participation[survey.id] = {"invited": tracked, "completed": completed,
            "rate": round(completed / tracked * 100, 1) if tracked else 0}
    comparisons = dashboard_comparisons(selected_survey, compare_survey, accessible, selected_sector)
    goals_period, goal_results = dashboard_goal_results(accessible, selected_survey, selected_sector, date_from)
    comment_themes = Counter(theme for detail in question_details for answer in detail["open_answers"] for theme in answer["themes"])
    log("dashboard_view", ",".join(accessible))
    db.session.commit()
    return render_template("dashboard.html", stats=stats,
        surveys=surveys,
        sectors=accessible, selected_survey=selected_survey, selected_sector=selected_sector,
        date_from=date_from, date_to=date_to, trends=trends, question_details=question_details,
        compare_survey=compare_survey, comparisons=comparisons, alerts=alerts,
        participation=participation, comment_themes=comment_themes,
        goal_results=goal_results, goals_period=goals_period,
        survey_titles={item.id: item.title for item in surveys})

@app.route("/admin/goals", methods=["GET", "POST"])
@roles("master")
def manage_goals():
    if request.method == "POST":
        sector = request.form.get("sector", "")
        period_key = request.form.get("period_key", "")
        metric = request.form.get("metric", "")
        survey_id = request.form.get("survey_id", type=int) or None
        try:
            datetime.strptime(period_key + "-01", "%Y-%m-%d")
            target = float(request.form.get("target", ""))
        except (TypeError, ValueError):
            abort(400)
        if sector not in SECTORS or metric not in ("average", "nps") or not (0 <= target <= 5 if metric == "average" else -100 <= target <= 100):
            abort(400)
        if survey_id and not db.session.get(Survey, survey_id):
            abort(400)
        goal = SectorGoal.query.filter_by(survey_id=survey_id, sector=sector, period_key=period_key, metric=metric).first()
        if not goal:
            goal = SectorGoal(survey_id=survey_id, sector=sector, period_key=period_key, metric=metric, target=target)
            db.session.add(goal)
            event = "goal_create"
        else:
            goal.target = target
            event = "goal_update"
        log(event, "goal:%s sector:%s period:%s metric:%s" % (goal.id or "new", sector, period_key, metric))
        db.session.commit()
        flash("Meta salva para o setor e período selecionados.", "success")
        return redirect(url_for("manage_goals"))
    goals = SectorGoal.query.order_by(SectorGoal.period_key.desc(), SectorGoal.sector, SectorGoal.metric).all()
    surveys = Survey.query.order_by(Survey.title).all()
    return render_template("goals.html", goals=goals, surveys=surveys, sectors=SECTORS,
        current_period=now().astimezone(RECIFE_TZ).strftime("%Y-%m"))

@app.post("/admin/goals/<int:goal_id>/delete")
@roles("master")
def delete_goal(goal_id):
    goal = db.get_or_404(SectorGoal, goal_id)
    log("goal_delete", "goal:%s sector:%s period:%s" % (goal.id, goal.sector, goal.period_key))
    db.session.delete(goal)
    db.session.commit()
    flash("Meta removida.", "success")
    return redirect(url_for("manage_goals"))

@app.route("/admin/alerts/settings", methods=["GET", "POST"])
@roles("master")
def configure_alerts():
    settings = db.session.get(AlertSettings, 1)
    if not settings:
        settings = AlertSettings(id=1)
        db.session.add(settings)
        db.session.flush()
    if request.method == "POST":
        try:
            nps_drop = int(request.form.get("nps_drop_points", ""))
            low_threshold = int(request.form.get("low_score_threshold", ""))
            low_max = int(request.form.get("low_score_max", ""))
            minimum_sample = int(request.form.get("minimum_sample", ""))
        except (TypeError, ValueError):
            abort(400)
        if not (1 <= nps_drop <= 100 and 1 <= low_threshold <= 10000 and 1 <= low_max <= 5 and 3 <= minimum_sample <= 10000):
            abort(400)
        settings.nps_drop_points = nps_drop
        settings.low_score_threshold = low_threshold
        settings.low_score_max = low_max
        settings.minimum_sample = minimum_sample
        settings.updated_at = now()
        log("alert_settings_update", "nps_drop:%s low_count:%s low_max:%s minimum_sample:%s" % (nps_drop, low_threshold, low_max, minimum_sample))
        db.session.commit()
        flash("Limites dos alertas atualizados.", "success")
        return redirect(url_for("configure_alerts"))
    return render_template("alert_settings.html", settings=settings)

@app.get("/dashboard/print")
@login_required
def print_dashboard():
    accessible = SECTORS if current_user.role in ("master", "auditoria") else ROLE_SECTORS.get(current_user.role, [])
    stats, _, _, _, _, _ = dashboard_data(accessible)
    layout = request.args.get("format") if request.args.get("format") in ("cards", "bi") else "cards"
    log("dashboard_print", layout)
    db.session.commit()
    return render_template("dashboard_print.html", stats=stats, layout=layout, generated_at=now())

@app.get("/dashboard/export.xlsx")
@login_required
def export_dashboard_xlsx():
    accessible = SECTORS if current_user.role in ("master", "auditoria") else ROLE_SECTORS.get(current_user.role, [])
    surveys = Survey.query.filter(Survey.questions.any(Question.sector.in_(accessible))).order_by(Survey.title).all() if accessible else []
    selected = request.args.get("survey", type=int)
    if selected:
        if selected not in {item.id for item in surveys}:
            abort(403)
        surveys = [item for item in surveys if item.id == selected]
    sector = request.args.get("sector", "")
    if sector not in accessible:
        sector = ""
    date_from, date_to = request.args.get("from", ""), request.args.get("to", "")
    try:
        if date_from:
            datetime.strptime(date_from, "%Y-%m-%d")
        if date_to:
            datetime.strptime(date_to, "%Y-%m-%d")
    except ValueError:
        abort(400)
    indicator_rows = [["Pesquisa", "Setor", "Pergunta", "Tipo", "Indicador", "Valor"]]
    comment_rows = [["Pesquisa", "Setor", "Pergunta", "Comentário", "Data/hora do servidor UTC", "Data/hora do dispositivo", "Fuso do dispositivo"]]
    participation_rows = [["Pesquisa", "Convites rastreáveis enviados", "Respostas recebidas", "Taxa de conclusão"]]
    for survey in surveys:
        details = dashboard_question_details(survey.id, accessible, sector, date_from, date_to, current_user.role)
        for detail in details:
            question = detail["question"]
            label_type = "NPS" if question.answer_type == "nps" else "Avaliação 1–5" if question.answer_type == "rating" else "Aberta" if question.answer_type == "open" else "Múltipla escolha"
            if question.answer_type in ("rating", "nps"):
                if detail["distribution_suppressed"]:
                    indicator_rows.append([survey.title, question.sector, question.text, label_type, "Distribuição", "Oculta: menos de 3 respostas"])
                else:
                    metric_name = "NPS" if question.answer_type == "nps" else "Média / 5"
                    metric_value = detail["nps"] if question.answer_type == "nps" else detail["average"]
                    indicator_rows.append([survey.title, question.sector, question.text, label_type, metric_name, metric_value])
                    for item in detail["distribution"]:
                        indicator_rows.append([survey.title, question.sector, question.text, label_type, "Resposta " + item["label"], item["count"]])
                    if detail.get("not_applicable"):
                        indicator_rows.append([survey.title, question.sector, question.text, label_type, "Não se aplica / Não sei avaliar", detail["not_applicable"]])
            elif question.answer_type in ("single", "multiple"):
                if detail["distribution_suppressed"]:
                    indicator_rows.append([survey.title, question.sector, question.text, label_type, "Distribuição", "Oculta: menos de 3 respostas"])
                else:
                    for item in detail["distribution"]:
                        indicator_rows.append([survey.title, question.sector, question.text, label_type, item["label"], item["count"]])
            elif question.answer_type == "open" and not detail["hidden_text"]:
                for answer in detail["open_answers"]:
                    device_time = answer["device_submitted_at"]
                    comment_rows.append([survey.title, question.sector, question.text, answer["text"],
                        answer["submitted_at"].strftime("%Y-%m-%d %H:%M:%S UTC"),
                        device_time.strftime("%Y-%m-%d %H:%M:%S UTC") if device_time else "Não informado", answer["device_timezone"]])
        tracked = SurveyInvite.query.filter_by(survey_id=survey.id).filter(
            SurveyInvite.response_token_hash != "", SurveyInvite.reminder_sent_at.isnot(None)).count()
        completed = SurveyInvite.query.filter_by(survey_id=survey.id).filter(
            SurveyInvite.response_token_hash != "", SurveyInvite.responded_at.isnot(None)).count()
        participation_rows.append([survey.title, tracked, completed, "%s%%" % round(completed / tracked * 100, 1) if tracked else "—"])
    log("dashboard_export_xlsx", "surveys:%s sector:%s" % (len(surveys), sector or "all"))
    db.session.commit()
    file = make_xlsx([("Indicadores", indicator_rows), ("Comentários", comment_rows), ("Participação", participation_rows)])
    return send_file(file, mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        as_attachment=True, download_name="indicadores_pesquisa.xlsx")

@app.get("/dashboard/export.pdf")
@login_required
def export_dashboard_pdf():
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    from reportlab.graphics.shapes import Drawing
    from reportlab.graphics.charts.barcharts import VerticalBarChart
    from xml.sax.saxutils import escape

    accessible = SECTORS if current_user.role in ("master", "auditoria") else ROLE_SECTORS.get(current_user.role, [])
    surveys = Survey.query.filter(Survey.questions.any(Question.sector.in_(accessible))).order_by(Survey.title).all() if accessible else []
    selected = request.args.get("survey", type=int)
    if selected:
        if selected not in {item.id for item in surveys}:
            abort(403)
        surveys = [item for item in surveys if item.id == selected]
    sector = request.args.get("sector", "")
    if sector not in accessible:
        sector = ""
    date_from, date_to = request.args.get("from", ""), request.args.get("to", "")
    try:
        if date_from:
            datetime.strptime(date_from, "%Y-%m-%d")
        if date_to:
            datetime.strptime(date_to, "%Y-%m-%d")
    except ValueError:
        abort(400)

    output = io.BytesIO()
    doc = SimpleDocTemplate(output, pagesize=landscape(A4), rightMargin=12*mm, leftMargin=12*mm, topMargin=13*mm, bottomMargin=13*mm)
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="SmallCell", parent=styles["BodyText"], fontSize=7.5, leading=9, alignment=TA_LEFT))
    styles.add(ParagraphStyle(name="Subtle", parent=styles["BodyText"], textColor=colors.HexColor("#566273"), fontSize=8))
    story = [Paragraph("Relatório de pesquisas", styles["Title"]),
        Paragraph("Filtros: %s · Setor: %s · Período: %s a %s" % (
            escape(", ".join(item.title for item in surveys) or "Todas as pesquisas acessíveis"),
            escape(sector or "Todos os setores permitidos"), escape(date_from or "início"), escape(date_to or "hoje")), styles["Subtle"]), Spacer(1, 5*mm)]
    for survey_index, survey in enumerate(surveys):
        if survey_index:
            story.append(PageBreak())
        story.append(Paragraph(escape(survey.title), styles["Heading1"]))
        details = dashboard_question_details(survey.id, accessible, sector, date_from, date_to, current_user.role)
        invite_count = SurveyInvite.query.filter_by(survey_id=survey.id).filter(
            SurveyInvite.response_token_hash != "", SurveyInvite.reminder_sent_at.isnot(None)).count()
        completed_count = SurveyInvite.query.filter_by(survey_id=survey.id).filter(
            SurveyInvite.response_token_hash != "", SurveyInvite.responded_at.isnot(None)).count()
        story.append(Paragraph("Participação: %d convites rastreáveis · %d respostas · %s%% de conclusão" % (
            invite_count, completed_count, round(completed_count / invite_count * 100, 1) if invite_count else 0), styles["BodyText"]))
        for detail in details:
            question = detail["question"]
            story.extend([Spacer(1, 3*mm), Paragraph("<b>%s</b> · %s" % (escape(question.sector), escape(question.text)), styles["Heading3"])])
            if question.answer_type in ("rating", "nps", "single", "multiple"):
                if detail["distribution_suppressed"]:
                    story.append(Paragraph("Indicadores ocultos: menos de 3 respostas.", styles["Subtle"]))
                    continue
                metric = ("NPS: %s" % detail["nps"] if question.answer_type == "nps" else
                    "Média: %s / 5" % detail["average"] if question.answer_type == "rating" else "Respostas por opção")
                story.append(Paragraph(escape(metric), styles["BodyText"]))
                distribution = detail["distribution"]
                chart = Drawing(650, 150)
                bars = VerticalBarChart()
                bars.x, bars.y, bars.width, bars.height = 42, 28, 585, 105
                bars.data = [[item["count"] for item in distribution]]
                bars.categoryAxis.categoryNames = [str(item["label"])[:18] for item in distribution]
                bars.categoryAxis.labels.fontSize = 7
                bars.valueAxis.valueMin = 0
                bars.valueAxis.valueMax = max(1, max((item["count"] for item in distribution), default=1))
                bars.valueAxis.valueStep = max(1, bars.valueAxis.valueMax // 5)
                bars.bars[0].fillColor = colors.HexColor("#0b7d79")
                chart.add(bars)
                story.append(chart)
                rows = [[Paragraph("Opção", styles["SmallCell"]), Paragraph("Respostas", styles["SmallCell"])]]
                rows += [[Paragraph(escape(str(item["label"])), styles["SmallCell"]), str(item["count"])] for item in distribution]
                table = Table(rows, colWidths=[160*mm, 28*mm], repeatRows=1)
                table.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,0), colors.HexColor("#eaf3f2")),
                    ("GRID", (0,0), (-1,-1), .25, colors.HexColor("#ccd7d7")), ("VALIGN", (0,0), (-1,-1), "TOP")]))
                story.append(table)
            elif question.answer_type == "open":
                if detail["hidden_text"]:
                    story.append(Paragraph("Comentários ocultos pelas regras de privacidade.", styles["Subtle"]))
                elif detail["open_answers"]:
                    rows = [["Tema(s)", "Comentário"]]
                    rows += [[Paragraph(escape(", ".join(item["themes"])), styles["SmallCell"]),
                        Paragraph(escape(item["text"]), styles["SmallCell"])] for item in detail["open_answers"]]
                    table = Table(rows, colWidths=[45*mm, 220*mm], repeatRows=1)
                    table.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,0), colors.HexColor("#eaf3f2")),
                        ("GRID", (0,0), (-1,-1), .25, colors.HexColor("#ccd7d7")), ("VALIGN", (0,0), (-1,-1), "TOP")]))
                    story.append(table)
                else:
                    story.append(Paragraph("Sem comentários no filtro selecionado.", styles["Subtle"]))
    if not surveys:
        story.append(Paragraph("Nenhuma pesquisa disponível para os filtros e permissões deste perfil.", styles["BodyText"]))
    doc.build(story)
    output.seek(0)
    log("dashboard_export_pdf", "surveys:%s sector:%s" % (len(surveys), sector or "all"))
    db.session.commit()
    return send_file(output, mimetype="application/pdf", as_attachment=True, download_name="indicadores_pesquisa.pdf")

@app.route("/action-plans", methods=["GET", "POST"])
@login_required
def action_plans():
    accessible = SECTORS if current_user.role in ("master", "auditoria") else ROLE_SECTORS.get(current_user.role, [])
    if request.method == "POST" and request.form.get("action") == "review":
        plan = db.get_or_404(ActionPlan, request.form.get("plan_id", type=int))
        if plan.sector not in accessible:
            abort(403)
        plan.reviewed_average = sector_rating_average(plan.survey_id, plan.sector)
        plan.reviewed_at = now()
        plan.review_notes = request.form.get("review_notes", "").strip()[:2000]
        log("action_plan_review", "plan:%s" % plan.id)
        db.session.commit()
        flash("Revisão registrada com a média atual do setor.", "success")
        return redirect(url_for("action_plans"))
    if request.method == "POST":
        plan_id = request.form.get("plan_id", type=int)
        plan = db.get_or_404(ActionPlan, plan_id) if plan_id else ActionPlan()
        sector = request.form.get("sector", "")
        if sector not in accessible or (plan_id and plan.sector not in accessible):
            abort(403)
        plan.survey_id = request.form.get("survey_id", type=int)
        if not db.session.get(Survey, plan.survey_id):
            abort(400)
        selected_survey = db.session.get(Survey, plan.survey_id)
        survey_has_questions = Question.query.filter_by(survey_id=selected_survey.id).first() is not None
        sector_has_questions = Question.query.filter(Question.survey_id == selected_survey.id, Question.sector == sector).first() is not None
        if survey_has_questions and not sector_has_questions:
            abort(403)
        if not survey_has_questions and current_user.role != "master":
            abort(403)
        plan.sector = sector
        plan.title = request.form.get("title", "").strip()[:200]
        plan.description = request.form.get("description", "").strip()[:2000]
        plan.owner = request.form.get("owner", "").strip()[:120]
        if not plan_id and plan.baseline_average is None:
            plan.baseline_average = sector_rating_average(plan.survey_id, sector)
        plan.priority = request.form.get("priority") if request.form.get("priority") in ("baixa", "media", "alta") else "media"
        plan.status = request.form.get("status") if request.form.get("status") in ("aberto", "andamento", "concluido") else "aberto"
        try:
            due = request.form.get("due_date", "")
            plan.due_date = datetime.strptime(due, "%Y-%m-%d").date() if due else None
        except ValueError:
            abort(400)
        if not plan.title:
            flash("Informe o título do plano de ação.", "error")
        else:
            if not plan_id:
                db.session.add(plan)
            alert_id = request.form.get("alert_id", type=int)
            alert = db.session.get(SurveyAlert, alert_id) if alert_id else None
            if alert_id and not alert:
                abort(403)
            if alert and (alert.action_plan_id is not None or alert.survey_id != plan.survey_id or alert.sector != sector or sector not in accessible):
                abort(403)
            if alert:
                db.session.flush()
                alert.action_plan_id = plan.id
            log("action_plan_save", ("update:" if plan_id else "create:") + str(plan.id or "new"))
            db.session.commit()
            flash("Plano de ação salvo.", "success")
        return redirect(url_for("action_plans"))
    plans = ActionPlan.query.filter(ActionPlan.sector.in_(accessible)).order_by(ActionPlan.due_date, ActionPlan.id.desc()).all() if accessible else []
    surveys = (Survey.query.filter(db.or_(Survey.questions.any(Question.sector.in_(accessible)),
        db.and_(current_user.role == "master", ~Survey.questions.any()))).order_by(Survey.title).all()
               if accessible else [])
    survey_titles = {s.id: s.title for s in surveys}
    alert_id = request.args.get("alert_id", type=int)
    alert = db.session.get(SurveyAlert, alert_id) if alert_id else None
    if alert and (alert.sector not in accessible or alert.action_plan_id is not None):
        alert = None
    return render_template("action_plans.html", plans=plans, surveys=surveys, sectors=accessible,
        survey_titles=survey_titles, alert=alert)

@app.route("/admin/surveys", methods=["GET", "POST"])
@login_required
def manage_surveys():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        slug = re.sub(r"[^a-z0-9-]", "-", request.form.get("slug", "").lower()).strip("-")
        if not title or not slug or Survey.query.filter_by(slug=slug).first():
            flash("Informe título e slug exclusivo.", "error")
        else:
            s = Survey(title=title[:200], slug=slug[:120], description=request.form.get("description", "")[:2000],
                       target=request.form.get("target") if request.form.get("target") in ("lojista", "publico") else "lojista",
                       identity_type=("cnpj" if request.form.get("target") == "lojista" else "none"),
                       whatsapp_mode="none", automatic_reminders=False, reminder_delay_days=3)
            db.session.add(s)
            log("survey_create", slug)
            db.session.commit()
            return redirect(url_for("edit_survey", sid=s.id))
    surveys = Survey.query.order_by(Survey.id.desc()).all()
    response_counts = {survey_id: count for survey_id, count in
        db.session.query(Response.survey_id, db.func.count(Response.id)).group_by(Response.survey_id).all()}
    return render_template("surveys.html", surveys=surveys, response_counts=response_counts)

@app.post("/admin/surveys/<int:sid>/delete")
@roles("master")
def delete_survey(sid):
    survey = db.get_or_404(Survey, sid)
    registered_identity = RespondentIdentity.query.filter(
        RespondentIdentity.survey_id == sid,
        db.or_(
            RespondentIdentity.document_type.in_(("cpf", "cnpj")),
            db.and_(RespondentIdentity.document_number.isnot(None), RespondentIdentity.document_number != ""),
            db.and_(RespondentIdentity.eligibility_cnpj.isnot(None), RespondentIdentity.eligibility_cnpj != "")
        )
    ).first()
    legacy_document = Response.query.filter(
        Response.survey_id == sid,
        db.or_(
            db.and_(Response.cnpj.isnot(None), Response.cnpj != ""),
            Response.merchant_id.isnot(None)
        )
    ).first()
    if registered_identity or legacy_document:
        flash("A pesquisa não pode ser excluída: há CPF ou CNPJ registrado.", "error")
        return redirect(url_for("manage_surveys"))
    question_ids = [q.id for q in survey.questions]
    response_ids = [r.id for r in Response.query.filter_by(survey_id=sid).all()]
    if question_ids:
        Answer.query.filter(Answer.question_id.in_(question_ids)).delete(synchronize_session=False)
    if response_ids:
        Answer.query.filter(Answer.response_id.in_(response_ids)).delete(synchronize_session=False)
    Response.query.filter_by(survey_id=sid).delete(synchronize_session=False)
    RespondentIdentity.query.filter_by(survey_id=sid).delete(synchronize_session=False)
    SurveyAlert.query.filter_by(survey_id=sid).delete(synchronize_session=False)
    ActionPlan.query.filter_by(survey_id=sid).delete(synchronize_session=False)
    SurveyInvite.query.filter_by(survey_id=sid).delete(synchronize_session=False)
    log("survey_delete", "survey:" + str(sid))
    db.session.delete(survey)
    db.session.commit()
    flash("Pesquisa e resultados excluídos. Nenhum CPF ou CNPJ estava registrado.", "success")
    return redirect(url_for("manage_surveys"))

@app.post("/admin/surveys/<int:sid>/clear-responses")
@roles("master")
def clear_survey_responses(sid):
    survey = db.get_or_404(Survey, sid)
    response_ids = [row[0] for row in db.session.query(Response.id).filter_by(survey_id=sid).all()]
    answer_count = Answer.query.filter(Answer.response_id.in_(response_ids)).count() if response_ids else 0
    response_count = len(response_ids)
    # Remove respostas e identificações armazenadas separadamente desta pesquisa;
    # perguntas, pesquisa, convites e planos de ação permanecem intactos.
    if response_ids:
        Answer.query.filter(Answer.response_id.in_(response_ids)).delete(synchronize_session=False)
    Response.query.filter_by(survey_id=sid).delete(synchronize_session=False)
    RespondentIdentity.query.filter_by(survey_id=sid).delete(synchronize_session=False)
    SurveyInvite.query.filter_by(survey_id=sid).update({"responded_at": None}, synchronize_session=False)
    SurveyAlert.query.filter_by(survey_id=sid).delete(synchronize_session=False)
    log("survey_responses_cleared", "survey:%s responses:%s answers:%s" % (sid, response_count, answer_count))
    db.session.commit()
    flash("Respostas e identificações desta pesquisa removidas. A pesquisa e as perguntas foram preservadas.", "success")
    return redirect(url_for("edit_survey", sid=sid))

def csv_export_value(value):
    value = "" if value is None else str(value)
    if value.startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'" + value
    return value

def csv_import_value(value):
    value = (value or "").strip()
    if len(value) > 1 and value[0] == "'" and value[1] in ("=", "+", "-", "@", "\t", "\r"):
        return value[1:]
    return value

def questions_csv_response(filename, rows):
    output = io.StringIO(newline="")
    writer = csv.writer(output, delimiter=";", lineterminator="\r\n")
    writer.writerow(["setor", "enunciado", "tipo_resposta", "opcoes", "aviso", "obrigatoria"])
    for row in rows:
        writer.writerow([csv_export_value(value) for value in row])
    data = ("\ufeff" + output.getvalue()).encode("utf-8")
    return send_file(io.BytesIO(data), mimetype="text/csv; charset=utf-8", as_attachment=True, download_name=filename)

@app.get("/admin/questions/model.csv")
@login_required
def questions_csv_model():
    return questions_csv_response("modelo_perguntas_pesquisa.csv", [])

def survey_editor(view):
    """Restringe as rotas de edição depois da primeira resposta ao Master."""
    @wraps(view)
    def wrapped(sid, *args, **kwargs):
        survey = db.get_or_404(Survey, sid)
        if getattr(current_user, "role", None) != "master" and Response.query.filter_by(survey_id=sid).first():
            flash("Esta pesquisa já recebeu resposta. Somente o Master pode editá-la.", "info")
            return redirect(url_for("public_survey", slug=survey.slug))
        return view(sid, *args, **kwargs)
    return wrapped


@app.get("/admin/surveys/<int:sid>/questions.csv")
@login_required
@survey_editor
def export_survey_questions(sid):
    survey = db.get_or_404(Survey, sid)
    rows = [
        (q.sector, q.text, q.answer_type, "|".join(q.choice_options), q.notice or "", "nao" if q.optional else "sim")
        for q in Question.query.filter_by(survey_id=sid).order_by(Question.position).all()
    ]
    return questions_csv_response("perguntas_" + survey.slug + ".csv", rows)

@app.post("/admin/surveys/<int:sid>/questions/import")
@login_required
@survey_editor
def import_survey_questions(sid):
    survey = db.get_or_404(Survey, sid)
    uploaded = request.files.get("file")
    if not uploaded or not uploaded.filename:
        flash("Selecione um arquivo CSV.", "error")
        return redirect(url_for("edit_survey", sid=sid))
    raw = uploaded.read(2 * 1024 * 1024 + 1)
    if len(raw) > 2 * 1024 * 1024:
        flash("O arquivo excede o limite de 2 MB.", "error")
        return redirect(url_for("edit_survey", sid=sid))
    try:
        content = raw.decode("utf-8-sig")
        reader = csv.DictReader(io.StringIO(content, newline=""), delimiter=";")
        required = {"setor", "enunciado", "tipo_resposta", "opcoes", "aviso"}
        headers = set(reader.fieldnames or [])
        if not required.issubset(headers):
            raise ValueError("Cabeçalhos inválidos. Baixe e use o modelo CSV disponibilizado.")
        prepared, errors = [], []
        aliases = {"rating": "rating", "nps": "nps", "aberta": "open", "open": "open", "multipla_escolha": "single", "single": "single", "multipla_escolha_varias": "multiple", "multiple": "multiple"}
        for row_number, row in enumerate(reader, start=2):
            if not any((value or "").strip() for value in row.values() if value is not None):
                continue
            if len(prepared) >= 500:
                errors.append("O limite é de 500 perguntas por arquivo.")
                break
            sector = csv_import_value(row.get("setor"))
            statement = csv_import_value(row.get("enunciado"))
            raw_type = csv_import_value(row.get("tipo_resposta")).casefold()
            answer_type = aliases.get(raw_type)
            notice = csv_import_value(row.get("aviso"))
            options_raw = csv_import_value(row.get("opcoes"))
            choices = parse_choices(options_raw.replace("|", "\n")) if answer_type in ("single", "multiple") else []
            issues = []
            if sector not in SECTORS:
                issues.append("setor inválido")
            if not statement or len(statement) > 1000:
                issues.append("enunciado obrigatório com até 1.000 caracteres")
            if not answer_type:
                issues.append("tipo_resposta inválido")
            if len(notice) > 500:
                issues.append("aviso excede 500 caracteres")
            if answer_type in ("single", "multiple") and choices is None:
                issues.append("opcoes deve ter 2 a 20 opções exclusivas separadas por |")
            if issues:
                errors.append("Linha " + str(row_number) + ": " + "; ".join(issues))
            else:
                required_flag = (row.get("obrigatoria") or "sim").strip().casefold()
                if required_flag not in ("sim", "nao", "true", "false", "1", "0"):
                    errors.append("Linha " + str(row_number) + ": obrigatoria deve ser sim ou nao")
                else:
                    prepared.append((sector, statement, answer_type, choices, notice, required_flag not in ("nao", "false", "0")))
        if errors:
            flash("CSV não importado: " + " | ".join(errors[:10]), "error")
        elif not prepared:
            flash("O CSV não contém perguntas para importar.", "error")
        else:
            position = len(survey.questions)
            for offset, item in enumerate(prepared, start=1):
                sector, statement, answer_type, choices, notice, required = item
                db.session.add(Question(survey_id=sid, sector=sector, text=statement, position=position + offset, active=True, answer_type=answer_type, notice=notice, choices=json.dumps(choices, ensure_ascii=False), optional=not required))
            log("questions_csv_import", str(sid) + ":" + str(len(prepared)))
            db.session.commit()
            flash(str(len(prepared)) + " pergunta(s) importada(s) e salva(s). As perguntas existentes foram mantidas.", "success")
    except (UnicodeDecodeError, csv.Error, ValueError) as exc:
        db.session.rollback()
        flash("Não foi possível importar o CSV: " + str(exc)[:300], "error")
    return redirect(url_for("edit_survey", sid=sid))

def survey_publish_review(survey):
    questions = Question.query.filter_by(survey_id=survey.id, active=True).order_by(Question.position).all()
    warnings = []
    normalized = {}
    for question in questions:
        key = re.sub(r"[^a-z0-9]+", " ", unicodedata.normalize("NFKD", question.text.lower()).encode("ascii", "ignore").decode()).strip()
        normalized.setdefault(key, []).append(question)
    for group in (group for group in normalized.values() if len(group) > 1):
        warnings.append("Pergunta repetida: " + group[0].text[:120])
    vague_terms = ("outros", "etc", "bom?", "ruim?", "avalie", "o que acha")
    for question in questions:
        text_value = question.text.strip()
        if len(text_value.split()) < 3 or any(term in text_value.lower() for term in vague_terms):
            warnings.append("Revise se esta pergunta está clara: " + text_value[:120])
    required = [question for question in questions if not question.optional]
    if len(required) >= 10 and required and len(required) / max(len(questions), 1) >= 0.8:
        warnings.append("A pesquisa tem muitas perguntas obrigatórias; considere marcar algumas como opcionais.")
    if not questions:
        warnings.insert(0, "Adicione ao menos uma pergunta ativa antes de publicar.")
    return warnings


def sector_rating_average(survey_id, sector):
    value = (db.session.query(db.func.avg(Answer.rating))
        .join(Question, Answer.question_id == Question.id)
        .filter(Question.survey_id == survey_id, Question.sector == sector,
            Question.answer_type == "rating", Answer.rating > 0).scalar())
    return round(float(value), 2) if value is not None else None


@app.route("/admin/surveys/<int:sid>", methods=["GET", "POST"])
@login_required
@survey_editor
def edit_survey(sid):
    survey = db.get_or_404(Survey, sid)
    if request.method == "POST":
        kind = request.form.get("kind")
        if kind == "settings":
            try:
                starts_at = parse_local_datetime(request.form.get("starts_at"))
                ends_at = parse_local_datetime(request.form.get("ends_at"))
                target = request.form.get("target") if request.form.get("target") in ("lojista", "publico") else survey.target
                identity_type = request.form.get("identity_type") if request.form.get("identity_type") in ("none", "cpf", "cnpj") else survey.identity_type
                whatsapp_mode = request.form.get("whatsapp_mode") if request.form.get("whatsapp_mode") in ("none", "optional", "required") else survey.whatsapp_mode
                response_limit = request.form.get("response_limit", "none")
                reminder_delay_days = int(request.form.get("reminder_delay_days", "3"))
                automatic_reminders = request.form.get("automatic_reminders") == "on"
                followup_enabled = request.form.get("followup_enabled") == "on"
                if not 1 <= reminder_delay_days <= 30:
                    raise ValueError("Escolha o prazo de lembrete entre 1 e 30 dias.")
                if starts_at and ends_at and starts_at >= ends_at:
                    raise ValueError("A data de encerramento precisa ser posterior à data de início.")
                if response_limit not in ("none", "document", "merchant"):
                    raise ValueError("Escolha um limite de respostas válido.")
                if response_limit == "document" and identity_type not in ("cpf", "cnpj"):
                    raise ValueError("Para limitar por documento, configure a pesquisa para solicitar CPF ou CNPJ.")
                if response_limit == "merchant" and target != "lojista":
                    raise ValueError("O limite por lojista só pode ser usado em pesquisas destinadas a lojistas.")
            except ValueError as exc:
                flash(str(exc) or "Informe as datas no formato correto.", "error")
            else:
                before = {
                    "title": survey.title, "description": survey.description or "", "target": survey.target,
                    "active": survey.active, "identity_type": survey.identity_type, "whatsapp_mode": survey.whatsapp_mode, "followup_enabled": survey.followup_enabled, "response_limit": survey.response_limit,
                    "automatic_reminders": survey.automatic_reminders, "reminder_delay_days": survey.reminder_delay_days,
                    "shuffle_questions": survey.shuffle_questions, "starts_at": survey.starts_at, "ends_at": survey.ends_at,
                }
                survey.title = request.form.get("title", survey.title)[:200]
                survey.description = request.form.get("description", "")[:2000]
                survey.target = target
                requested_active = request.form.get("save_draft") != "yes" and request.form.get("active") == "on"
                if requested_active and not Question.query.filter_by(survey_id=sid, active=True).first():
                    survey.active = False
                    flash("A pesquisa precisa ter ao menos uma pergunta ativa antes de publicar.", "error")
                else:
                    survey.active = requested_active
                    if requested_active:
                        for warning in survey_publish_review(survey):
                            flash(warning, "warning")
                survey.identity_type = identity_type
                survey.whatsapp_mode = whatsapp_mode
                survey.followup_enabled = followup_enabled
                survey.response_limit = response_limit
                survey.automatic_reminders = automatic_reminders
                survey.reminder_delay_days = reminder_delay_days
                survey.shuffle_questions = request.form.get("shuffle_questions") == "on"
                survey.starts_at, survey.ends_at = starts_at, ends_at
                changed = [field for field, old_value in before.items() if old_value != getattr(survey, field)]
                log("survey_update", "survey:%s changed_fields:%s" % (sid, ",".join(changed) or "none"))
                if request.form.get("save_draft") == "yes":
                    flash("Rascunho salvo. Ele continuará fechado para respostas.", "success")
        elif kind == "question":
            sector = request.form.get("sector")
            text = request.form.get("text", "").strip()
            answer_type = request.form.get("answer_type") if request.form.get("answer_type") in ("rating", "nps", "open", "single", "multiple") else "rating"
            notice = request.form.get("notice", "").strip()[:500]
            choices = parse_choices(request.form.get("choices", "")) if answer_type in ("single", "multiple") else []
            branch_question_id = request.form.get("branch_question_id", type=int)
            branch_parent = db.session.get(Question, branch_question_id) if branch_question_id else None
            branch_value = request.form.get("branch_value", "")[:255]
            if branch_parent and (branch_parent.survey_id != sid or branch_parent.position >= len(survey.questions) + 1 or branch_parent.answer_type not in ("rating", "nps", "single")):
                branch_parent = None
            if not branch_value:
                branch_parent = None
            invalid_branch = bool(branch_parent and not branch_value_valid(branch_parent, branch_value))
            if invalid_branch:
                flash("Escolha uma resposta válida para a condição da pergunta.", "error")
            elif answer_type in ("single", "multiple") and choices is None:
                flash("Informe de 2 a 20 opções exclusivas, uma por linha, com até 200 caracteres cada.", "error")
            elif sector in SECTORS and text:
                question = Question(survey_id=sid, sector=sector, text=text[:1000], position=len(survey.questions)+1, answer_type=answer_type, notice=notice, choices=json.dumps(choices, ensure_ascii=False), branch_question_id=branch_parent.id if branch_parent else None, branch_value=branch_value if branch_parent else "", optional=request.form.get("optional") == "on", allow_na=request.form.get("allow_na") == "on")
                db.session.add(question)
                db.session.flush()
                log("question_create", "survey:%s question:%s fields:sector,text,type,optional,notice,choices,branch" % (sid, question.id))
                flash("Pergunta adicionada e salva automaticamente.", "success")
        elif kind == "move_question":
            q = db.get_or_404(Question, int(request.form.get("question_id", 0)))
            if q.survey_id != sid:
                abort(403)
            ordered = list(survey.questions)
            index = ordered.index(q)
            target_index = index - 1 if request.form.get("direction") == "up" else index + 1
            if 0 <= target_index < len(ordered):
                other = ordered[target_index]
                q.position, other.position = other.position, q.position
                log("question_reorder", str(sid))
        elif kind == "edit_question":
            q = db.get_or_404(Question, int(request.form.get("question_id", 0)))
            if q.survey_id != sid:
                abort(403)
            if request.form.get("delete") == "yes":
                if Answer.query.filter_by(question_id=q.id).first():
                    q.active = False
                else:
                    db.session.delete(q)
                log("question_remove", "survey:%s question:%s" % (sid, q.id))
            else:
                before = {"text": q.text, "active": q.active, "optional": q.optional, "allow_na": q.allow_na, "notice": q.notice or "",
                    "answer_type": q.answer_type, "choices": q.choices, "branch_question_id": q.branch_question_id,
                    "branch_value": q.branch_value}
                q.text = request.form.get("text", q.text)[:1000]
                q.active = request.form.get("active") == "on"
                q.optional = request.form.get("optional") == "on"
                q.allow_na = request.form.get("allow_na") == "on"
                q.notice = request.form.get("notice", "").strip()[:500]
                if request.form.get("answer_type") in ("rating", "nps", "open", "single", "multiple"):
                    new_type = request.form.get("answer_type")
                    has_answers = Answer.query.filter_by(question_id=q.id).first() is not None
                    new_choices = parse_choices(request.form.get("choices", "")) if new_type in ("single", "multiple") else []
                    choices_changed = new_choices is None or new_choices != q.choice_options
                    if new_type in ("single", "multiple") and new_choices is None:
                        flash("Informe de 2 a 20 opções exclusivas, uma por linha, com até 200 caracteres cada.", "error")
                    elif has_answers and (new_type != q.answer_type or choices_changed):
                        flash("O tipo e as opções não podem ser alterados porque esta pergunta já recebeu respostas.", "error")
                    else:
                        q.answer_type = new_type
                        q.choices = json.dumps(new_choices, ensure_ascii=False)
                parent_id = request.form.get("branch_question_id", type=int)
                parent = db.session.get(Question, parent_id) if parent_id else None
                branch_value = request.form.get("branch_value", "")[:255]
                if parent and parent.survey_id == sid and parent.id != q.id and parent.position < q.position and parent.answer_type in ("rating", "nps", "single") and branch_value:
                    if branch_value_valid(parent, branch_value):
                        q.branch_question_id, q.branch_value = parent.id, branch_value
                    else:
                        flash("Escolha uma resposta válida para a condição da pergunta.", "error")
                else:
                    q.branch_question_id, q.branch_value = None, ""
                changed = [field for field, old_value in before.items() if old_value != getattr(q, field)]
                log("question_update", "survey:%s question:%s changed_fields:%s" % (sid, q.id, ",".join(changed) or "none"))
        db.session.commit()
        return redirect(url_for("edit_survey", sid=sid))
    invite_total = SurveyInvite.query.filter_by(survey_id=sid).count()
    invite_pending = SurveyInvite.query.filter_by(survey_id=sid, reminder_sent_at=None).count()
    response_count = Response.query.filter_by(survey_id=sid).count()
    tracked_invites = SurveyInvite.query.filter_by(survey_id=sid).filter(SurveyInvite.response_token_hash != "", SurveyInvite.reminder_sent_at.isnot(None)).count()
    tracked_responses = SurveyInvite.query.filter_by(survey_id=sid).filter(SurveyInvite.response_token_hash != "", SurveyInvite.responded_at.isnot(None)).count()
    return render_template("edit_survey.html", survey=survey, invite_total=invite_total,
        invite_pending=invite_pending, response_count=response_count,
        tracked_invites=tracked_invites, tracked_responses=tracked_responses,
        participation_rate=round(tracked_responses / tracked_invites * 100, 1) if tracked_invites else 0,
        starts_at_input=local_datetime_input(survey.starts_at), ends_at_input=local_datetime_input(survey.ends_at),
        publish_review=survey_publish_review(survey))

@app.get("/admin/surveys/<int:sid>/qrcode.png")
@login_required
@survey_editor
def survey_qrcode(sid):
    survey = db.get_or_404(Survey, sid)
    import qrcode
    image = qrcode.make(url_for("public_survey", slug=survey.slug, _external=True))
    output = io.BytesIO()
    image.save(output, format="PNG")
    output.seek(0)
    return send_file(output, mimetype="image/png", download_name="qr_" + survey.slug + ".png")

@app.post("/admin/surveys/<int:sid>/invites/import")
@roles("master")
def import_survey_invites(sid):
    survey = db.get_or_404(Survey, sid)
    uploaded = request.files.get("file")
    if not uploaded:
        flash("Selecione um CSV com uma coluna email.", "error")
        return redirect(url_for("edit_survey", sid=sid))
    raw = uploaded.read(2 * 1024 * 1024 + 1)
    try:
        if len(raw) > 2 * 1024 * 1024:
            raise ValueError("O arquivo excede 2 MB.")
        reader = csv.DictReader(io.StringIO(raw.decode("utf-8-sig"), newline=""), delimiter=";")
        if not reader.fieldnames or "email" not in [h.strip().lower() for h in reader.fieldnames]:
            raise ValueError("Use cabeçalho email e separador ponto e vírgula.")
        column = reader.fieldnames[[h.strip().lower() for h in reader.fieldnames].index("email")]
        emails = []
        for row in reader:
            email = (row.get(column) or "").strip().lower()
            if email and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
                raise ValueError("Há endereço de e-mail inválido; nenhum registro foi importado.")
            if email:
                emails.append(email[:255])
            if len(emails) > 1000:
                raise ValueError("O limite é de 1.000 endereços por arquivo.")
        for email in set(emails):
            exists = SurveyInvite.query.filter_by(survey_id=sid, email=email).first()
            if not exists:
                db.session.add(SurveyInvite(survey_id=sid, email=email))
        log("survey_invites_import", str(sid) + ":" + str(len(set(emails))))
        db.session.commit()
        flash(str(len(set(emails))) + " destinatário(s) processado(s). Endereços ficam separados das respostas.", "success")
    except (UnicodeDecodeError, csv.Error, ValueError) as exc:
        db.session.rollback()
        flash("CSV não importado: " + str(exc)[:250], "error")
    return redirect(url_for("edit_survey", sid=sid))

@app.get("/admin/invites/model.csv")
@roles("master")
def survey_invites_csv_model():
    output = io.BytesIO("\ufeffemail\r\n".encode("utf-8"))
    return send_file(output, mimetype="text/csv; charset=utf-8", as_attachment=True, download_name="modelo_destinatarios.csv")

@app.post("/admin/surveys/<int:sid>/invites/remind")
@roles("master")
@limiter.limit("2 per hour")
def remind_survey_invites(sid):
    survey = db.get_or_404(Survey, sid)
    if not survey.active:
        flash("Publique a pesquisa antes de enviar lembretes.", "error")
        return redirect(url_for("edit_survey", sid=sid))
    settings = effective_smtp_settings()
    if not settings["host"]:
        flash("Configure o SMTP antes de enviar lembretes.", "error")
        return redirect(url_for("edit_survey", sid=sid))
    pending = SurveyInvite.query.filter_by(survey_id=sid, reminder_sent_at=None, responded_at=None).limit(1000).all()
    sent = 0
    try:
        with smtplib.SMTP(settings["host"], int(settings["port"]), timeout=12) as smtp:
            if settings["tls"]:
                smtp.starttls()
            if settings["username"]:
                smtp.login(settings["username"], settings["password"])
            for invite in pending:
                token = secrets.token_urlsafe(32)
                invite.response_token_hash = hashlib.sha256(token.encode()).hexdigest()
                msg = EmailMessage()
                msg["Subject"] = "Lembrete: pesquisa de satisfação — " + survey.title
                msg["From"] = settings["from_address"] or "pesquisa@example.invalid"
                msg["To"] = invite.email
                msg.set_content("A pesquisa de satisfação está aberta. Responda pelo link individual: " + url_for("public_survey", slug=survey.slug, invite=token, _external=True) + "\\n\\nOs dados de identificação não são vinculados às respostas individuais. O sistema registra apenas se este convite recebeu resposta, sem associar o e-mail às respostas.")
                smtp.send_message(msg)
                invite.reminder_sent_at = now()
                sent += 1
        log("survey_reminders_sent", str(sid) + ":" + str(sent))
        db.session.commit()
        flash(str(sent) + " lembrete(s) enviado(s).", "success")
    except Exception:
        db.session.commit()
        record_system_incident("smtp", "Falha no envio de lembretes manuais.")
        flash(str(sent) + " lembrete(s) enviado(s); houve falha no restante. Os pendentes podem ser reenviados.", "error")
    return redirect(url_for("edit_survey", sid=sid))

@app.post("/admin/surveys/<int:sid>/reorder")
@login_required
@survey_editor
def reorder_survey_questions(sid):
    survey = db.get_or_404(Survey, sid)
    payload = request.get_json(silent=True) or {}
    order = payload.get("order")
    current_ids = [q.id for q in survey.questions]
    if (not isinstance(order, list) or len(order) != len(current_ids)
            or any(type(item) is not int for item in order)
            or set(order) != set(current_ids)):
        abort(400)
    questions_by_id = {q.id: q for q in survey.questions}
    positions = {question_id: index for index, question_id in enumerate(order, start=1)}
    for question in survey.questions:
        if question.branch_question_id and positions.get(question.branch_question_id, 0) >= positions.get(question.id, 0):
            return jsonify(ok=False, error="A pergunta condicionada precisa ficar depois da pergunta que controla sua exibição."), 400
    for position, question_id in enumerate(order, start=1):
        questions_by_id[question_id].position = position
    log("question_reorder", str(sid))
    db.session.commit()
    return jsonify(ok=True)

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
    first_access_url = None
    if request.method == "POST":
        username, role = request.form.get("username", "").strip(), request.form.get("role")
        if role not in ROLES or not username or User.query.filter_by(username=username).first():
            flash("Informe um usuário exclusivo e um perfil válido.", "error")
        else:
            user = User(username=username[:90], password_hash=generate_password_hash(secrets.token_urlsafe(32)), role=role)
            db.session.add(user)
            db.session.flush()
            token = secrets.token_urlsafe(32)
            db.session.add(FirstAccessToken(user_id=user.id, token_hash=hashlib.sha256(token.encode()).hexdigest(), expires_at=now() + timedelta(hours=24)))
            log("user_create", username + ":" + role)
            db.session.commit()
            base_url = os.environ.get("PUBLIC_BASE_URL", "https://nps.shoppingcarpina.com.br").rstrip("/")
            first_access_url = base_url + url_for("first_access", token=token)
            flash("Usuário cadastrado. Copie o link de primeiro acesso exibido; ele expira em 24 horas.", "success")
    return render_template("users.html", users=User.query.order_by(User.username).all(), roles=ROLES, first_access_url=first_access_url)

@app.route("/first-access/<token>", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def first_access(token):
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    record = FirstAccessToken.query.filter_by(token_hash=token_hash).first()
    valid = bool(record and record.used_at is None and record.expires_at > now() and record.user and record.user.active)
    if not valid:
        return render_template("first_access.html", invalid=True), 410
    if request.method == "POST":
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        if len(password) < 12:
            flash("A senha precisa ter pelo menos 12 caracteres.", "error")
        elif password != confirm:
            flash("As senhas não conferem.", "error")
        else:
            record.user.password_hash = generate_password_hash(password)
            record.used_at = now()
            db.session.commit()
            flash("Senha cadastrada. Agora você pode entrar.", "success")
            return redirect(url_for("login"))
    return render_template("first_access.html", invalid=False)

@app.post("/admin/users/<int:uid>/edit")
@roles("master")
def edit_user(uid):
    user = db.get_or_404(User, uid)
    username = request.form.get("username", "").strip()
    role = request.form.get("role", "")
    password = request.form.get("password", "")
    duplicate = User.query.filter(User.username == username, User.id != uid).first() if username else None
    if not username or len(username) > 90 or duplicate or role not in ROLES:
        flash("Informe um usuário exclusivo de até 90 caracteres e um perfil válido.", "error")
        return redirect(url_for("users"))
    if password and len(password) < 12:
        flash("A nova senha deve ter pelo menos 12 caracteres.", "error")
        return redirect(url_for("users"))
    if user.id == current_user.id and (role != "master" or request.form.get("active") != "on"):
        flash("Não é permitido remover ou desativar seu próprio perfil Master.", "error")
        return redirect(url_for("users"))
    user.username = username
    user.role = role
    if user.id != current_user.id:
        user.active = request.form.get("active") == "on"
    if password:
        user.password_hash = generate_password_hash(password)
    log("user_update", str(uid) + ":" + role)
    db.session.commit()
    flash("Cadastro do usuário atualizado.", "success")
    return redirect(url_for("users"))

@app.post("/admin/users/<int:uid>/delete")
@roles("master")
def delete_user(uid):
    user = db.get_or_404(User, uid)
    if user.id == current_user.id:
        flash("Não é permitido excluir sua própria conta.", "error")
        return redirect(url_for("users"))
    if user.role == "master" and user.active and User.query.filter_by(role="master", active=True).count() <= 1:
        flash("Não é permitido excluir o último Master ativo.", "error")
        return redirect(url_for("users"))
    username, role = user.username, user.role
    FirstAccessToken.query.filter_by(user_id=user.id).delete(synchronize_session=False)
    db.session.delete(user)
    log("user_delete", username + ":" + role)
    db.session.commit()
    flash("Usuário excluído.", "success")
    return redirect(url_for("users"))

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
    records = Response.query.filter(db.or_(Response.store_name.isnot(None), Response.owner_name.isnot(None), Response.email.isnot(None), Response.cnpj.isnot(None))).order_by(Response.submitted_at.desc()).limit(500).all()
    log("pii_access", "response_list")
    db.session.commit()
    return render_template("responses.html", records=records)

@app.get("/admin/responses/<int:rid>")
@roles("master")
def response_detail(rid):
    record = db.get_or_404(Response, rid)
    log("pii_access", "response:" + str(rid))
    db.session.commit()
    return render_template("response_detail.html", record=record, answers=[(db.session.get(Question, a.question_id), a) for a in record.answers])

@app.get("/admin/open-answers")
@login_required
def open_answers():
    query = (db.session.query(Answer, Question, Response.submitted_at)
             .join(Question, Question.id == Answer.question_id)
             .join(Response, Response.id == Answer.response_id)
             .filter(Question.answer_type.in_(("open", "single", "multiple")), Answer.answer_text.isnot(None)))
    if current_user.role != "master":
        query = query.filter(Question.sector == "Geral")
    rows = query.order_by(Response.submitted_at.desc()).limit(1000).all()
    log("open_answers_access", "general_only" if current_user.role != "master" else "all_anonymous_answers")
    db.session.commit()
    return render_template("open_answers.html", records=rows)

@app.get("/admin/identities")
@roles("master")
def identities():
    rows = (db.session.query(RespondentIdentity, Survey.title)
            .join(Survey, Survey.id == RespondentIdentity.survey_id)
            .filter(RespondentIdentity.token_hash.is_(None))
            .order_by(RespondentIdentity.submitted_at.desc()).limit(500).all())
    log("identity_access", "identity_list")
    db.session.commit()
    return render_template("identities.html", records=rows)

@app.get("/audit")
@roles("master", "auditoria")
def audit():
    logs = Audit.query.order_by(Audit.id.desc()).limit(500).all()
    return render_template("audit.html", logs=logs)

@app.get("/admin/system-health")
@roles("master")
def system_health():
    database_ok = False
    smtp_configured = False
    alert_email_configured = False
    incidents = []
    try:
        db.session.execute(text("SELECT 1")).scalar_one()
        database_ok = True
        incidents = SystemIncident.query.order_by(SystemIncident.resolved_at.is_(None).desc(),
            SystemIncident.created_at.desc()).limit(100).all()
        smtp = effective_smtp_settings()
        smtp_configured = bool(smtp["host"])
        alert_email_configured = bool(smtp.get("master_alert_email"))
    except Exception:
        db.session.rollback()
        app.logger.warning("Falha ao consultar o estado do sistema.")
    return render_template("system_health.html", database_ok=database_ok,
        smtp_configured=smtp_configured, alert_email_configured=alert_email_configured,
        incidents=incidents), (200 if database_ok else 503)

@app.post("/admin/system-health/incidents/<int:incident_id>/resolve")
@roles("master")
def resolve_system_incident(incident_id):
    incident = db.get_or_404(SystemIncident, incident_id)
    incident.resolved_at = now()
    log("system_incident_resolved", "incident:%s component:%s" % (incident.id, incident.component))
    db.session.commit()
    flash("Ocorrência marcada como resolvida.", "success")
    return redirect(url_for("system_health"))

@app.errorhandler(500)
def handle_internal_error(error):
    record_system_incident("application", "A aplicação registrou um erro interno (HTTP 500).")
    return render_template("server_error.html"), 500

@app.route("/p/<slug>", methods=["GET", "POST"])
@limiter.limit("40 per hour")
def public_survey(slug):
    s = Survey.query.filter_by(slug=slug).first_or_404()
    if not survey_is_open(s):
        return render_template("survey_closed.html", survey=s)
    questions = [q for q in s.questions if q.active]
    if not questions:
        abort(404)
    session.pop("survey_invite_id", None)
    invite_token = request.args.get("invite", "").strip()
    if invite_token:
        invited = SurveyInvite.query.filter_by(survey_id=s.id,
            response_token_hash=hashlib.sha256(invite_token.encode()).hexdigest()).first()
        if invited:
            session["survey_invite_id"] = invited.id
    if request.method == "POST":
        if request.form.get("stage") == "identity":
            info = {k: request.form.get(k, "").strip()[:255] for k in ("store_name", "email", "owner_name", "cnpj")}
            whatsapp = request.form.get("whatsapp_number", "").strip()[:20]
            whatsapp_digits = re.sub(r"\D", "", whatsapp)
            valid_whatsapp = bool(re.fullmatch(r"\+?[0-9\s().-]{10,20}", whatsapp) and 10 <= len(whatsapp_digits) <= 15)
            if s.whatsapp_mode == "required" and not valid_whatsapp:
                flash("Informe um número de WhatsApp válido para continuar.", "error")
                return render_template("identity.html", survey=s)
            if s.whatsapp_mode == "optional" and whatsapp and not valid_whatsapp:
                flash("Informe um número de WhatsApp válido ou deixe o campo em branco.", "error")
                return render_template("identity.html", survey=s)
            if s.whatsapp_mode == "none":
                whatsapp = ""
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
                
                if s.identity_type in ("cpf", "cnpj"):
                    doc = re.sub(r"\D", "", request.form.get("document_number", "") or request.form.get("cnpj", ""))
                    valid = (len(doc) == 11 and valid_cpf(doc)) if s.identity_type == "cpf" else valid_cnpj(doc)
                    if not valid:
                        flash("Informe um " + s.identity_type.upper() + " válido.", "error")
                        return render_template("identity.html", survey=s)
                    info["document_type"], info["document_number"] = s.identity_type, doc
                else:
                    info["document_type"], info["document_number"] = "none", ""
                db.session.query(RespondentIdentity).filter(
                    RespondentIdentity.token_hash.isnot(None),
                    RespondentIdentity.submitted_at < now() - timedelta(hours=24)
                ).delete(synchronize_session=False)
                duplicate = False
                if s.response_limit == "document" and info["document_type"] in ("cpf", "cnpj"):
                    duplicate = RespondentIdentity.query.filter_by(survey_id=s.id, document_type=info["document_type"], document_number=info["document_number"]).first() is not None
                    if not duplicate and info["document_type"] == "cnpj":
                        duplicate = Response.query.filter(Response.survey_id == s.id, Response.cnpj == info["document_number"]).first() is not None
                elif s.response_limit == "merchant" and matched:
                    duplicate = RespondentIdentity.query.filter_by(survey_id=s.id, eligibility_cnpj=matched.cnpj).first() is not None
                    if not duplicate:
                        duplicate = Response.query.filter_by(survey_id=s.id, merchant_id=matched.id).first() is not None
                if duplicate:
                    flash("Esta pesquisa já recebeu uma resposta usando este documento ou cadastro.", "error")
                    return render_template("identity.html", survey=s)
                if request.form.get("followup_consent") == "on":
                    followup_email = request.form.get("followup_email", "").strip().lower()[:255]
                    followup_whatsapp = request.form.get("followup_whatsapp", "").strip()[:20]
                    followup_digits = re.sub(r"\D", "", followup_whatsapp)
                    valid_followup_phone = bool(re.fullmatch(r"\+?[0-9\s().-]{10,20}", followup_whatsapp) and 10 <= len(followup_digits) <= 15)
                    followup_topic = request.form.get("followup_topic", "").strip()[:1000]
                    if followup_email and not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", followup_email):
                        flash("Informe um e-mail válido para retorno.", "error")
                        return render_template("identity.html", survey=s)
                    if not followup_email and not valid_followup_phone:
                        flash("Para receber retorno, informe um e-mail ou WhatsApp válido.", "error")
                        return render_template("identity.html", survey=s)
                    if not followup_topic:
                        flash("Descreva brevemente o assunto para receber retorno.", "error")
                        return render_template("identity.html", survey=s)
                    db.session.add(ParticipantFollowup(survey_id=s.id, email=followup_email,
                        whatsapp=followup_whatsapp if valid_followup_phone else "", topic=followup_topic))

                pending = RespondentIdentity(
                    survey_id=s.id,
                    document_type=info.get("document_type", "none"),
                    document_number=info.get("document_number", ""),
                    eligibility_cnpj=cnpj_digits(info.get("cnpj", "")),
                    store_name=info.get("store_name", ""),
                    owner_name=info.get("owner_name", ""),
                    email=info.get("email", ""),
                    whatsapp_number=whatsapp,
                    token_hash=hashlib.sha256(token.encode()).hexdigest()
                )
                db.session.add(pending)
                db.session.commit()
                has_branches = any(q.branch_question_id for q in questions)
                invite_id = session.get("survey_invite_id")
                invite = db.session.get(SurveyInvite, invite_id) if invite_id else None
                if not invite or invite.survey_id != s.id:
                    invite_id = None
                session["survey_state"] = {"survey": s.id, "token": token, "merchant_id": matched.id if matched else None, "invite_id": invite_id,
                                           "question_order": [q.id for q in questions]}
                if s.shuffle_questions and not has_branches:
                    random.shuffle(session["survey_state"]["question_order"])
                return redirect(url_for("answer_survey", slug=slug))
    return render_template("identity.html", survey=s)

@app.route("/p/<slug>/responder", methods=["GET", "POST"])
@limiter.limit("80 per hour")
def answer_survey(slug):
    s = Survey.query.filter_by(slug=slug).first_or_404()
    if not survey_is_open(s):
        session.pop("survey_state", None)
        return render_template("survey_closed.html", survey=s)
    state = session.get("survey_state") or {}
    if state.get("survey") != s.id:
        return redirect(url_for("public_survey", slug=slug))
    pending_identity = RespondentIdentity.query.filter_by(token_hash=hashlib.sha256(state.get("token", "").encode()).hexdigest(), survey_id=s.id).first()
    if not pending_identity:
        session.pop("survey_state", None)
        return redirect(url_for("public_survey", slug=slug))
    questions = [q for q in s.questions if q.active]
    if not questions:
        abort(404)
    order = state.get("question_order", [])
    positions = {qid: index for index, qid in enumerate(order)}
    questions.sort(key=lambda q: positions.get(q.id, len(positions) + q.position))
    if request.method == "POST":
        answers = {}
        for q in questions:
            raw = request.form.get("q_" + str(q.id), "").strip()
            if q.branch_question_id:
                parent_value = request.form.get("q_" + str(q.branch_question_id), "").strip()
                if parent_value != q.branch_value:
                    continue
            selected = request.form.getlist("q_" + str(q.id)) if q.answer_type in ("single", "multiple") else []
            is_blank = (not selected) if q.answer_type in ("single", "multiple") else (not raw)
            if q.optional and is_blank:
                continue
            if q.answer_type in ("single", "multiple"):
                options = q.choice_options
                if (q.answer_type == "single" and len(selected) != 1) or (q.answer_type == "multiple" and not selected) or any(value not in options for value in selected):
                    flash("Selecione uma ou mais opções válidas para continuar.", "error")
                    return render_template("answer.html", survey=s, questions=questions, values=request.form)
                answers[q.id] = {"rating": 0, "text": json.dumps(selected, ensure_ascii=False)}
            elif q.answer_type == "open":
                if not raw or len(raw) > 5000:
                    flash("Responda cada pergunta aberta com até 5.000 caracteres.", "error")
                    return render_template("answer.html", survey=s, questions=questions, values=request.form)
                answers[q.id] = {"rating": 0, "text": raw}
            else:
                allowed = ("0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10") if q.answer_type == "nps" else (("1", "2", "3", "4", "5", "na") if q.allow_na else ("1", "2", "3", "4", "5"))
                if raw not in allowed:
                    flash("Responda todas as perguntas antes de confirmar.", "error")
                    return render_template("answer.html", survey=s, questions=questions, values=request.form)
                answers[q.id] = {"rating": 0 if raw == "na" else int(raw), "text": None}
        if request.form.get("confirm") != "yes":
            flash("Confirme suas respostas na última etapa.", "error")
            return render_template("answer.html", survey=s, questions=questions, values=request.form)
        # Revalidação no servidor da lista de acesso, inclusive após voltar pelo navegador.
        merchant = db.session.get(Merchant, state.get("merchant_id")) if state.get("merchant_id") else None
        identity = pending_identity
        if s.target == "lojista" and (not merchant or not merchant.enabled or
            cnpj_digits(identity.eligibility_cnpj) != merchant.cnpj or
            not hmac.compare_digest(clean_name(identity.owner_name), clean_name(merchant.owner_name))):
            log("audience_denied", "survey:" + str(s.id))
            db.session.commit()
            session.pop("survey_state", None)
            return render_template("thanks.html", sent=False)
        device_time = request.form.get("device_submitted_at", "").strip()
        try:
            device_time = datetime.fromisoformat(device_time.replace("Z", "+00:00"))
            device_time = device_time.astimezone(timezone.utc) if device_time.tzinfo else None
        except ValueError:
            device_time = None
        device_timezone = request.form.get("device_timezone", "").strip()[:80]
        resp = Response(survey_id=s.id, device_submitted_at=device_time, device_timezone=device_timezone)
        db.session.add(resp)
        invite = db.session.get(SurveyInvite, state.get("invite_id")) if state.get("invite_id") else None
        if invite and invite.survey_id == s.id:
            invite.responded_at = now()
        identity.token_hash = None
        identity.submitted_at = now()
        db.session.flush()
        for q in questions:
            if q.id not in answers:
                continue
            item = answers[q.id]
            db.session.add(Answer(response_id=resp.id, question_id=q.id, rating=item["rating"], answer_text=item["text"]))
        evaluate_survey_alerts(s.id)
        log("survey_submitted", "survey:" + str(s.id))
        db.session.commit()
        session.pop("survey_state", None)
        session.pop("survey_invite_id", None)
        sent = send_receipt(resp, s, questions, answers, identity.email or "")
        if sent:
            resp.email_sent = True
            db.session.commit()
        return render_template("thanks.html", sent=sent)
    return render_template("answer.html", survey=s, questions=questions, values=request.form)

def smtp_fernet():
    from cryptography.fernet import Fernet
    key = base64.urlsafe_b64encode(hashlib.sha256(app.config["SECRET_KEY"].encode()).digest())
    return Fernet(key)

def effective_smtp_settings():
    config = SMTPConfig.query.order_by(SMTPConfig.id).first()
    result = {
        "host": (config.host if config and config.host else os.environ.get("SMTP_HOST", "")),
        "port": (config.port if config else int(os.environ.get("SMTP_PORT", "587"))),
        "tls": (config.tls if config else os.environ.get("SMTP_TLS", "1") == "1"),
        "username": (config.username if config and config.username else os.environ.get("SMTP_USER", "")),
        "from_address": (config.from_address if config and config.from_address else os.environ.get("SMTP_FROM", "")),
        "master_alert_email": ((config.master_alert_email if config else "") or os.environ.get("MASTER_ALERT_EMAIL", "")),
        "password": os.environ.get("SMTP_PASSWORD", ""),
    }
    if config and config.password_encrypted:
        try:
            result["password"] = smtp_fernet().decrypt(config.password_encrypted.encode()).decode()
        except Exception:
            app.logger.error("Não foi possível descriptografar a senha SMTP configurada")
            result["password"] = ""
    return result

def send_smtp_message(settings, message):
    with smtplib.SMTP(settings["host"], int(settings["port"]), timeout=12) as smtp:
        if settings["tls"]:
            smtp.starttls()
        if settings["username"]:
            smtp.login(settings["username"], settings["password"])
        smtp.send_message(message)

def notify_master_incident(incident):
    config = SMTPConfig.query.order_by(SMTPConfig.id).first()
    recipient = ((config.master_alert_email if config else "") or os.environ.get("MASTER_ALERT_EMAIL", "")).strip()
    settings = effective_smtp_settings()
    if not recipient or not settings["host"]:
        return
    msg = EmailMessage()
    msg["Subject"] = "Alerta do sistema de pesquisas"
    msg["From"] = settings["from_address"] or "pesquisa@example.invalid"
    msg["To"] = recipient
    msg.set_content("O sistema registrou uma ocorrência em " + incident.component + ".\n\n"
        + incident.summary + "\n\nAcesse a área Saúde do sistema no painel para verificar o status.")
    try:
        send_smtp_message(settings, msg)
    except Exception:
        app.logger.warning("Não foi possível enviar a notificação de incidente ao Master.")

def record_system_incident(component, summary, notify=True):
    try:
        existing = SystemIncident.query.filter_by(component=component, resolved_at=None).first()
        if existing:
            return existing
        incident = SystemIncident(component=component[:40], summary=summary[:255])
        db.session.add(incident)
        db.session.commit()
    except Exception:
        db.session.rollback()
        app.logger.error("Não foi possível registrar uma ocorrência de sistema.")
        return None
    if notify:
        notify_master_incident(incident)
    return incident

def resolve_system_incidents(component):
    SystemIncident.query.filter_by(component=component, resolved_at=None).update(
        {SystemIncident.resolved_at: now()}, synchronize_session=False)

@app.route("/admin/settings/smtp", methods=["GET", "POST"])
@roles("master")
def smtp_settings():
    config = SMTPConfig.query.order_by(SMTPConfig.id).first()
    test_recipient = ""
    if request.method == "POST":
        action = request.form.get("action", "save")
        if action == "test":
            test_recipient = request.form.get("test_recipient", "").strip().lower()
            if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", test_recipient) or len(test_recipient) > 255:
                flash("Informe um e-mail válido para receber o teste.", "error")
            else:
                settings = effective_smtp_settings()
                if not settings["host"]:
                    flash("Salve a configuração SMTP antes de testar o envio.", "error")
                else:
                    msg = EmailMessage()
                    msg["Subject"] = "Teste de envio SMTP — Pesquisa Shopping Carpina"
                    msg["From"] = settings["from_address"] or "pesquisa@example.invalid"
                    msg["To"] = test_recipient
                    msg.set_content("Este é um teste de envio SMTP da aplicação de pesquisas do Shopping Carpina. Nenhuma resposta de pesquisa foi incluída.")
                    try:
                        send_smtp_message(settings, msg)
                        resolve_system_incidents("smtp")
                        log("smtp_test_success", "test_email_sent")
                        db.session.commit()
                        flash("E-mail de teste enviado. Confira a caixa de entrada e o spam.", "success")
                    except Exception:
                        db.session.rollback()
                        record_system_incident("smtp", "Falha no teste de envio SMTP.")
                        flash("Falha ao enviar o teste SMTP. Confira servidor, porta, TLS e autenticação; nenhum segredo foi exibido.", "error")
            return render_template("smtp_settings.html", settings=smtp_form_values(config),
                password_saved=bool(config and config.password_encrypted) or bool(os.environ.get("SMTP_PASSWORD")),
                test_recipient=test_recipient)
        if action != "save":
            abort(400)
        host = request.form.get("host", "").strip()
        from_address = request.form.get("from_address", "").strip()
        username = request.form.get("username", "").strip()
        master_alert_email = request.form.get("master_alert_email", "").strip().lower()
        if master_alert_email and (not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", master_alert_email) or len(master_alert_email) > 255):
            flash("Informe um e-mail válido para alertas do Master.", "error")
            return render_template("smtp_settings.html", settings=smtp_form_values(config),
                password_saved=bool(config and config.password_encrypted) or bool(os.environ.get("SMTP_PASSWORD")))
        try:
            port = int(request.form.get("port", "587"))
            if not 1 <= port <= 65535:
                raise ValueError()
        except (TypeError, ValueError):
            flash("Informe uma porta SMTP entre 1 e 65535.", "error")
            return render_template("smtp_settings.html", settings=smtp_form_values(config),
                password_saved=bool(config and config.password_encrypted) or bool(os.environ.get("SMTP_PASSWORD")))
        if not config:
            config = SMTPConfig()
            db.session.add(config)
        config.host = host[:255]
        config.port = port
        config.tls = request.form.get("tls") == "on"
        config.username = username[:255]
        config.from_address = from_address[:255]
        config.master_alert_email = master_alert_email[:255]
        config.updated_at = now()
        new_password = request.form.get("password", "")
        if request.form.get("clear_password") == "on":
            config.password_encrypted = None
        elif new_password:
            config.password_encrypted = smtp_fernet().encrypt(new_password.encode()).decode()
        log("smtp_config_update", "settings_saved")
        db.session.commit()
        flash("Configuração SMTP salva.", "success")
        config = SMTPConfig.query.order_by(SMTPConfig.id).first()
    return render_template("smtp_settings.html", settings=smtp_form_values(config),
        password_saved=bool(config and config.password_encrypted) or bool(os.environ.get("SMTP_PASSWORD")),
        test_recipient=test_recipient)

def smtp_form_values(config):
    return {
        "host": config.host if config and config.host else os.environ.get("SMTP_HOST", ""),
        "port": config.port if config else os.environ.get("SMTP_PORT", "587"),
        "tls": config.tls if config else os.environ.get("SMTP_TLS", "1") == "1",
        "username": config.username if config and config.username else os.environ.get("SMTP_USER", ""),
        "from_address": config.from_address if config and config.from_address else os.environ.get("SMTP_FROM", ""),
        "master_alert_email": (config.master_alert_email if config and config.master_alert_email else os.environ.get("MASTER_ALERT_EMAIL", "")),
    }

@app.route("/admin/reports/schedules", methods=["GET", "POST"])
@roles("master")
def manage_report_schedules():
    if request.method == "POST":
        recipient = request.form.get("recipient_email", "").strip().lower()
        sector = request.form.get("sector", "")
        frequency = request.form.get("frequency", "")
        try:
            weekday = int(request.form.get("weekday", "0"))
            month_day = int(request.form.get("month_day", "1"))
            send_hour = int(request.form.get("send_hour", "8"))
        except ValueError:
            abort(400)
        if (not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", recipient) or len(recipient) > 255
            or sector not in SECTORS or frequency not in ("weekly", "monthly")
            or not 0 <= weekday <= 6 or not 1 <= month_day <= 28 or not 0 <= send_hour <= 23):
            abort(400)
        schedule = ReportSchedule(recipient_email=recipient, sector=sector, frequency=frequency,
            weekday=weekday, month_day=month_day, send_hour=send_hour)
        db.session.add(schedule)
        db.session.flush()
        log("report_schedule_create", "schedule:%s frequency:%s sector:%s" % (schedule.id, frequency, sector))
        db.session.commit()
        flash("Relatório agendado. O envio usará somente indicadores agregados do setor escolhido.", "success")
        return redirect(url_for("manage_report_schedules"))
    schedules = ReportSchedule.query.order_by(ReportSchedule.id.desc()).all()
    return render_template("report_schedules.html", schedules=schedules, sectors=SECTORS)

@app.post("/admin/reports/schedules/<int:schedule_id>/toggle")
@roles("master")
def toggle_report_schedule(schedule_id):
    schedule = db.get_or_404(ReportSchedule, schedule_id)
    schedule.active = not schedule.active
    log("report_schedule_toggle", "schedule:%s active:%s" % (schedule.id, schedule.active))
    db.session.commit()
    return redirect(url_for("manage_report_schedules"))

@app.post("/admin/reports/schedules/<int:schedule_id>/delete")
@roles("master")
def delete_report_schedule(schedule_id):
    schedule = db.get_or_404(ReportSchedule, schedule_id)
    log("report_schedule_delete", "schedule:%s" % schedule.id)
    db.session.delete(schedule)
    db.session.commit()
    flash("Agendamento removido.", "success")
    return redirect(url_for("manage_report_schedules"))

def build_scheduled_report_pdf(schedule, start_at, end_at, period_label):
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from xml.sax.saxutils import escape
    output = io.BytesIO()
    doc = SimpleDocTemplate(output, pagesize=A4, rightMargin=16*mm, leftMargin=16*mm, topMargin=16*mm, bottomMargin=16*mm)
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="ScheduleSmall", parent=styles["BodyText"], fontSize=8, leading=10))
    story = [Paragraph("Relatório de satisfação", styles["Title"]),
        Paragraph("Setor: %s · Período: %s" % (escape(schedule.sector), escape(period_label)), styles["BodyText"]),
        Paragraph("Somente indicadores agregados. Nenhum dado de identificação ou resposta individual está neste relatório.", styles["ScheduleSmall"]), Spacer(1, 6*mm)]
    metric_filter = db.or_(
        db.and_(Question.answer_type == "rating", Answer.rating.between(1, 5)),
        db.and_(Question.answer_type == "nps", Answer.rating.between(0, 10)))
    rows = (db.session.query(Survey.title, Question.text, Question.answer_type, db.func.count(Answer.id),
            db.func.avg(db.case((Question.answer_type == "rating", Answer.rating), else_=None)),
            db.func.sum(db.case((Answer.rating >= 9, 1), else_=0)),
            db.func.sum(db.case((Answer.rating <= 6, 1), else_=0)))
        .join(Question, Question.survey_id == Survey.id)
        .join(Answer, Answer.question_id == Question.id)
        .join(Response, Response.id == Answer.response_id)
        .filter(Question.sector == schedule.sector, Question.answer_type.in_(("rating", "nps")), metric_filter,
            Response.submitted_at >= start_at, Response.submitted_at < end_at)
        .group_by(Survey.title, Question.text, Question.answer_type).order_by(Survey.title, Question.text).all())
    table_data = [["Pesquisa / pergunta", "Métrica", "Respostas"]]
    minimum = 3
    for title, question, kind, count, average, promoters, detractors in rows:
        count = int(count or 0)
        if count < minimum:
            metric = "Oculto (menos de 3 respostas)"
        elif kind == "nps":
            metric = "NPS %s" % round((int(promoters or 0) - int(detractors or 0)) / count * 100)
        else:
            metric = "Média %.2f / 5" % float(average)
        count_label = str(count) if count >= minimum else "Oculto (<3)"
        table_data.append([Paragraph("<b>%s</b><br/>%s" % (escape(title), escape(question)), styles["ScheduleSmall"]), metric, count_label])
    if len(table_data) == 1:
        story.append(Paragraph("Não houve respostas para os filtros e período informados.", styles["BodyText"]))
    else:
        table = Table(table_data, colWidths=[112*mm, 44*mm, 24*mm], repeatRows=1)
        table.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,0), colors.HexColor("#141F39")),
            ("TEXTCOLOR", (0,0), (-1,0), colors.white), ("GRID", (0,0), (-1,-1), .3, colors.HexColor("#ccd7d7")),
            ("VALIGN", (0,0), (-1,-1), "TOP"), ("FONTSIZE", (0,0), (-1,-1), 8), ("PADDING", (0,0), (-1,-1), 6)]))
        story.append(table)
    doc.build(story)
    return output.getvalue()

def deliver_scheduled_report(schedule, run_at):
    if schedule.frequency == "weekly":
        current_week_start = (run_at.date() - timedelta(days=run_at.weekday()))
        start_date = current_week_start - timedelta(days=7)
        end_date = current_week_start
        period_key = "W:%04d-%02d" % (run_at.isocalendar().year, run_at.isocalendar().week)
        label = "%s a %s" % ((start_date).strftime("%d/%m/%Y"), (end_date - timedelta(days=1)).strftime("%d/%m/%Y"))
    else:
        current_month_start = run_at.date().replace(day=1)
        previous_month_end = current_month_start - timedelta(days=1)
        previous_month_start = previous_month_end.replace(day=1)
        start_date, end_date = previous_month_start, current_month_start
        period_key = "M:%04d-%02d" % (current_month_start.year, current_month_start.month)
        label = previous_month_start.strftime("%m/%Y")
    start_at = datetime.combine(start_date, datetime.min.time(), RECIFE_TZ).astimezone(timezone.utc)
    end_at = datetime.combine(end_date, datetime.min.time(), RECIFE_TZ).astimezone(timezone.utc)
    report = build_scheduled_report_pdf(schedule, start_at, end_at, label)
    settings = effective_smtp_settings()
    if not settings["host"] or not settings["from_address"]:
        return False
    message = EmailMessage()
    message["Subject"] = "Relatório %s de pesquisas — %s" % ("semanal" if schedule.frequency == "weekly" else "mensal", schedule.sector)
    message["From"] = settings["from_address"]
    message["To"] = schedule.recipient_email
    message.set_content("Segue o relatório agregado de pesquisas do setor selecionado. Resultados individuais e dados de identificação não são incluídos.")
    message.add_attachment(report, maintype="application", subtype="pdf", filename="relatorio_pesquisa.pdf")
    try:
        with smtplib.SMTP(settings["host"], int(settings["port"]), timeout=20) as smtp:
            if settings["tls"]:
                smtp.starttls()
            if settings["username"]:
                smtp.login(settings["username"], settings["password"])
            smtp.send_message(message)
    except Exception:
        record_system_incident("smtp", "Falha no envio de relatório agendado.")
        return False
    schedule.last_sent_period = period_key
    log("report_schedule_sent", "schedule:%s period:%s" % (schedule.id, period_key), actor="sistema")
    db.session.commit()
    return True

def public_invite_url(survey, token):
    if has_request_context():
        return url_for("public_survey", slug=survey.slug, invite=token, _external=True)
    base_url = (os.environ.get("PUBLIC_BASE_URL") or "https://nps.shoppingcarpina.com.br").rstrip("/")
    return base_url + "/p/" + survey.slug + "?invite=" + token

def send_due_invite_reminders(run_at=None, batch_limit=100):
    run_at = run_at or now()
    sent = 0
    surveys = Survey.query.filter_by(active=True).all()
    eligible = []
    for survey in surveys:
        if not survey.automatic_reminders or not survey_is_open(survey):
            continue
        cutoff = run_at - timedelta(days=survey.reminder_delay_days or 3)
        pending = (SurveyInvite.query.filter_by(survey_id=survey.id, reminder_sent_at=None, responded_at=None)
            .order_by(SurveyInvite.id).all())
        due = [invite for invite in pending
            if as_utc(invite.created_at) and as_utc(invite.created_at) <= cutoff][:batch_limit]
        if due:
            eligible.append((survey, due))
    if not eligible:
        return 0
    settings = effective_smtp_settings()
    if not settings["host"]:
        record_system_incident("smtp", "Lembretes automáticos aguardam configuração SMTP.")
        return 0
    try:
        with smtplib.SMTP(settings["host"], int(settings["port"]), timeout=12) as smtp:
            if settings["tls"]:
                smtp.starttls()
            if settings["username"]:
                smtp.login(settings["username"], settings["password"])
            for survey, invites in eligible:
                for invite in invites:
                    token = secrets.token_urlsafe(32)
                    msg = EmailMessage()
                    msg["Subject"] = "Lembrete: pesquisa de satisfação — " + survey.title
                    msg["From"] = settings["from_address"] or "pesquisa@example.invalid"
                    msg["To"] = invite.email
                    msg.set_content("A pesquisa de satisfação está aberta. Responda pelo link individual: "
                        + public_invite_url(survey, token)
                        + "\n\nOs dados de identificação não são vinculados às respostas individuais. "
                        + "O sistema registra apenas se este convite recebeu resposta, sem associar o e-mail às respostas.")
                    smtp.send_message(msg)
                    invite.response_token_hash = hashlib.sha256(token.encode()).hexdigest()
                    invite.reminder_sent_at = now()
                    db.session.commit()
                    sent += 1
        resolve_system_incidents("smtp")
        db.session.commit()
    except Exception:
        db.session.rollback()
        record_system_incident("smtp", "Falha no envio dos lembretes automáticos.")
    return sent

@app.cli.command("send-scheduled-reports")
def send_scheduled_reports_command():
    """Send due aggregate PDF reports; schedule this command every 15 minutes."""
    run_at = now().astimezone(RECIFE_TZ)
    sent = 0
    schedules = ReportSchedule.query.filter_by(active=True, send_hour=run_at.hour).all()
    if run_at.minute <= 15:
        for schedule in schedules:
            if schedule.frequency == "weekly" and schedule.weekday != run_at.weekday():
                continue
            if schedule.frequency == "monthly" and schedule.month_day != run_at.day:
                continue
            key = ("W:%04d-%02d" % (run_at.isocalendar().year, run_at.isocalendar().week)
                if schedule.frequency == "weekly" else "M:%04d-%02d" % (run_at.year, run_at.month))
            if schedule.last_sent_period == key:
                continue
            sent += int(deliver_scheduled_report(schedule, run_at))
    reminders_sent = send_due_invite_reminders(run_at.astimezone(timezone.utc))
    click_echo = "Relatórios enviados: %d; lembretes automáticos enviados: %d" % (sent, reminders_sent)
    print(click_echo)

def send_receipt(resp, survey, questions, answers, email):
    if not email:
        return False
    settings = effective_smtp_settings()
    if not settings["host"]:
        return False
    msg = EmailMessage()
    msg["Subject"] = "Obrigado por participar — " + survey.title
    msg["From"] = settings["from_address"] or "pesquisa@example.invalid"
    msg["To"] = email
    msg.set_content("Obrigado por participar da pesquisa " + survey.title + ". Seus dados de identificação são armazenados separadamente e não são vinculados às respostas individuais.")
    try:
        with smtplib.SMTP(settings["host"], int(settings["port"]), timeout=12) as smtp:
            if settings["tls"]:
                smtp.starttls()
            if settings["username"]:
                smtp.login(settings["username"], settings["password"])
            smtp.send_message(msg)
        resolve_system_incidents("smtp")
        return True
    except Exception:
        record_system_incident("smtp", "Falha no envio de recibo de pesquisa.")
        return False


def ensure_schema():
    """Create new tables and add optional fields without replacing existing data."""
    guard = db.engine.connect()
    guarded = db.engine.dialect.name == "postgresql"
    try:
        if guarded:
            guard.execute(text("SELECT pg_advisory_lock(74120261027)"))
            guard.commit()
        db.create_all()
        with db.engine.begin() as connection:
            tables = set(inspect(connection).get_table_names())
            additions = {
            "survey": {
                "identity_type": "VARCHAR(8) NOT NULL DEFAULT 'none'",
                "automatic_reminders": "BOOLEAN NOT NULL DEFAULT FALSE",
                "reminder_delay_days": "INTEGER NOT NULL DEFAULT 3",
                "whatsapp_mode": "VARCHAR(12) NOT NULL DEFAULT 'none'",
                "followup_enabled": "BOOLEAN NOT NULL DEFAULT TRUE",
                "shuffle_questions": "BOOLEAN NOT NULL DEFAULT FALSE",
                "starts_at": "TIMESTAMP WITH TIME ZONE",
                "ends_at": "TIMESTAMP WITH TIME ZONE",
                "response_limit": "VARCHAR(20) NOT NULL DEFAULT 'none'",
            },
            "survey_invite": {
                "response_token_hash": "VARCHAR(64) NOT NULL DEFAULT ''",
                "responded_at": "TIMESTAMP WITH TIME ZONE",
                "created_at": "TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP",
            },
            "smtp_config": {
                "master_alert_email": "VARCHAR(255) NOT NULL DEFAULT ''",
            },
            "action_plan": {
                "baseline_average": "FLOAT",
                "reviewed_average": "FLOAT",
                "reviewed_at": "TIMESTAMP WITH TIME ZONE",
                "review_notes": "TEXT NOT NULL DEFAULT ''",
            },
            "response": {
                "device_submitted_at": "TIMESTAMP WITH TIME ZONE",
                "device_timezone": "VARCHAR(80) NOT NULL DEFAULT ''",
            },
            "question": {
                "answer_type": "VARCHAR(20) NOT NULL DEFAULT 'rating'",
                "optional": "BOOLEAN NOT NULL DEFAULT FALSE",
                "allow_na": "BOOLEAN NOT NULL DEFAULT TRUE",
                "notice": "TEXT NOT NULL DEFAULT ''",
            "choices": "TEXT NOT NULL DEFAULT '[]'",
            "branch_question_id": "INTEGER",
            "branch_value": "VARCHAR(255) NOT NULL DEFAULT ''",
            },
            "answer": {"answer_text": "TEXT"},
            "respondent_identity": {
                "eligibility_cnpj": "VARCHAR(14) NOT NULL DEFAULT ''",
                "token_hash": "VARCHAR(64)",
                "whatsapp_number": "VARCHAR(20) NOT NULL DEFAULT ''",
            },
        }
            for table, columns in additions.items():
                if table not in tables:
                    continue
                existing = {column["name"] for column in inspect(connection).get_columns(table)}
                for name, declaration in columns.items():
                    if name not in existing:
                        connection.execute(text(f'ALTER TABLE "{table}" ADD COLUMN "{name}" {declaration}'))
                        existing.add(name)
    finally:
        if guarded:
            guard.execute(text("SELECT pg_advisory_unlock(74120261027)"))
            guard.commit()
        guard.close()

@app.cli.command("init-db")
def init_db():
    ensure_schema()
    print("Estrutura do banco atualizada sem remover dados.")

@app.cli.command("create-master")
def create_master():
    ensure_schema()
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

# Migração aditiva e idempotente ao iniciar, preservando os registros existentes.
with app.app_context():
    ensure_schema()
