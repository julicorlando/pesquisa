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
from datetime import datetime, timezone, timedelta
from email.message import EmailMessage
from functools import wraps
from urllib.parse import urlparse

from flask import Flask, request, redirect, url_for, render_template, flash, abort, session, jsonify, send_file
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

def clean_name(v):
    v = unicodedata.normalize("NFKD", (v or "").strip().casefold())
    return re.sub(r"\s+", " ", "".join(c for c in v if not unicodedata.combining(c)))

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
        return value in ("1", "2", "3", "4", "5", "na")
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
    shuffle_questions = db.Column(db.Boolean, nullable=False, default=False)
    questions = db.relationship("Question", backref="survey", order_by="Question.position", cascade="all,delete-orphan")

class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    survey_id = db.Column(db.Integer, db.ForeignKey("survey.id"), nullable=False)
    sector = db.Column(db.String(50), nullable=False)
    text = db.Column(db.Text, nullable=False)
    position = db.Column(db.Integer, default=0)
    active = db.Column(db.Boolean, default=True)
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
    created_at = db.Column(db.DateTime(timezone=True), default=now)

class SurveyInvite(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    survey_id = db.Column(db.Integer, db.ForeignKey("survey.id"), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    reminder_sent_at = db.Column(db.DateTime(timezone=True))
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

@app.route("/dashboard")
@login_required
def dashboard():
    accessible = SECTORS if current_user.role in ("master", "auditoria") else ROLE_SECTORS.get(current_user.role, [])
    stats, selected_survey, selected_sector, date_from, date_to, trends = dashboard_data(accessible)
    log("dashboard_view", ",".join(accessible))
    db.session.commit()
    return render_template("dashboard.html", stats=stats,
        surveys=Survey.query.filter(Survey.questions.any(Question.sector.in_(accessible))).order_by(Survey.title).all() if accessible else [],
        sectors=accessible, selected_survey=selected_survey, selected_sector=selected_sector,
        date_from=date_from, date_to=date_to, trends=trends)

@app.get("/dashboard/print")
@login_required
def print_dashboard():
    accessible = SECTORS if current_user.role in ("master", "auditoria") else ROLE_SECTORS.get(current_user.role, [])
    stats, _, _, _, _, _ = dashboard_data(accessible)
    layout = request.args.get("format") if request.args.get("format") in ("cards", "bi") else "cards"
    log("dashboard_print", layout)
    db.session.commit()
    return render_template("dashboard_print.html", stats=stats, layout=layout, generated_at=now())

@app.route("/action-plans", methods=["GET", "POST"])
@login_required
def action_plans():
    accessible = SECTORS if current_user.role in ("master", "auditoria") else ROLE_SECTORS.get(current_user.role, [])
    if request.method == "POST":
        plan_id = request.form.get("plan_id", type=int)
        plan = db.get_or_404(ActionPlan, plan_id) if plan_id else ActionPlan()
        sector = request.form.get("sector", "")
        if sector not in accessible or (plan_id and plan.sector not in accessible):
            abort(403)
        plan.survey_id = request.form.get("survey_id", type=int)
        if not db.session.get(Survey, plan.survey_id):
            abort(400)
        plan.sector = sector
        plan.title = request.form.get("title", "").strip()[:200]
        plan.description = request.form.get("description", "").strip()[:2000]
        plan.owner = request.form.get("owner", "").strip()[:120]
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
            log("action_plan_save", ("update:" if plan_id else "create:") + str(plan.id or "new"))
            db.session.commit()
            flash("Plano de ação salvo.", "success")
        return redirect(url_for("action_plans"))
    plans = ActionPlan.query.filter(ActionPlan.sector.in_(accessible)).order_by(ActionPlan.due_date, ActionPlan.id.desc()).all() if accessible else []
    surveys = Survey.query.order_by(Survey.title).all()
    survey_titles = {s.id: s.title for s in surveys}
    return render_template("action_plans.html", plans=plans, surveys=surveys, sectors=accessible, survey_titles=survey_titles)

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
                       identity_type=("cnpj" if request.form.get("target") == "lojista" else "none"))
            db.session.add(s)
            log("survey_create", slug)
            db.session.commit()
            return redirect(url_for("edit_survey", sid=s.id))
    return render_template("surveys.html", surveys=Survey.query.order_by(Survey.id.desc()).all())

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
    ActionPlan.query.filter_by(survey_id=sid).delete(synchronize_session=False)
    SurveyInvite.query.filter_by(survey_id=sid).delete(synchronize_session=False)
    log("survey_delete", "survey:" + str(sid))
    db.session.delete(survey)
    db.session.commit()
    flash("Pesquisa e resultados excluídos. Nenhum CPF ou CNPJ estava registrado.", "success")
    return redirect(url_for("manage_surveys"))

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
    writer.writerow(["setor", "enunciado", "tipo_resposta", "opcoes", "aviso"])
    for row in rows:
        writer.writerow([csv_export_value(value) for value in row])
    data = ("\ufeff" + output.getvalue()).encode("utf-8")
    return send_file(io.BytesIO(data), mimetype="text/csv; charset=utf-8", as_attachment=True, download_name=filename)

@app.get("/admin/questions/model.csv")
@login_required
def questions_csv_model():
    return questions_csv_response("modelo_perguntas_pesquisa.csv", [])

@app.get("/admin/surveys/<int:sid>/questions.csv")
@login_required
def export_survey_questions(sid):
    survey = db.get_or_404(Survey, sid)
    rows = [
        (q.sector, q.text, q.answer_type, "|".join(q.choice_options), q.notice or "")
        for q in Question.query.filter_by(survey_id=sid).order_by(Question.position).all()
    ]
    return questions_csv_response("perguntas_" + survey.slug + ".csv", rows)

@app.post("/admin/surveys/<int:sid>/questions/import")
@login_required
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
                prepared.append((sector, statement, answer_type, choices, notice))
        if errors:
            flash("CSV não importado: " + " | ".join(errors[:10]), "error")
        elif not prepared:
            flash("O CSV não contém perguntas para importar.", "error")
        else:
            position = len(survey.questions)
            for offset, item in enumerate(prepared, start=1):
                sector, statement, answer_type, choices, notice = item
                db.session.add(Question(survey_id=sid, sector=sector, text=statement, position=position + offset, active=True, answer_type=answer_type, notice=notice, choices=json.dumps(choices, ensure_ascii=False)))
            log("questions_csv_import", str(sid) + ":" + str(len(prepared)))
            db.session.commit()
            flash(str(len(prepared)) + " pergunta(s) importada(s) e salva(s). As perguntas existentes foram mantidas.", "success")
    except (UnicodeDecodeError, csv.Error, ValueError) as exc:
        db.session.rollback()
        flash("Não foi possível importar o CSV: " + str(exc)[:300], "error")
    return redirect(url_for("edit_survey", sid=sid))

@app.route("/admin/surveys/<int:sid>", methods=["GET", "POST"])
@login_required
def edit_survey(sid):
    survey = db.get_or_404(Survey, sid)
    if request.method == "POST":
        kind = request.form.get("kind")
        if kind == "settings":
            survey.title = request.form.get("title", survey.title)[:200]
            survey.description = request.form.get("description", "")[:2000]
            survey.target = request.form.get("target") if request.form.get("target") in ("lojista", "publico") else survey.target
            survey.active = request.form.get("save_draft") != "yes" and request.form.get("active") == "on"
            if request.form.get("identity_type") in ("none", "cpf", "cnpj"):
                survey.identity_type = request.form.get("identity_type")
            survey.shuffle_questions = request.form.get("shuffle_questions") == "on"
            log("survey_update", str(sid))
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
                db.session.add(Question(survey_id=sid, sector=sector, text=text[:1000], position=len(survey.questions)+1, answer_type=answer_type, notice=notice, choices=json.dumps(choices, ensure_ascii=False), branch_question_id=branch_parent.id if branch_parent else None, branch_value=branch_value if branch_parent else ""))
                log("question_create", str(sid))
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
                log("question_remove", str(q.id))
            else:
                q.text = request.form.get("text", q.text)[:1000]
                q.active = request.form.get("active") == "on"
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
                log("question_update", str(q.id))
        db.session.commit()
        return redirect(url_for("edit_survey", sid=sid))
    invite_total = SurveyInvite.query.filter_by(survey_id=sid).count()
    invite_pending = SurveyInvite.query.filter_by(survey_id=sid, reminder_sent_at=None).count()
    response_count = Response.query.filter_by(survey_id=sid).count()
    return render_template("edit_survey.html", survey=survey, invite_total=invite_total,
        invite_pending=invite_pending, response_count=response_count)

@app.get("/admin/surveys/<int:sid>/qrcode.png")
@login_required
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
    pending = SurveyInvite.query.filter_by(survey_id=sid, reminder_sent_at=None).limit(1000).all()
    sent = 0
    try:
        with smtplib.SMTP(settings["host"], int(settings["port"]), timeout=12) as smtp:
            if settings["tls"]:
                smtp.starttls()
            if settings["username"]:
                smtp.login(settings["username"], settings["password"])
            for invite in pending:
                msg = EmailMessage()
                msg["Subject"] = "Lembrete: pesquisa de satisfação — " + survey.title
                msg["From"] = settings["from_address"] or "pesquisa@example.invalid"
                msg["To"] = invite.email
                msg.set_content("A pesquisa de satisfação está aberta. Responda pelo link: " + url_for("public_survey", slug=survey.slug, _external=True) + "\\n\\nOs dados de identificação não são vinculados às respostas individuais.")
                smtp.send_message(msg)
                invite.reminder_sent_at = now()
                sent += 1
        log("survey_reminders_sent", str(sid) + ":" + str(sent))
        db.session.commit()
        flash(str(sent) + " lembrete(s) enviado(s).", "success")
    except Exception:
        db.session.commit()
        app.logger.exception("Falha no envio de lembretes")
        flash(str(sent) + " lembrete(s) enviado(s); houve falha no restante. Os pendentes podem ser reenviados.", "error")
    return redirect(url_for("edit_survey", sid=sid))

@app.post("/admin/surveys/<int:sid>/reorder")
@login_required
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
                pending = RespondentIdentity(
                    survey_id=s.id,
                    document_type=info.get("document_type", "none"),
                    document_number=info.get("document_number", ""),
                    eligibility_cnpj=cnpj_digits(info.get("cnpj", "")),
                    store_name=info.get("store_name", ""),
                    owner_name=info.get("owner_name", ""),
                    email=info.get("email", ""),
                    token_hash=hashlib.sha256(token.encode()).hexdigest()
                )
                db.session.add(pending)
                db.session.commit()
                has_branches = any(q.branch_question_id for q in questions)
                session["survey_state"] = {"survey": s.id, "token": token, "merchant_id": matched.id if matched else None,
                                           "question_order": [q.id for q in questions]}
                if s.shuffle_questions and not has_branches:
                    random.shuffle(session["survey_state"]["question_order"])
                return redirect(url_for("answer_survey", slug=slug))
    return render_template("identity.html", survey=s)

@app.route("/p/<slug>/responder", methods=["GET", "POST"])
@limiter.limit("80 per hour")
def answer_survey(slug):
    s = Survey.query.filter_by(slug=slug, active=True).first_or_404()
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
            if q.answer_type in ("single", "multiple"):
                selected = request.form.getlist("q_" + str(q.id))
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
                allowed = ("0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10") if q.answer_type == "nps" else ("1", "2", "3", "4", "5", "na")
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
        resp = Response(survey_id=s.id)
        db.session.add(resp)
        identity.token_hash = None
        identity.submitted_at = now()
        db.session.flush()
        for q in questions:
            if q.id not in answers:
                continue
            item = answers[q.id]
            db.session.add(Answer(response_id=resp.id, question_id=q.id, rating=item["rating"], answer_text=item["text"]))
        log("survey_submitted", "survey:" + str(s.id))
        db.session.commit()
        session.pop("survey_state", None)
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
        "password": os.environ.get("SMTP_PASSWORD", ""),
    }
    if config and config.password_encrypted:
        try:
            result["password"] = smtp_fernet().decrypt(config.password_encrypted.encode()).decode()
        except Exception:
            app.logger.error("Não foi possível descriptografar a senha SMTP configurada")
            result["password"] = ""
    return result

@app.route("/admin/settings/smtp", methods=["GET", "POST"])
@roles("master")
def smtp_settings():
    config = SMTPConfig.query.order_by(SMTPConfig.id).first()
    if request.method == "POST":
        host = request.form.get("host", "").strip()
        from_address = request.form.get("from_address", "").strip()
        username = request.form.get("username", "").strip()
        try:
            port = int(request.form.get("port", "587"))
            if not 1 <= port <= 65535:
                raise ValueError()
        except (TypeError, ValueError):
            flash("Informe uma porta SMTP entre 1 e 65535.", "error")
            return render_template("smtp_settings.html", settings=smtp_form_values(config), password_saved=bool(config and config.password_encrypted) or bool(os.environ.get("SMTP_PASSWORD")))
        if not config:
            config = SMTPConfig()
            db.session.add(config)
        config.host = host[:255]
        config.port = port
        config.tls = request.form.get("tls") == "on"
        config.username = username[:255]
        config.from_address = from_address[:255]
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
    return render_template("smtp_settings.html", settings=smtp_form_values(config), password_saved=bool(config and config.password_encrypted) or bool(os.environ.get("SMTP_PASSWORD")))

def smtp_form_values(config):
    return {
        "host": config.host if config and config.host else os.environ.get("SMTP_HOST", ""),
        "port": config.port if config else os.environ.get("SMTP_PORT", "587"),
        "tls": config.tls if config else os.environ.get("SMTP_TLS", "1") == "1",
        "username": config.username if config and config.username else os.environ.get("SMTP_USER", ""),
        "from_address": config.from_address if config and config.from_address else os.environ.get("SMTP_FROM", ""),
    }

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
        return True
    except Exception:
        app.logger.exception("Falha ao enviar recibo de pesquisa")
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
                "shuffle_questions": "BOOLEAN NOT NULL DEFAULT FALSE",
            },
            "question": {
                "answer_type": "VARCHAR(20) NOT NULL DEFAULT 'rating'",
                "notice": "TEXT NOT NULL DEFAULT ''",
            "choices": "TEXT NOT NULL DEFAULT '[]'",
            "branch_question_id": "INTEGER",
            "branch_value": "VARCHAR(255) NOT NULL DEFAULT ''",
            },
            "answer": {"answer_text": "TEXT"},
            "respondent_identity": {
                "eligibility_cnpj": "VARCHAR(14) NOT NULL DEFAULT ''",
                "token_hash": "VARCHAR(64)",
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
