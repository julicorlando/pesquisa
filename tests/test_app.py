import os
import io
import hashlib
import zipfile
from datetime import datetime, timezone, timedelta
import app as app_module
os.environ["SECRET_KEY"] = "test-secret-is-only-for-tests-not-production"
os.environ["DATABASE_URL"] = "sqlite://"
import pytest
from app import app, db, limiter, User, Merchant, Survey, SurveyInvite, SurveyAlert, AlertSettings, SectorGoal, ReportSchedule, SMTPConfig, SystemIncident, Question, Response, Answer, ActionPlan, ParticipantFollowup, RespondentIdentity, Audit, valid_cnpj, valid_cpf, generate_password_hash, now, classify_comment, send_due_invite_reminders, survey_is_open, effective_smtp_settings

@pytest.fixture()
def client():
    app.config.update(TESTING=True, WTF_CSRF_ENABLED=False, RATELIMIT_ENABLED=False)
    limiter.enabled = False
    with app.app_context():
        db.create_all()
        yield app.test_client()
        db.session.remove()
        db.drop_all()

def signin(client, username, password):
    return client.post("/login", data={"username":username,"password":password}, follow_redirects=True)

def test_root(client):
    assert client.get("/").status_code == 200

def test_roles_and_no_identity_leak(client):
    with app.app_context():
        db.session.add(User(username="com", password_hash=generate_password_hash("long-test-pass"),role="comercial"))
        db.session.add(Survey(title="T",slug="t",active=True,target="publico"))
        db.session.commit()
        s=Survey.query.filter_by(slug="t").first()
        q=Question(survey_id=s.id,sector="Comercial",text="Atendimento?",position=1)
        db.session.add(q)
        db.session.commit()
        for x in range(3):
            r=Response(survey_id=s.id,owner_name="NOME SIGILOSO",email="privado@example.com")
            db.session.add(r)
            db.session.flush()
            db.session.add(Answer(response_id=r.id,question_id=q.id,rating=4))
        db.session.commit()
    signin(client,"com","long-test-pass")
    body=client.get("/dashboard").get_data(as_text=True)
    assert "4.0" in body
    assert "NOME SIGILOSO" not in body
    assert "privado@example.com" not in body
    assert client.get("/admin/responses").status_code == 403
    assert client.get("/audit").status_code == 403

def test_unauthorized_merchant_is_not_recorded_as_response(client):
    with app.app_context():
        db.session.add(Survey(title="T",slug="t",active=True,target="lojista"))
        db.session.commit()
        s=Survey.query.filter_by(slug="t").first()
        db.session.add(Question(survey_id=s.id,sector="Comercial",text="Teste?",position=1))
        db.session.commit()
    res=client.post("/p/t",data={"stage":"identity","store_name":"Loja","email":"a@b.com","cnpj":"00000000000000","owner_name":"Qualquer"})
    assert res.status_code == 200
    assert "Obrigado" in res.get_data(as_text=True)
    with app.app_context():
        assert Response.query.count() == 0

def test_step_by_step_page_and_not_auto_submitted(client):
    with app.app_context():
        s=Survey(title="T",slug="t",active=True,target="publico")
        db.session.add(s);db.session.flush()
        db.session.add(Question(survey_id=s.id,sector="TI",text="Wi-Fi?",position=1))
        db.session.commit()
    client.post("/p/t",data={"stage":"identity","email":"a@example.com"})
    page=client.get("/p/t/responder")
    assert page.status_code == 200
    assert b"Wi-Fi?" in page.data
    with app.app_context():
        assert Response.query.count() == 0

def test_invalid_cnpj():
    assert not valid_cnpj("00000000000000")
    assert not valid_cnpj("123")

def test_nps_dashboard_uses_promoters_minus_detractors(client):
    with app.app_context():
        db.session.add(User(username="aud", password_hash=generate_password_hash("long-test-pass"), role="auditoria"))
        survey=Survey(title="NPS",slug="nps",active=True,target="publico")
        db.session.add(survey);db.session.flush()
        q=Question(survey_id=survey.id,sector="Geral",text="Recomendaria?",position=1,answer_type="nps")
        db.session.add(q);db.session.flush()
        for score in (9,10,6):
            response=Response(survey_id=survey.id)
            db.session.add(response);db.session.flush()
            db.session.add(Answer(response_id=response.id,question_id=q.id,rating=score))
        db.session.commit()
    signin(client,"aud","long-test-pass")
    page=client.get("/dashboard?sector=Geral")
    assert page.status_code == 200
    assert b"33" in page.data and b"NPS" in page.data

def test_conditional_question_can_be_skipped_server_side(client):
    with app.app_context():
        survey=Survey(title="Condicional",slug="cond",active=True,target="publico")
        db.session.add(survey);db.session.flush()
        parent=Question(survey_id=survey.id,sector="Geral",text="Nota?",position=1)
        db.session.add(parent);db.session.flush()
        db.session.add(Question(survey_id=survey.id,sector="Geral",text="Detalhe",position=2,branch_question_id=parent.id,branch_value="5"))
        db.session.commit()
    client.post("/p/cond",data={"stage":"identity"})
    response=client.post("/p/cond/responder",data={"q_1":"1","confirm":"yes"})
    assert response.status_code == 200
    with app.app_context():
        assert Response.query.filter_by(survey_id=1).count() == 1
        assert Answer.query.count() == 1

def test_optional_question_can_be_left_blank(client):
    with app.app_context():
        db.session.add(User(username="author", password_hash=generate_password_hash("long-test-pass"), role="auditoria"))
        survey=Survey(title="Opcional",slug="optional",active=True,target="publico")
        db.session.add(survey);db.session.flush()
        db.session.add(Question(survey_id=survey.id,sector="Geral",text="Obrigatória",position=1))
        db.session.commit()
    signin(client,"author","long-test-pass")
    edit=client.post("/admin/surveys/1",data={"kind":"question","sector":"Geral","text":"Opcional","answer_type":"open","optional":"on"})
    assert edit.status_code == 302
    with app.app_context():
        assert Question.query.filter_by(text="Opcional").first().optional is True
    assert b"Pergunta opcional" in client.get("/admin/surveys/1").data
    client.post("/p/optional",data={"stage":"identity"})
    page=client.get("/p/optional/responder")
    assert b"data-optional=\"true\"" in page.data
    assert b"Opcional" in page.data
    response=client.post("/p/optional/responder",data={"q_1":"4","confirm":"yes","device_submitted_at":"2026-10-27T14:30:00Z","device_timezone":"America/Recife"})
    assert response.status_code == 200
    with app.app_context():
        assert Response.query.filter_by(survey_id=1).count() == 1
        assert Answer.query.count() == 1
        assert Answer.query.first().question_id == 1
        saved_response = Response.query.first()
        assert saved_response.device_submitted_at.isoformat().startswith("2026-10-27T14:30:00")
        assert saved_response.device_timezone == "America/Recife"

def test_action_plan_and_qr_code_routes(client):
    with app.app_context():
        db.session.add(User(username="master", password_hash=generate_password_hash("long-test-pass"), role="master"))
        db.session.add(Survey(title="Plano",slug="plano",active=True,target="publico"))
        db.session.commit()
    signin(client,"master","long-test-pass")
    edit=client.get("/admin/surveys/1")
    assert edit.status_code == 200 and b"Baixar QR Code" in edit.data
    image=client.get("/admin/surveys/1/qrcode.png")
    assert image.status_code == 200 and image.mimetype == "image/png"
    saved=client.post("/action-plans",data={"survey_id":"1","sector":"Geral","title":"Revisar acesso","priority":"alta","status":"aberto"},follow_redirects=True)
    assert saved.status_code == 200 and b"Revisar acesso" in saved.data
    with app.app_context():
        assert ActionPlan.query.count() == 1

def test_survey_period_is_saved_in_brasilia_time_and_blocks_public_access(client):
    with app.app_context():
        db.session.add(User(username="master", password_hash=generate_password_hash("long-test-pass"), role="master"))
        db.session.add(Survey(title="Agendada", slug="agendada", active=True, target="publico"))
        db.session.commit()
    signin(client, "master", "long-test-pass")
    response = client.post("/admin/surveys/1", data={
        "kind": "settings", "title": "Agendada", "target": "publico", "identity_type": "none",
        "starts_at": "2099-04-01T09:00", "ends_at": "2099-04-30T18:00", "active": "on"
    })
    assert response.status_code == 302
    with app.app_context():
        survey = db.session.get(Survey, 1)
        assert survey.starts_at.isoformat().startswith("2099-04-01T12:00")
    public = client.get("/p/agendada")
    assert public.status_code == 200 and b"Esta pesquisa n\xc3\xa3o est\xc3\xa1 recebendo respostas" in public.data
    home = client.get("/")
    assert b"Agendada" not in home.data

def test_master_can_clear_responses_without_deleting_survey_questions_or_action_plans(client):
    with app.app_context():
        db.session.add(User(username="master", password_hash=generate_password_hash("long-test-pass"), role="master"))
        survey = Survey(title="Preservar", slug="preservar", active=True, target="publico")
        db.session.add(survey); db.session.flush()
        question = Question(survey_id=survey.id, sector="Geral", text="Pergunta", position=1)
        db.session.add(question); db.session.flush()
        response = Response(survey_id=survey.id)
        db.session.add(response); db.session.flush()
        db.session.add(Answer(response_id=response.id, question_id=question.id, rating=5))
        db.session.add(RespondentIdentity(survey_id=survey.id, document_type="cpf", document_number="12345678901"))
        db.session.add(ActionPlan(survey_id=survey.id, sector="Geral", title="Plano", priority="alta", status="aberto"))
        db.session.commit()
    signin(client, "master", "long-test-pass")
    result = client.post("/admin/surveys/1/clear-responses", follow_redirects=True)
    assert result.status_code == 200 and b"perguntas foram preservadas" in result.data
    with app.app_context():
        assert Survey.query.count() == 1
        assert Question.query.count() == 1
        assert ActionPlan.query.count() == 1
        assert Response.query.count() == 0
        assert Answer.query.count() == 0
        assert RespondentIdentity.query.count() == 0

def test_dashboard_drilldown_shows_question_level_distributions(client):
    with app.app_context():
        db.session.add(User(username="master", password_hash=generate_password_hash("long-test-pass"), role="master"))
        survey = Survey(title="Detalhada", slug="detalhada", active=True, target="publico")
        db.session.add(survey); db.session.flush()
        rating = Question(survey_id=survey.id, sector="Geral", text="Nota geral", position=1, answer_type="rating")
        choice = Question(survey_id=survey.id, sector="Geral", text="Opção", position=2, answer_type="single", choices='["Sim", "Não"]')
        opened = Question(survey_id=survey.id, sector="Geral", text="Comentário", position=3, answer_type="open")
        db.session.add_all([rating, choice, opened]); db.session.flush()
        for _ in range(3):
            response = Response(survey_id=survey.id, device_submitted_at=datetime(2026, 10, 27, 14, 30, tzinfo=timezone.utc), device_timezone="America/Recife")
            db.session.add(response); db.session.flush()
            db.session.add_all([
                Answer(response_id=response.id, question_id=rating.id, rating=4),
                Answer(response_id=response.id, question_id=choice.id, rating=0, answer_text='["Sim"]'),
                Answer(response_id=response.id, question_id=opened.id, rating=0, answer_text="Bom atendimento"),
            ])
        db.session.commit()
    signin(client, "master", "long-test-pass")
    page = client.get("/dashboard?survey=1")
    assert page.status_code == 200
    assert b"Perguntas e respostas da pesquisa" in page.data
    assert b"Nota geral" in page.data and b"Coment\xc3\xa1rio" in page.data
    assert b"Bom atendimento" in page.data and b"Sim" in page.data

def test_dashboard_alerts_offer_direct_action_plan(client):
    with app.app_context():
        db.session.add(User(username="park", password_hash=generate_password_hash("long-test-pass"), role="estacionamento"))
        survey = Survey(title="Alerta", slug="alerta", active=True, target="publico")
        db.session.add(survey); db.session.flush()
        question = Question(survey_id=survey.id, sector="Estacionamento", text="Facilidade para estacionar?", position=1, answer_type="rating")
        db.session.add(question); db.session.flush()
        for _ in range(3):
            response = Response(survey_id=survey.id, submitted_at=now())
            db.session.add(response); db.session.flush()
            db.session.add(Answer(response_id=response.id, question_id=question.id, rating=2))
        db.session.commit()
    signin(client, "park", "long-test-pass")
    page = client.get("/dashboard")
    assert page.status_code == 200 and b"Avalia\xc3\xa7\xc3\xb5es baixas" in page.data
    with app.app_context():
        alert = SurveyAlert.query.one()
        alert_id = alert.id
    saved = client.post("/action-plans", data={"alert_id": str(alert_id), "survey_id": "1", "sector": "Estacionamento", "title": "Revisar estacionamento", "description": "Verificar notas baixas", "priority": "alta", "status": "aberto"}, follow_redirects=True)
    assert saved.status_code == 200
    with app.app_context():
        alert = db.session.get(SurveyAlert, alert_id)
        assert alert.action_plan_id is not None
        assert ActionPlan.query.count() == 1

def test_dashboard_compares_months_and_matching_questions_across_surveys(client):
    with app.app_context():
        db.session.add(User(username="aud", password_hash=generate_password_hash("long-test-pass"), role="auditoria"))
        current = Survey(title="Atual", slug="atual", active=True, target="publico")
        comparison = Survey(title="Comparação", slug="comparacao", active=True, target="publico")
        db.session.add_all([current, comparison]); db.session.flush()
        q1 = Question(survey_id=current.id, sector="Geral", text="Atendimento", position=1, answer_type="rating")
        q2 = Question(survey_id=comparison.id, sector="Geral", text="Atendimento", position=1, answer_type="rating")
        db.session.add_all([q1, q2]); db.session.flush()
        for question, rating, age in [(q1, 4, 4), (q1, 2, 40), (q2, 5, 4)]:
            for _ in range(3):
                response = Response(survey_id=question.survey_id, submitted_at=now() - timedelta(days=age))
                db.session.add(response); db.session.flush()
                db.session.add(Answer(response_id=response.id, question_id=question.id, rating=rating))
        db.session.commit()
    signin(client, "aud", "long-test-pass")
    page = client.get("/dashboard?survey=1&compare_survey=2")
    assert page.status_code == 200
    assert b"M\xc3\xaas atual" in page.data and b"Pesquisa selecionada" in page.data
    assert b"melhorou" in page.data

def test_xlsx_export_respects_login_and_contains_filtered_question_sheets(client):
    with app.app_context():
        db.session.add(User(username="master", password_hash=generate_password_hash("long-test-pass"), role="master"))
        survey = Survey(title="Exportar", slug="exportar", active=True, target="publico")
        db.session.add(survey); db.session.flush()
        question = Question(survey_id=survey.id, sector="Geral", text="Qual sua opinião?", position=1, answer_type="open")
        db.session.add(question); db.session.flush()
        for _ in range(3):
            response = Response(survey_id=survey.id)
            db.session.add(response); db.session.flush()
            db.session.add(Answer(response_id=response.id, question_id=question.id, rating=0, answer_text="Ótimo atendimento"))
        db.session.commit()
    assert client.get("/dashboard/export.xlsx?survey=1").status_code == 302
    signin(client, "master", "long-test-pass")
    result = client.get("/dashboard/export.xlsx?survey=1")
    assert result.status_code == 200
    with zipfile.ZipFile(io.BytesIO(result.data)) as book:
        assert "xl/worksheets/sheet1.xml" in book.namelist()
        assert "xl/worksheets/sheet2.xml" in book.namelist()
        comments_sheet = book.read("xl/worksheets/sheet2.xml").decode()
        assert "Qual sua opinião?" in comments_sheet
        assert "Ótimo atendimento" in comments_sheet

def test_pdf_export_requires_login_and_returns_a_pdf(client):
    with app.app_context():
        db.session.add(User(username="master", password_hash=generate_password_hash("long-test-pass"), role="master"))
        survey = Survey(title="Relatório", slug="relatorio", active=True, target="publico")
        db.session.add(survey); db.session.flush()
        question = Question(survey_id=survey.id, sector="Geral", text="Como foi?", position=1, answer_type="rating")
        db.session.add(question); db.session.flush()
        for rating in (3, 4, 5):
            response = Response(survey_id=survey.id)
            db.session.add(response); db.session.flush()
            db.session.add(Answer(response_id=response.id, question_id=question.id, rating=rating))
        db.session.commit()
    assert client.get("/dashboard/export.pdf?survey=1").status_code == 302
    signin(client, "master", "long-test-pass")
    result = client.get("/dashboard/export.pdf?survey=1&sector=Geral")
    assert result.status_code == 200 and result.mimetype == "application/pdf"
    assert result.data.startswith(b"%PDF-")

def test_survey_document_limit_blocks_duplicate_and_keeps_identity_separate(client):
    cpf = "52998224725"
    assert valid_cpf(cpf)
    with app.app_context():
        survey = Survey(title="Uma resposta", slug="uma-resposta", active=True, target="publico", identity_type="cpf", response_limit="document")
        db.session.add(survey); db.session.flush()
        question = Question(survey_id=survey.id, sector="Geral", text="Nota?", position=1)
        db.session.add(question)
        db.session.add(RespondentIdentity(survey_id=survey.id, document_type="cpf", document_number=cpf, token_hash=None))
        db.session.commit()
    page = client.post("/p/uma-resposta", data={"stage": "identity", "document_number": cpf}, follow_redirects=True)
    assert page.status_code == 200 and b"j\xc3\xa1 recebeu uma resposta" in page.data
    with app.app_context():
        assert RespondentIdentity.query.count() == 1
        assert Response.query.count() == 0

def test_tracked_invitation_updates_aggregate_participation_without_answer_link(client):
    token = "convite-individual"
    with app.app_context():
        survey = Survey(title="Rastreada", slug="rastreada", active=True, target="publico")
        db.session.add(survey); db.session.flush()
        db.session.add(Question(survey_id=survey.id, sector="Geral", text="Nota?", position=1))
        invite = SurveyInvite(survey_id=survey.id, email="invite@example.com", reminder_sent_at=now(), response_token_hash=hashlib.sha256(token.encode()).hexdigest())
        db.session.add(invite); db.session.commit()
    client.get("/p/rastreada?invite=" + token)
    started = client.post("/p/rastreada?invite=" + token, data={"stage": "identity"})
    assert started.status_code == 302
    submitted = client.post("/p/rastreada/responder", data={"q_1": "5", "confirm": "yes"})
    assert submitted.status_code == 200
    with app.app_context():
        invite = SurveyInvite.query.one()
        assert invite.responded_at is not None
        assert Response.query.count() == 1 and Answer.query.count() == 1
        assert not hasattr(invite, "response_id")

def test_comment_theme_classifier_handles_multiple_topics():
    assert set(classify_comment("A vaga estava suja e a cancela demorou")) == {"Estacionamento", "Limpeza"}

def test_master_can_adjust_alert_thresholds_and_low_score_rule_uses_them(client):
    with app.app_context():
        db.session.add(User(username="master", password_hash=generate_password_hash("long-test-pass"), role="master"))
        survey=Survey(title="Limites",slug="limites",active=True,target="publico")
        db.session.add(survey);db.session.flush()
        question=Question(survey_id=survey.id,sector="Estacionamento",text="Nota?",position=1,answer_type="rating")
        db.session.add(question);db.session.flush()
        for rating in (3, 3):
            response=Response(survey_id=survey.id,submitted_at=now())
            db.session.add(response);db.session.flush()
            db.session.add(Answer(response_id=response.id,question_id=question.id,rating=rating))
        db.session.commit()
    signin(client,"master","long-test-pass")
    result=client.post("/admin/alerts/settings",data={"nps_drop_points":"15","low_score_threshold":"2","low_score_max":"3","minimum_sample":"4"},follow_redirects=True)
    assert result.status_code==200 and b"Limites dos alertas atualizados" in result.data
    page=client.get("/dashboard")
    assert page.status_code==200 and b"Avalia\xc3\xa7\xc3\xb5es baixas" in page.data
    with app.app_context():
        settings=db.session.get(AlertSettings,1)
        assert (settings.nps_drop_points,settings.low_score_threshold,settings.low_score_max,settings.minimum_sample)==(15,2,3,4)
        assert Audit.query.filter_by(event="alert_settings_update").count()==1

def test_sector_goal_appears_only_to_profiles_with_sector_access(client):
    period=now().astimezone(app_module.RECIFE_TZ).strftime("%Y-%m")
    with app.app_context():
        db.session.add(User(username="parking",password_hash=generate_password_hash("long-test-pass"),role="estacionamento"))
        survey=Survey(title="Meta",slug="meta",active=True,target="publico")
        db.session.add(survey);db.session.flush()
        question=Question(survey_id=survey.id,sector="Estacionamento",text="Avaliação",position=1,answer_type="rating")
        db.session.add(question);db.session.flush()
        db.session.add_all([SectorGoal(survey_id=survey.id,sector="Estacionamento",period_key=period,metric="average",target=4.0),
            SectorGoal(sector="Marketing",period_key=period,metric="average",target=4.5)])
        for rating in (4,5,4):
            response=Response(survey_id=survey.id,submitted_at=now())
            db.session.add(response);db.session.flush()
            db.session.add(Answer(response_id=response.id,question_id=question.id,rating=rating))
        db.session.commit()
    signin(client,"parking","long-test-pass")
    page=client.get("/dashboard")
    assert page.status_code==200 and b"Meta atingida" in page.data
    assert b"Marketing" not in page.data
    assert client.get("/admin/goals").status_code==403

def test_survey_audit_records_changed_fields_without_question_content(client):
    with app.app_context():
        db.session.add(User(username="master",password_hash=generate_password_hash("long-test-pass"),role="master"))
        db.session.add(Survey(title="Original",slug="audit",active=False,target="publico"))
        db.session.commit()
    signin(client,"master","long-test-pass")
    result=client.post("/admin/surveys/1",data={"kind":"settings","title":"Novo nome","description":"Descrição","target":"publico","identity_type":"none","response_limit":"none","active":"on","shuffle_questions":"on"})
    assert result.status_code==302
    with app.app_context():
        event=Audit.query.filter_by(event="survey_update").one()
        assert "changed_fields:title" in event.detail and "Novo nome" not in event.detail

def test_scheduled_report_command_sends_aggregate_pdf_once(monkeypatch,client):
    sent=[]
    class FakeSMTP:
        def __init__(self,*args,**kwargs): pass
        def __enter__(self): return self
        def __exit__(self,*args): pass
        def starttls(self): pass
        def login(self,*args): pass
        def send_message(self,message): sent.append(message)
    monkeypatch.setattr(app_module.smtplib,"SMTP",FakeSMTP)
    monkeypatch.setattr(app_module,"now",lambda: datetime(2026,10,27,11,5,tzinfo=timezone.utc))
    with app.app_context():
        db.session.add(ReportSchedule(recipient_email="gestor@example.com",sector="Estacionamento",frequency="weekly",weekday=1,month_day=1,send_hour=8))
        db.session.add(SMTPConfig(host="smtp.example.com",port=587,tls=True,from_address="noreply@example.com"))
        db.session.commit()
    runner=app.test_cli_runner()
    first=runner.invoke(args=["send-scheduled-reports"])
    second=runner.invoke(args=["send-scheduled-reports"])
    assert first.exit_code==0 and "Relatórios enviados: 1" in first.output
    assert second.exit_code==0 and "Relatórios enviados: 0" in second.output
    assert len(sent)==1 and sent[0]["To"]=="gestor@example.com"
    attachment=list(sent[0].iter_attachments())[0]
    assert attachment.get_content_type()=="application/pdf"
    with app.app_context():
        schedule=ReportSchedule.query.one()
        assert schedule.last_sent_period=="W:2026-44"
        assert Audit.query.filter_by(event="report_schedule_sent").count()==1

def test_keyboard_accessibility_is_present_on_public_survey(client):
    with app.app_context():
        survey=Survey(title="Acessível",slug="a11y",active=True,target="publico")
        db.session.add(survey);db.session.flush()
        db.session.add(Question(survey_id=survey.id,sector="Geral",text="Pergunta?",position=1))
        db.session.commit()
    home=client.get("/")
    assert b"Pular para o conte\xc3\xbado principal" in home.data
    client.post("/p/a11y",data={"stage":"identity"})
    page=client.get("/p/a11y/responder")
    assert page.status_code==200 and b"aria-valuenow" in page.data and b"tabindex=\"-1\"" in page.data


def test_whatsapp_required_is_validated_and_stored_separately(client):
    with app.app_context():
        survey = Survey(title="WhatsApp obrigatório", slug="whatsapp-obrigatorio", active=True,
                        target="publico", whatsapp_mode="required")
        db.session.add(survey); db.session.flush()
        db.session.add(Question(survey_id=survey.id, sector="Geral", text="Avaliação?", position=1))
        db.session.commit()
    invalid = client.post("/p/whatsapp-obrigatorio", data={"stage":"identity"})
    assert invalid.status_code == 200
    assert "número de WhatsApp válido" in invalid.get_data(as_text=True)
    with app.app_context():
        assert RespondentIdentity.query.count() == 0
    client.post("/p/whatsapp-obrigatorio", data={"stage":"identity", "whatsapp_number":"(81) 99999-1234"})
    with app.app_context():
        participant = RespondentIdentity.query.one()
        assert participant.whatsapp_number == "(81) 99999-1234"
        assert Response.query.count() == 0

def test_whatsapp_optional_and_disabled_modes(client):
    with app.app_context():
        optional = Survey(title="WhatsApp opcional", slug="wa-opcional", active=True,
                          target="publico", whatsapp_mode="optional")
        disabled = Survey(title="Sem WhatsApp", slug="wa-desativado", active=True,
                          target="publico", whatsapp_mode="none")
        db.session.add_all([optional, disabled]); db.session.flush()
        db.session.add_all([
            Question(survey_id=optional.id, sector="Geral", text="Avaliação?", position=1),
            Question(survey_id=disabled.id, sector="Geral", text="Avaliação?", position=1),
        ])
        db.session.commit()
    page = client.get("/p/wa-opcional").get_data(as_text=True)
    assert 'name="whatsapp_number"' in page and "opcional" in page
    client.post("/p/wa-opcional", data={"stage":"identity"})
    with app.app_context():
        assert RespondentIdentity.query.filter_by(survey_id=1).one().whatsapp_number == ""
    disabled_page = client.get("/p/wa-desativado").get_data(as_text=True)
    assert 'name="whatsapp_number"' not in disabled_page
    client.post("/p/wa-desativado", data={"stage":"identity", "whatsapp_number":"81999991234"})
    with app.app_context():
        assert RespondentIdentity.query.filter_by(survey_id=2).one().whatsapp_number == ""


class FakeSMTP:
    sent_messages = []

    def __init__(self, *args, **kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def starttls(self):
        pass

    def login(self, *args):
        pass

    def send_message(self, message):
        self.sent_messages.append(message)


def test_master_can_test_saved_smtp_configuration(client, monkeypatch):
    FakeSMTP.sent_messages = []
    monkeypatch.setattr(app_module.smtplib, "SMTP", FakeSMTP)
    with app.app_context():
        db.session.add(User(username="master", password_hash=generate_password_hash("long-test-pass"), role="master"))
        db.session.add(SMTPConfig(host="smtp.example.test", port=25, tls=False, from_address="pesquisa@example.test"))
        db.session.commit()
    signin(client, "master", "long-test-pass")
    response = client.post("/admin/settings/smtp", data={"action": "test", "test_recipient": "destino@example.test"})
    assert response.status_code == 200
    assert b"E-mail de teste enviado" in response.data
    assert len(FakeSMTP.sent_messages) == 1
    assert FakeSMTP.sent_messages[0]["To"] == "destino@example.test"


def test_automatic_reminder_only_sends_for_opted_in_surveys(client, monkeypatch):
    FakeSMTP.sent_messages = []
    monkeypatch.setattr(app_module.smtplib, "SMTP", FakeSMTP)
    with app.app_context():
        db.session.add(SMTPConfig(host="smtp.example.test", port=25, tls=False, from_address="pesquisa@example.test"))
        enabled = Survey(title="Lembrete ligado", slug="lembrete-ligado", active=True, target="publico",
                         automatic_reminders=True, reminder_delay_days=3)
        disabled = Survey(title="Lembrete desligado", slug="lembrete-desligado", active=True, target="publico",
                          automatic_reminders=False, reminder_delay_days=3)
        db.session.add_all([enabled, disabled])
        db.session.flush()
        due = now() - timedelta(days=4)
        db.session.add_all([
            SurveyInvite(survey_id=enabled.id, email="pessoa1@example.test", created_at=due),
            SurveyInvite(survey_id=disabled.id, email="pessoa2@example.test", created_at=due),
        ])
        db.session.commit()
        assert Survey.query.filter_by(active=True).count() == 2
        assert Survey.query.filter_by(automatic_reminders=True).count() == 1
        assert survey_is_open(Survey.query.filter_by(slug="lembrete-ligado").one())
        assert SurveyInvite.query.filter_by(survey_id=enabled.id, responded_at=None, reminder_sent_at=None).count() == 1
        assert effective_smtp_settings()["host"] == "smtp.example.test"
        count = send_due_invite_reminders(now())
        assert count == 1
        invite = SurveyInvite.query.filter_by(survey_id=enabled.id).one()
        assert invite.reminder_sent_at is not None
        assert invite.response_token_hash
        assert SurveyInvite.query.filter_by(survey_id=disabled.id).one().reminder_sent_at is None
    assert len(FakeSMTP.sent_messages) == 1


def test_system_health_is_master_only_and_lists_incidents(client):
    with app.app_context():
        db.session.add(User(username="master", password_hash=generate_password_hash("long-test-pass"), role="master"))
        db.session.add(SystemIncident(component="application", summary="Falha de teste"))
        db.session.commit()
    signin(client, "master", "long-test-pass")
    page = client.get("/admin/system-health")
    assert page.status_code == 200
    assert b"Falha de teste" in page.data

def test_participation_api_returns_aggregate_only(client):
    with app.app_context():
        db.session.add(User(username="master", password_hash=generate_password_hash("long-test-pass"), role="master"))
        survey=Survey(title="Participação",slug="participacao",active=True,target="publico")
        db.session.add(survey);db.session.flush()
        q=Question(survey_id=survey.id,sector="Geral",text="Avalia o serviço?",position=1)
        db.session.add(q);db.session.flush()
        response=Response(survey_id=survey.id)
        db.session.add(response);db.session.flush()
        db.session.add(Answer(response_id=response.id,question_id=q.id,rating=5))
        db.session.commit()
    signin(client,"master","long-test-pass")
    response=client.get("/api/participation")
    assert response.status_code == 200
    body=response.get_json()
    assert body["surveys"][0]["responses"] == 1
    assert "answers" not in body and "email" not in body and "identity" not in body

def test_followup_record_is_separate_from_response(client):
    with app.app_context():
        survey=Survey(title="Retorno",slug="retorno",active=True,target="publico")
        db.session.add(survey);db.session.flush()
        db.session.add(Question(survey_id=survey.id,sector="Geral",text="Como foi sua experiência?",position=1))
        db.session.commit()
    page=client.post("/p/retorno",data={"stage":"identity","email":"respondente@example.com",
        "followup_consent":"on","followup_email":"retorno@example.com","followup_topic":"Problema no estacionamento"})
    assert page.status_code in (200, 302)
    with app.app_context():
        assert ParticipantFollowup.query.count() == 1
        assert Response.query.count() == 0
        item=ParticipantFollowup.query.first()
        assert item.email == "retorno@example.com"
        assert not hasattr(item,"response_id")

def test_survey_review_detects_duplicates_and_vague_questions(client):
    with app.app_context():
        survey=Survey(title="Revisão",slug="revisao",active=False,target="publico")
        db.session.add(survey);db.session.flush()
        db.session.add_all([
            Question(survey_id=survey.id,sector="Geral",text="Atendimento foi bom?",position=1),
            Question(survey_id=survey.id,sector="Geral",text="Atendimento foi bom?",position=2),
        ])
        db.session.commit()
        warnings=app_module.survey_publish_review(survey)
        assert any("repetida" in warning.lower() for warning in warnings)
        assert any("clara" in warning.lower() for warning in warnings)

def test_survey_author_can_disable_participant_followup(client):
    with app.app_context():
        db.session.add(User(username="master", password_hash=generate_password_hash("long-test-pass"), role="master"))
        survey=Survey(title="Pesquisa opcional",slug="retorno-opcional",active=True,target="publico")
        db.session.add(survey);db.session.flush()
        db.session.add(Question(survey_id=survey.id,sector="Geral",text="Como foi sua experiência?",position=1))
        db.session.commit()
        sid=survey.id
    signin(client,"master","long-test-pass")
    page=client.get(f"/admin/surveys/{sid}")
    assert page.status_code == 200
    assert b"retorno ao participante" in page.data.lower()
    response=client.post(f"/admin/surveys/{sid}",data={
        "kind":"settings","title":"Pesquisa opcional","description":"","target":"publico",
        "identity_type":"none","whatsapp_mode":"none","response_limit":"none",
        "reminder_delay_days":"3","save_draft":"yes"
    })
    assert response.status_code == 302
    with app.app_context():
        survey=db.session.get(Survey,sid)
        assert survey.followup_enabled is False
    public=client.get("/p/retorno-opcional")
    assert public.status_code == 200
    assert b"Retorno sobre o problema relatado" not in public.data


def test_non_master_loses_edit_access_after_first_response(client):
    with app.app_context():
        db.session.add(User(username="comercial", password_hash=generate_password_hash("long-test-pass"), role="comercial"))
        survey=Survey(title="Pesquisa publicada",slug="pesquisa-publicada",active=True,target="publico")
        db.session.add(survey);db.session.flush()
        db.session.add(Question(survey_id=survey.id,sector="Geral",text="Como foi a visita?",position=1))
        db.session.add(Response(survey_id=survey.id))
        db.session.commit()
        sid=survey.id
    signin(client,"comercial","long-test-pass")
    edit=client.get(f"/admin/surveys/{sid}")
    assert edit.status_code == 302
    assert edit.location.endswith("/p/pesquisa-publicada")
    assert client.get(f"/admin/surveys/{sid}/questions.csv").status_code == 302
    listing=client.get("/admin/surveys")
    assert listing.status_code == 200
    assert "Edição exclusiva do Master".encode() in listing.data
    assert "Link público".encode() in listing.data

def test_master_can_edit_survey_after_responses(client):
    with app.app_context():
        db.session.add(User(username="master", password_hash=generate_password_hash("long-test-pass"), role="master"))
        survey=Survey(title="Pesquisa publicada",slug="pesquisa-publicada",active=True,target="publico")
        db.session.add(survey);db.session.flush()
        db.session.add(Question(survey_id=survey.id,sector="Geral",text="Como foi a visita?",position=1))
        db.session.add(Response(survey_id=survey.id))
        db.session.commit()
        sid=survey.id
    signin(client,"master","long-test-pass")
    assert client.get(f"/admin/surveys/{sid}").status_code == 200
