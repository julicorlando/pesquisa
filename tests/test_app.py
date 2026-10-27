import os
from datetime import datetime, timezone
os.environ["SECRET_KEY"] = "test-secret-is-only-for-tests-not-production"
os.environ["DATABASE_URL"] = "sqlite://"
import pytest
from app import app, db, User, Merchant, Survey, Question, Response, Answer, ActionPlan, RespondentIdentity, valid_cnpj, generate_password_hash

@pytest.fixture()
def client():
    app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
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
