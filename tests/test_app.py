import os
os.environ["SECRET_KEY"] = "test-secret-is-only-for-tests-not-production"
os.environ["DATABASE_URL"] = "sqlite://"
import pytest
from app import app, db, User, Merchant, Survey, Question, Response, Answer, ActionPlan, valid_cnpj, generate_password_hash

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
