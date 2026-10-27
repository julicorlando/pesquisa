import os
os.environ["SECRET_KEY"] = "test-secret-is-only-for-tests-not-production"
os.environ["DATABASE_URL"] = "sqlite://"
import pytest
from app import app, db, User, Merchant, Survey, Question, Response, Answer, valid_cnpj, generate_password_hash

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
