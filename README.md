# Plataforma de Pesquisas — Shopping Carpina

Sistema Flask de pesquisa de satisfação com questionário público, escala de 1 a 5 com expressões faciais, validação de lojistas e gestão por perfis.

## Funcionalidades
- Master cria, edita, ativa e desativa questionários e perguntas; cadastra lojistas e usuários; consulta respostas identificadas e trilhas de auditoria.
- Questionário para público geral ou para lojistas pré-autorizados. Neste último caso, valida CNPJ (dígitos verificadores) e nome completo normalizado perante cadastro do Master.
- Tentativas não autorizadas recebem agradecimento genérico e ficam registradas na auditoria sem gravar respostas.
- Uma pergunta por vez, voltar, notas 1–5, revisão e confirmação.
- Recibo por SMTP com as respostas, quando SMTP estiver configurado.
- Perfis Comercial, Marketing, Operacional, Administrativo, Estacionamento e TI veem somente médias correspondentes, sem identificação e com supressão para amostras inferiores a 3 notas.
- Perfil Auditoria consulta eventos e estatísticas agregadas; somente Master acessa dados identificados.
- Questionário pronto com 41 perguntas por setor. TI restrita ao Mall Wi-Fi público e tecnologia de estacionamento.

## Instalação local

Python 3.12+:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export FLASK_APP=app:app
export SECRET_KEY="$(python -c 'import secrets;print(secrets.token_hex(32))')"
export MASTER_USERNAME=admin
export MASTER_PASSWORD='COLOQUE_UMA_SENHA_FORTE_DE_12_OU_MAIS'
flask init-db
flask create-master
flask seed-survey
flask run
```

No Windows PowerShell, substitua source por .venv\Scripts\Activate.ps1 e configure as variáveis com $env:NOME = "valor".

O questionário é criado inativo para evitar respostas antes da configuração de participantes. Cadastre os lojistas em /admin/merchants e depois ative em /admin/surveys. URL pública: /p/satisfacao-lojistas-shopping-carpina.

## Docker / Coolify
Deploy via Dockerfile, porta interna 8000, TLS, SECRET_KEY fixa, COOKIE_SECURE=1, DATABASE_URL (preferir PostgreSQL) e SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, SMTP_FROM. Executar uma vez os três comandos de inicialização acima. Para múltiplas réplicas configure RATELIMIT_STORAGE_URI com Redis. Configure persistência do banco e backups.

## Acesso
- master: tudo, inclusive dados pessoais e respostas individuais.
- auditoria: auditoria e indicadores agregados; não acessa identidade.
- comercial: Comercial.
- marketing: Marketing.
- operacional: Limpeza, Manutenção, Zeladoria, Lago e Parque das Aves.
- administrativo: Administrativo.
- estacionamento: Estacionamento.
- ti: TI.

## Segurança / limites desta primeira versão
Antes de ambiente de produção, adote migrações de banco, MFA no Master, correio assíncrono com retentativa, gerenciamento de ciclo de vida dos dados pessoais, informações de privacidade/consentimento conforme base legal aplicável (LGPD), backups criptografados e monitoramento. CNPJ + nome completo NÃO garantem identidade de pessoa; para verificação forte, convites individuais com token de uso único e canal previamente validado são recomendados. Agregação com limiar de 3 ajuda, mas pode não impedir reidentificação de lojas em grupos pequenos.

## Testes
```bash
pip install pytest
pytest -q
```
