# Apify Actor image for AgentVerify. Build context is the repository root (see actor.json).
# No secrets are baked in; the optional signing key arrives as a secret run input.
FROM apify/actor-python:3.13

COPY requirements-actor.txt ./
RUN pip install -r requirements-actor.txt

COPY app ./app
COPY agentverify_client ./agentverify_client
COPY apify_actor ./apify_actor
COPY LICENSE ./

CMD ["python", "-m", "apify_actor"]
