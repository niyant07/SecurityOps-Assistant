# SecurityOps Assistant — hosted web version.
#
# Runs in public mode: listens on $PORT and requires the SECURITYOPS_ACCESS_CODE
# access code for every API call. Only public internet targets can be assessed.
#
#   docker build -t securityops .
#   docker run -p 8765:8765 -e SECURITYOPS_ACCESS_CODE=choose-a-long-code securityops

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SECURITYOPS_PUBLIC=1 \
    PORT=8765

WORKDIR /app
# The web app only needs these; PySide6 is for the optional desktop app.
RUN pip install --no-cache-dir "PyYAML>=6.0" "Jinja2>=3.1" "dnspython>=2.4" "anthropic>=0.88"

COPY securityops ./securityops
RUN useradd --create-home appuser
USER appuser

EXPOSE 8765
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import os,urllib.request; urllib.request.urlopen(f'http://127.0.0.1:{os.environ[\"PORT\"]}/healthz', timeout=4)"
CMD ["python", "-m", "securityops", "--no-browser"]
