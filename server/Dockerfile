FROM python:3.11-slim

WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir flask gunicorn \
    && pip install --no-cache-dir --no-deps .

VOLUME ["/data"]
EXPOSE 8780
ENV CATCHME_SERVER_DB=/data/server.db

CMD ["gunicorn", "--chdir", "/app/server", "--bind", "0.0.0.0:8780", "--workers", "1", "--threads", "4", "--timeout", "30", "wsgi:app"]
