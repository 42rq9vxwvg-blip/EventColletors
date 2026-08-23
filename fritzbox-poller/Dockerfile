FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir requests==2.32.3 fritzconnection==1.15.1 tzdata==2024.1

COPY poller.py .

RUN useradd --create-home polleruser
USER polleruser

CMD ["python3", "poller.py"]