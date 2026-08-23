FROM python:3.12-slim
 
WORKDIR /app
 
RUN pip install --no-cache-dir requests==2.32.3
 
COPY relay.py .
 
# Kein root noetig, da Port 6514 (nicht privilegiert) verwendet wird
RUN useradd --create-home relayuser && \
    mkdir -p /var/log && \
    chown -R relayuser:relayuser /var/log
USER relayuser
 
CMD ["python3", "relay.py"]