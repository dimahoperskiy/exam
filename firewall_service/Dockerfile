FROM python:3.9-slim
WORKDIR /app
COPY firewall_service.py /app/
RUN pip install flask prometheus-client
CMD ["python", "firewall_service.py"]
