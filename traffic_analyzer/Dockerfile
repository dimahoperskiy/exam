FROM python:3.9-slim
WORKDIR /app
COPY traffic_analyzer.py /app/
RUN pip install flask requests prometheus-client
CMD ["python", "traffic_analyzer.py"]
