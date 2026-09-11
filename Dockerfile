FROM python:3.11-slim

WORKDIR /app

COPY hermes_phish_detect.py .

ENV PYTHONUNBUFFERED=1

CMD ["python", "hermes_phish_detect.py"]