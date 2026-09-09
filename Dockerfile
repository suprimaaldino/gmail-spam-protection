FROM python:3.11-slim

WORKDIR /app

COPY hermes_phish_detect.py .

CMD ["python", "hermes_phish_detect.py", "suprimaaldino@gmail.com", "APP_PASSWORD"]