FROM python:3.11-slim

WORKDIR /app

COPY hermes_phish_detect.py .

ENV GMAIL_USER_1=aldinoaja@gmail.com
ENV GMAIL_USER_2=suprimaaldino@gmail.com

CMD ["python", "hermes_phish_detect.py"]