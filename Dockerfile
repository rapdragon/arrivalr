FROM python:3.12-alpine
WORKDIR /app
COPY monitor.py .
CMD ["python", "-u", "monitor.py"]
