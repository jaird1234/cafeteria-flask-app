
FROM python:3.10-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8000
# Usaremos gunicorn con --reload para desarrollo local
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--reload", "--timeout", "120", "app:app"]