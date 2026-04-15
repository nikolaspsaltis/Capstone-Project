FROM python:3.12-slim

WORKDIR /app

# Install dependencies first so this layer is cached independently of code changes
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code and migration files
COPY app/ ./app/
COPY alembic/ ./alembic/
COPY alembic.ini .
COPY policies/ ./policies/

# Apply all database migrations before starting the server
RUN alembic upgrade head

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
