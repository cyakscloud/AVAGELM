FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md main.py ./
COPY src ./src
ENV PYTHONPATH=/app/src PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
EXPOSE 8765
CMD ["python", "main.py", "--dashboard", "--output", "/data/artifacts", "--port", "8765"]
