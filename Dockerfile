FROM python:3.11-slim

WORKDIR /app

# Копіюємо requirements та встановлюємо залежності
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копіюємо весь проект у контейнер
COPY . .

EXPOSE 8000

# Запуск Flask через Python
CMD ["python", "app.py"]
