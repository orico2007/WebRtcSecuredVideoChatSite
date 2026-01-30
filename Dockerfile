FROM python:3.11-slim

WORKDIR /app

# If signaling uses websockets, install it
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 34535 8000
