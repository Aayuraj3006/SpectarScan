FROM python:3.11-slim

# Set working directory inside the container
WORKDIR /app

# Copy the Python dependencies first (for caching)
COPY requirements.txt .

# Upgrade pip and install dependencies
RUN pip install --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Copy the rest of your project
COPY . .

# Expose the port your app runs on
EXPOSE 10000

# Start command to run FastAPI
CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "10000"]