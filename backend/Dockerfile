# =============================================================================================
# DOCKERFILE - BUILD INSTRUCTIONS FOR THE API CONTAINER
# =============================================================================================
# This file tells Docker how to build an image for your FastAPI application.
# Think of it like a recipe to create a custom Linux box with Python + your code.
#
# CONNECTION: docker-compose.yml references this file with "build: context: ./backend"
# RESULT: Creates an image that can run your FastAPI app in isolation
# =============================================================================================

# Start from a small official Python image (has Python installed)
# This is a pre-made Linux environment with Python 3.12 already installed
FROM python:3.12-slim

# Set working directory inside the container (like "cd /app")
# All subsequent commands run from this directory
WORKDIR /app

# -------------------------
# LAYER OPTIMIZATION TRICK: Install dependencies first
# -------------------------
# Docker caches each step (layer). If requirements.txt doesn't change,
# Docker reuses the cached layer instead of re-downloading packages.
# This makes rebuilds MUCH faster during development.
COPY backend/requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copy your application code into the image
# This copies app/ from project root → /app/app inside the container
# CONNECTION: This is your Python code from app/main.py
COPY app /app/app

# Make Python print logs immediately (no buffering)
# WHY: Without this, you won't see print() statements in `docker logs` right away
ENV PYTHONUNBUFFERED=1

# Document the listening port (Compose does the actual port mapping)
# This is documentation only - doesn't actually open the port
EXPOSE 8000
