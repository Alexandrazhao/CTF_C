# Specify the parent image from which we build
FROM python:3.7-slim

# Set the working directory
WORKDIR /app

# Copy files from your host to your current working directory
COPY ./app


# Run the application
CMD exec gunicorn --bind :$PORT --workers 1 --threads 8 --timeout 0 app:app
