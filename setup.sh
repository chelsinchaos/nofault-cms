#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

echo "Creating folder structure and files..."

######################################
# Content Generation Service
######################################

mkdir -p content_generation_service/templates

cat << 'EOF' > content_generation_service/main.py
from fastapi import FastAPI, HTTPException
from jinja2 import Environment, FileSystemLoader
import aiofiles
import os

app = FastAPI()
env = Environment(loader=FileSystemLoader('templates'))

@app.post("/generate")
async def generate_page(content: dict, page_id: str):
    try:
        template = env.get_template('base.html')
        html_content = template.render(content=content)
        # Ensure output directory exists
        os.makedirs('output', exist_ok=True)
        # Save the static page
        async with aiofiles.open(f'output/{page_id}.html', 'w') as f:
            await f.write(html_content)
        return {"status": "success", "page_id": page_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
EOF

cat << 'EOF' > content_generation_service/templates/base.html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ content.title }}</title>
    <meta name="description" content="{{ content.description }}">
    <link href="/static/css/tailwind.css" rel="stylesheet">
</head>
<body>
    <h1>{{ content.title }}</h1>
    <div>{{ content.body | safe }}</div>
</body>
</html>
EOF

cat << 'EOF' > content_generation_service/Dockerfile
FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
EOF

cat << 'EOF' > content_generation_service/requirements.txt
fastapi
jinja2
aiofiles
uvicorn
EOF

######################################
# IPFS Publishing Service
######################################

mkdir -p ipfs_publishing_service

cat << 'EOF' > ipfs_publishing_service/main.py
from fastapi import FastAPI, HTTPException
import ipfshttpclient
import os

app = FastAPI()

# Connect to local IPFS node
try:
    client = ipfshttpclient.connect('/dns/localhost/tcp/5001/http')
except Exception as e:
    raise Exception("Failed to connect to IPFS daemon: " + str(e))

@app.post("/publish")
async def publish_page(page_id: str):
    try:
        file_path = f'output/{page_id}.html'
        if not os.path.exists(file_path):
            raise HTTPException(status_code=404, detail="Page not found")
        res = client.add(file_path)
        ipfs_hash = res['Hash']
        human_readable_url = f"https://ipfs.io/ipfs/{ipfs_hash}"
        return {"status": "success", "ipfs_hash": ipfs_hash, "url": human_readable_url}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
EOF

cat << 'EOF' > ipfs_publishing_service/Dockerfile
FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8001

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8001"]
EOF

cat << 'EOF' > ipfs_publishing_service/requirements.txt
fastapi
ipfshttpclient
uvicorn
EOF

######################################
# Data Management Service
######################################

mkdir -p data_management_service

cat << 'EOF' > data_management_service/database.py
from sqlalchemy import create_engine, Column, String, Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from cryptography.fernet import Fernet
import os

Base = declarative_base()
KEY = os.getenv('DB_ENCRYPTION_KEY')  # Should be a 32-byte base64-encoded key

cipher_suite = Fernet(KEY)

# Use SQLCipher for SQLite encryption
engine = create_engine('sqlite:///secure_db.sqlite3')
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

class Content(Base):
    __tablename__ = 'content'
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True)
    body = Column(String)

# Create tables
Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
EOF

cat << 'EOF' > data_management_service/main.py
from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from database import get_db, Content, cipher_suite
from pydantic import BaseModel
import os

app = FastAPI()

class ContentRequest(BaseModel):
    title: str
    body: str

class ContentResponse(BaseModel):
    id: int
    title: str
    body: str

@app.post("/add_content", response_model=ContentResponse)
async def add_content(content_request: ContentRequest, db: Session = Depends(get_db)):
    encrypted_body = cipher_suite.encrypt(content_request.body.encode()).decode()
    new_content = Content(title=content_request.title, body=encrypted_body)
    db.add(new_content)
    db.commit()
    db.refresh(new_content)
    return {"id": new_content.id, "title": new_content.title, "body": content_request.body}

@app.get("/get_content/{content_id}", response_model=ContentResponse)
async def get_content(content_id: int, db: Session = Depends(get_db)):
    content = db.query(Content).filter(Content.id == content_id).first()
    if not content:
        raise HTTPException(status_code=404, detail="Content not found")
    decrypted_body = cipher_suite.decrypt(content.body.encode()).decode()
    return {"id": content.id, "title": content.title, "body": decrypted_body}
EOF

cat << 'EOF' > data_management_service/Dockerfile
FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN apt-get update && \\
    apt-get install -y libsqlcipher-dev && \\
    pip install --no-cache-dir -r requirements.txt

COPY . .

# Generate a secure key for encryption
ENV DB_ENCRYPTION_KEY=$(python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")

EXPOSE 8002

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8002"]
EOF

cat << 'EOF' > data_management_service/requirements.txt
fastapi
sqlalchemy
sqlcipher3
cryptography
uvicorn
EOF

######################################
# Feed Aggregation Service
######################################

mkdir -p feed_aggregation_service/grpc_clients

cat << 'EOF' > feed_aggregation_service/main.py
from fastapi import FastAPI, HTTPException
import feedparser
import grpc
from pydantic import BaseModel
import os
import lz4.frame
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from grpc_clients import data_management_pb2, data_management_pb2_grpc

app = FastAPI()

class FeedRequest(BaseModel):
    feed_url: str

# AES-512 key (64 bytes)
AES_KEY = os.getenv('AES_KEY')  # Should be 64 bytes
IV = os.urandom(16)  # 16 bytes IV for AES

@app.post("/fetch_feed")
async def fetch_feed(feed_request: FeedRequest):
    try:
        feed = feedparser.parse(feed_request.feed_url)
        entries = []
        for entry in feed.entries:
            entries.append({
                "title": entry.title,
                "body": entry.summary
            })

        # Set up gRPC channel with encryption and compression
        credentials = grpc.ssl_channel_credentials()
        channel = grpc.secure_channel('data_management_service:8002', credentials)
        stub = data_management_pb2_grpc.DataManagementStub(channel)

        for entry in entries:
            # Prepare message
            content_request = data_management_pb2.ContentRequest(
                title=entry['title'],
                body=entry['body']
            )
            serialized = content_request.SerializeToString()

            # Compress
            compressed = lz4.frame.compress(serialized)

            # Encrypt
            cipher = Cipher(algorithms.AES(AES_KEY.encode()), modes.CFB(IV), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted = encryptor.update(compressed) + encryptor.finalize()

            # Send encrypted message
            encrypted_message = data_management_pb2.EncryptedMessage(data=encrypted)
            response = stub.AddContent(encrypted_message)

        return {"status": "success", "entries_fetched": len(entries)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
EOF

cat << 'EOF' > feed_aggregation_service/data_management.proto
syntax = "proto3";

service DataManagement {
    rpc AddContent(EncryptedMessage) returns (EncryptedMessage);
}

message EncryptedMessage {
    bytes data = 1;
}
EOF

# Generate gRPC code
python -m grpc_tools.protoc -Ifeed_aggregation_service --python_out=feed_aggregation_service/grpc_clients --grpc_python_out=feed_aggregation_service/grpc_clients feed_aggregation_service/data_management.proto

cat << 'EOF' > feed_aggregation_service/Dockerfile
FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV AES_KEY=$(python -c "import os; print(os.urandom(64).hex())")

EXPOSE 8003

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8003"]
EOF

cat << 'EOF' > feed_aggregation_service/requirements.txt
fastapi
feedparser
requests
grpcio
grpcio-tools
lz4
cryptography
uvicorn
EOF

######################################
# Authentication Service
######################################

mkdir -p authentication_service

cat << 'EOF' > authentication_service/main.py
from fastapi import FastAPI, HTTPException
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import os

app = FastAPI()

# Generate or load RSA keys
if not os.path.exists("private_key.pem") or not os.path.exists("public_key.pem"):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )
    public_key = private_key.public_key()
    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open("public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
else:
    with open("private_key.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
        )
    with open("public_key.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

@app.post("/exchange_keys")
async def exchange_keys(client_public_key_pem: str):
    try:
        client_public_key = serialization.load_pem_public_key(client_public_key_pem.encode())

        # Generate AES-512 key
        aes_key = os.urandom(64)  # 512 bits

        # Encrypt AES key with client's public RSA key
        encrypted_aes_key = client_public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Encrypt AES key with server's private RSA key for signature
        signature = private_key.sign(
            aes_key,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return {
            "encrypted_aes_key": encrypted_aes_key.hex(),
            "signature": signature.hex(),
            "server_public_key": public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
EOF

cat << 'EOF' > authentication_service/Dockerfile
FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8004

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8004"]
EOF

cat << 'EOF' > authentication_service/requirements.txt
fastapi
cryptography
uvicorn
EOF

######################################
# Logging and Monitoring Service
######################################

mkdir -p logging_service

cat << 'EOF' > logging_service/main.py
from fastapi import FastAPI, Request
import logging

app = FastAPI()

# Configure logging
logging.basicConfig(filename='service_logs.log', level=logging.INFO,
                    format='%(asctime)s %(levelname)s %(message)s')

logger = logging.getLogger("service_logs")

@app.middleware("http")
async def log_requests(request: Request, call_next):
    logger.info(f"New request: {request.method} {request.url}")
    response = await call_next(request)
    logger.info(f"Response status: {response.status_code}")
    return response

@app.post("/log")
async def receive_log(log_entry: dict):
    logger.info(log_entry)
    return {"status": "logged"}
EOF

cat << 'EOF' > logging_service/Dockerfile
FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8005

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8005"]
EOF

cat << 'EOF' > logging_service/requirements.txt
fastapi
uvicorn
EOF

######################################
# Admin Panel
######################################

mkdir -p admin_panel/admin_panel
mkdir -p admin_panel/cms
mkdir -p admin_panel/templates

# Initialize Django project (assuming django-admin is installed)
cd admin_panel
django-admin startproject admin_panel .
django-admin startapp cms
cd ..

cat << 'EOF' > admin_panel/admin_panel/settings.py
"""
Django settings for admin_panel project.

Generated by 'django-admin startproject' using Django 3.x.

For the full list of settings and their values, see
https://docs.djangoproject.com/en/3.x/ref/settings/
"""

import os
from pathlib import Path

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve(strict=True).parent.parent

SECRET_KEY = 'your-secret-key'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = []

# Application definition

INSTALLED_APPS = [
    'cms',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'tailwind',
    'theme',
    'django_browser_reload',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django_browser_reload.middleware.BrowserReloadMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'admin_panel.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / "templates"],  # Add your templates directory
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',  # Required by Django Tailwind
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'admin_panel.wsgi.application'

# Database
# Use SQLite for simplicity

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

# Static files (CSS, JavaScript, Images)

STATIC_URL = '/static/'
STATICFILES_DIRS = [
    BASE_DIR / "static",
]

# Tailwind CSS configuration

TAILWIND_APP_NAME = 'theme'

INTERNAL_IPS = [
    '127.0.0.1',
]

EOF

cat << 'EOF' > admin_panel/cms/models.py
from django.db import models
from django.contrib.auth.models import AbstractUser

class User(AbstractUser):
    # Additional fields if necessary
    pass

class Content(models.Model):
    title = models.CharField(max_length=255)
    body = models.TextField()
    # Add other fields as necessary

    def __str__(self):
        return self.title
EOF

cat << 'EOF' > admin_panel/cms/admin.py
from django.contrib import admin
from .models import User, Content
from django.contrib.auth.admin import UserAdmin

admin.site.register(User, UserAdmin)
admin.site.register(Content)
EOF

cat << 'EOF' > admin_panel/Dockerfile
FROM python:3.9-slim

ENV PYTHONUNBUFFERED 1

WORKDIR /app

COPY requirements.txt .
RUN apt-get update && \\
    apt-get install -y nodejs npm && \\
    pip install --no-cache-dir -r requirements.txt && \\
    npm install -g tailwindcss

COPY . .

EXPOSE 8006

CMD ["gunicorn", "admin_panel.wsgi:application", "--bind", "0.0.0.0:8006"]
EOF

cat << 'EOF' > admin_panel/requirements.txt
django
djangorestframework
django-tailwind
gunicorn
EOF

######################################
# Top-level requirements.txt
######################################

cat << 'EOF' > requirements.txt
fastapi
jinja2
aiofiles
uvicorn
ipfshttpclient
sqlalchemy
sqlcipher3
cryptography
feedparser
requests
grpcio
grpcio-tools
lz4
django
djangorestframework
django-tailwind
gunicorn
EOF

######################################
# Docker Compose File
######################################

cat << 'EOF' > docker-compose.yml
version: '3.8'
services:
  content_generation:
    build: ./content_generation_service
    ports:
      - "8000:8000"
    depends_on:
      - data_management

  ipfs_publishing:
    build: ./ipfs_publishing_service
    ports:
      - "8001:8001"
    depends_on:
      - content_generation

  data_management:
    build: ./data_management_service
    ports:
      - "8002:8002"

  feed_aggregation:
    build: ./feed_aggregation_service
    ports:
      - "8003:8003"
    depends_on:
      - data_management

  authentication:
    build: ./authentication_service
    ports:
      - "8004:8004"

  logging:
    build: ./logging_service
    ports:
      - "8005:8005"

  admin_panel:
    build: ./admin_panel
    ports:
      - "8006:8006"
    depends_on:
      - data_management
EOF

echo "Setup complete! All directories and files have been created."
