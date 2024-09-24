# nofault-cms

## Description

NoFaultCMS is a Python-based, robust, and secure content management system leveraging IPFS for decentralized publishing. Designed with a microservices architecture, it features a comprehensive suite of backend services including content generation, data management with encrypted SQLite3, IPFS publishing, secure authentication, and feed aggregation from platforms like Medium and Substack. The system ensures secure inter-service communication with RSA4096 and AES-512 encryption, all managed with Docker and Kubernetes for fault tolerance and scalability. Ideal for projects demanding high privacy, security, and fault tolerance.

## Prerequisites

- OS === macOS OR Debian/Ubuntu/CentOS
- CPU Architecture === x86 OR ARM or Apple Silicon
- Docker-compose already installed

## Installing

- RUN: chmod +x setup.sh
- RUN: chmod +x helpers/compile.sh && chmod +x helpers/run.sh
- RUN: pip install -r requirements.txt
- RUN: ./setup.py
- RUN: docker-compose up --build