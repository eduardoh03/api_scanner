# Vulnerability Scanner API

API REST assíncrona para escaneamento de vulnerabilidades em domínios e IPs.

Construída com **FastAPI**, **Celery**, **PostgreSQL**, **Redis** e **Docker**.

## Módulos de Scanning

| Módulo | Descrição |
|--------|-----------|
| **Port Scanner** | Escaneia portas abertas via asyncio, identifica serviços e portas de risco |
| **Header Analyzer** | Verifica headers de segurança HTTP (HSTS, CSP, X-Frame-Options, etc.) |
| **SSL/TLS Checker** | Valida certificado, expiração, versão TLS e cipher suites |
| **DNS Recon** | Enumera registros DNS, verifica SPF/DKIM/DMARC |
| **CVE Lookup** | Detecta tecnologias e busca CVEs na API do NIST NVD |

## Quick Start

```bash
# Clone o repositório
git clone https://github.com/eduardoh03/scanner-api.git
cd scanner-api

# Suba os containers
docker compose up --build

# Acesse a documentação
open http://localhost:8000/docs
```

## Endpoints

| Método | Endpoint | Descrição |
|--------|----------|-----------|
| `POST` | `/auth/register` | Registrar usuário |
| `POST` | `/auth/login` | Login (retorna JWT) |
| `POST` | `/scans` | Criar scan (async) |
| `GET` | `/scans` | Listar scans do usuário |
| `GET` | `/scans/{id}` | Detalhes + findings do scan |
| `GET` | `/health` | Health check |

## Arquitetura

```
FastAPI (REST API) → Celery (Workers) → Scanner Modules
      ↕                    ↕
  PostgreSQL            Redis (Broker)
```

## Stack

- **Python 3.12** + **FastAPI**
- **Celery** + **Redis** (task queue)
- **PostgreSQL** + **SQLAlchemy** (async)
- **Docker Compose**
- **JWT** authentication

## Exemplo de Resposta

```json
{
  "id": "a1b2c3d4",
  "target": "exemplo.com",
  "status": "completed",
  "risk_score": 72,
  "findings": [
    {
      "module": "ssl_checker",
      "severity": "high",
      "title": "TLS 1.0 habilitado",
      "description": "O servidor aceita conexões TLS 1.0, considerado inseguro.",
      "recommendation": "Desabilitar TLS 1.0 e 1.1, manter apenas TLS 1.2+"
    }
  ]
}
```
