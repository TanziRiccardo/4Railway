# APNs PHP Microservice (Railway)

Microservizio PHP per inviare notifiche **Apple Push Notification (APNs)** via HTTP/2.
Progettato per essere usato da un backend (es. Altervista) che **non può** parlare direttamente con APNs.

## Endpoints
- `GET /` → health check
- `POST /push` → invio push a più token  
  Body JSON:
  ```json
  { "tokens": ["<token1>", "<token2>"], "message": "Test" }
