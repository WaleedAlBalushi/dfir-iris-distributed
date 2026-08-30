# DFIR-IRIS Distributed Architecture

## Initial two-server target

```text
Users
  |
  | HTTPS 443
  v
IRIS Application Server
  - Nginx
  - IRIS App
  - IRIS Worker
  - RabbitMQ
  |
  | PostgreSQL TCP 5432
  v
IRIS Database Server
  - PostgreSQL
```

The application server is the only user-facing IRIS host. PostgreSQL is exposed only on the selected database interface and should be restricted by network controls to the application server.

## Application-side internal flow

```text
Nginx -> App:8000
App/Worker -> PostgreSQL:<configured port>
App/Worker -> RabbitMQ
Worker -> App:8000
```

## Design rules

- Database data is persistent on the DB server.
- IRIS shared application volumes remain on the application server in version 1.
- Database and application roles have separate management scripts.
- Wazuh and OpenCTI integrations live on the application server only.
- Deep hardening and HA are later phases; version 1 performs basic safety checks and avoids exposing secrets in normal status output.
