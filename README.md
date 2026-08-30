# DFIR-IRIS Distributed Installer v1

This package turns the tested IRIS split into a role-based installer for a two-server deployment.

## Target architecture

```text
Users
  |
  | HTTPS 443
  v
Application Server
  - Nginx
  - IRIS App
  - IRIS Worker
  - RabbitMQ
  |
  | PostgreSQL TCP 5432
  v
Database Server
  - PostgreSQL
```

## Start

```bash
chmod +x install.sh
sudo ./install.sh
```

The installer offers:

1. Database Server
2. Application Server
3. Single-Node / Lab

The distributed roles generate different `setup.sh` management consoles.

## Recommended deployment order

### 1. Database server

Run `install.sh`, choose **Database Server**, and complete the prompts.

The installer creates:

```text
/opt/iris-db/
├── .env
├── .iris-role
├── docker-compose.yml
├── setup.sh
├── backups/
└── secrets/
    └── application-connection.env
```

The connection file is sensitive and is mode `600`. It can be securely copied to the application server and imported during application installation.

Database management menu:

```text
1) Database Services
2) Backup & Restore
3) Health & Connectivity
4) Storage & Connections
5) Configuration & Maintenance
0) Exit
```

### 2. Application server

Run the same `install.sh`, choose **Application Server**, then either enter DB details manually or import `application-connection.env`.

The installer verifies network connectivity and PostgreSQL authentication before deploying IRIS.

The application installation contains the official DFIR-IRIS repository checkout plus the distributed compose and management files:

```text
/opt/iris-web/
├── .env
├── .iris-role
├── docker-compose.distributed-app.yml
├── setup.sh
├── lib/
│   └── legacy_runtime.sh
├── integrations/
│   └── integration_tools.sh
├── secrets/
│   └── initial-credentials.txt
└── ... official DFIR-IRIS repository files ...
```

Application management menu:

```text
1) IRIS Services
2) Integrations
3) Health & Diagnostics
4) Configuration & Security
5) Backup & Maintenance
6) Upgrade Tools
0) Exit
```

## Management commands

Database examples:

```bash
/opt/iris-db/setup.sh status
/opt/iris-db/setup.sh doctor
/opt/iris-db/setup.sh backup
/opt/iris-db/setup.sh connections
```

Application examples:

```bash
/opt/iris-web/setup.sh status
/opt/iris-web/setup.sh doctor
/opt/iris-web/setup.sh db-test
/opt/iris-web/setup.sh backup-app
/opt/iris-web/setup.sh wazuh
/opt/iris-web/setup.sh opencti
```

## Integration functionality

The application-side Wazuh and OpenCTI implementation is modularized from the previously tested `setup.sh`, rather than being re-created from scratch. The top-level management interface and distributed platform logic are new.

This preserves the existing capabilities such as Wazuh remote bundles, local-container integration, Wazuh Markdown patch/test/rollback, and the OpenCTI bridge, preflight, dry-run/live-write controls, timer, IRIS enrichment module, rollback and support-bundle tooling.

## Basic security choices in v1

- Database and application roles are separated.
- PostgreSQL binds to a selected server interface/port instead of requiring a Docker-shared network.
- `.env` and credential files are mode `600`.
- Normal information/status output hides secrets.
- Application installation validates remote DB connectivity/authentication before deployment.
- Internal App/Worker/RabbitMQ services are not published to the host.
- Support bundles use a sanitized environment file.
- Destructive DB restore requires explicit `RESTORE` confirmation.
- Automatic cross-version upgrades are intentionally not implemented without reviewing official upgrade/schema requirements.

## Important production notes

Version 1 is intended for architecture validation and the first controlled server deployment. Before declaring production readiness, review at least:

- host/network firewall rules restricting PostgreSQL to the application server;
- trusted TLS certificates instead of repository development certificates;
- database transport TLS if required by the environment;
- OS and Docker hardening;
- centralized backup retention and restore testing;
- monitoring and alerting;
- secrets-vault integration;
- HA/failover requirements.

The inherited Wazuh integration still contains the earlier single-customer routing model when generating a standard bundle. The multi-tenant routing redesign should be implemented and tested separately rather than silently changing tenant behavior in this first distributed-build version.

See `docs/ARCHITECTURE.md` and `docs/TEST_PLAN.md`.

## Automatic Docker bootstrap (v1.1)
If Docker is not installed, `install.sh` now detects that condition and installs Docker Engine and the Docker Compose plugin automatically. On systemd hosts it also attempts to enable and start the Docker service. Supported package-manager families for prerequisite installation are APT, DNF, and YUM.
