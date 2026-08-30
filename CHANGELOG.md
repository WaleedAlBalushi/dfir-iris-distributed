# Changelog

## 1.0.0-lab

- Added role-based Database/Application/Single-Node installer.
- Added independent PostgreSQL deployment and remote DB application stack.
- Added DB connection bundle for easier application-server onboarding.
- Added role-specific grouped management menus.
- Added DB backup/restore, storage, connection and maintenance tools.
- Added application doctor, DB auth test, TLS info, security check, app backup and support bundle.
- Modularized the previous Wazuh and OpenCTI integration implementation for the application role.
- Added architecture, validation and known-limitations documentation.

## v1.1.0
- Installer now detects when Docker is missing and installs Docker Engine automatically using Docker's official installation script.
- Installer starts/enables the Docker daemon when possible.
- Installer attempts to install the Docker Compose plugin if it is missing.
- Missing base prerequisites such as curl, git, Python 3, CA certificates, and OpenSSL are installed automatically on supported package managers.
