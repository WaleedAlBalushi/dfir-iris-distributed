# Validation Plan

1. Install DB role and confirm PostgreSQL health.
2. Install APP role and verify remote PostgreSQL authentication before starting IRIS.
3. Confirm all application containers are running.
4. Confirm HTTPS redirects to `/dashboard`.
5. Create a customer/case and verify persistence.
6. Restart application stack and verify data remains.
7. Restart database stack and verify data remains.
8. Stop database and confirm application reports DB failure.
9. Start database and confirm application recovery.
10. Run DB backup and test a restore in a disposable environment.
11. Run application support bundle and confirm secrets are redacted.
12. Test Wazuh/OpenCTI integration only after the base distributed platform is stable.
