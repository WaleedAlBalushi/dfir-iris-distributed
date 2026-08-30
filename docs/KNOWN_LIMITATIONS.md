# Known Limitations / Next Improvements

1. **Wazuh tenant routing**: the retained integration generator uses the earlier single IRIS customer ID model. A later revision should use an authoritative tenant map (preferably Wazuh agent-group/customer metadata) and fail closed for unmapped agents.
2. **Firewall automation**: v1 binds PostgreSQL to the selected interface but does not rewrite host firewall/Proxmox rules automatically.
3. **Database TLS**: PostgreSQL transport TLS is not configured by this installer yet.
4. **Application TLS**: the official repository development certificate layout is used initially; production certificates should replace it.
5. **HA**: v1 is two-role separation, not an HA cluster.
6. **Automatic IRIS version upgrade**: intentionally not performed because database/schema upgrade steps must be reviewed per release.
7. **IRIS RBAC source changes**: the previous multi-tenant RBAC limitations are not patched by this infrastructure installer. Those changes should be implemented as controlled source changes with tests after the distributed baseline is stable.
