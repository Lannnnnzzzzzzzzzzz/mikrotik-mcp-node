# OpenCode guidance for this project

Use read-only tools first. If no router is configured, do not guess a target or invent credentials; explain that the MCP can be explored, but router-backed calls need an explicitly configured test router.

Do not apply RouterOS changes unless the user explicitly asks for that change. Inspect any plan and its exact targets and fields first; do not generate or submit apply confirmations unless the user approves that specific plan. Keep write, high-risk, active-diagnostics, and destructive gates off unless the user explicitly asks to change the safety configuration.

Treat scanning, flood ping, speed or bandwidth tests, Wake-on-LAN, packet capture, support bundles, backups, S3 operations, deletion, reboot, and shutdown as consequential. Explain the target and impact and obtain explicit approval before invoking them.

Never put RouterOS passwords, SSH credentials, webhook URLs, or AWS credentials in source files, prompts, or chat. Use a protected process environment or secret store. Do not claim Safe Mode, automatic rollback, or backup restore is available; consult `README.md` for current limitations.
