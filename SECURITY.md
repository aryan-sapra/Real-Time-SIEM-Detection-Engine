# Security Notes

This project is a local defensive SIEM lab.

## Responsible use

Use only with logs and systems you are authorized to monitor. The included
`simulate_attack.py` creates synthetic events locally and does not perform
network attacks.

## Secrets

Keep `.env` out of version control. Never commit SMTP passwords, Slack
webhooks, API keys, tokens, certificates, or private keys.

## Reporting a vulnerability

For a real deployment, replace this section with the repository owner's
preferred private disclosure channel before publishing the project.
