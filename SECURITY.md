# Security policy

Report vulnerabilities through this repository's private vulnerability reporting
form on its Security tab. Do not put vulnerabilities or session material in a
public issue. Include the affected version, a synthetic reproducer and expected
impact; omit passwords, tokens, cookies and article content.

Use the latest published release. Security fixes are published in a new version;
older releases may not receive backports.

## Trust boundaries

Each configured user has an independent bearer token, session store, browser
profile directory, archive and export directory. User URLs are routing labels;
knowing one never grants access. Tokens grant full access to that user's news
data. Administrators of the host can access every user's data: this is a trusted
self-hosted installation, not protection against a malicious administrator.

Sign-in links are short-lived capabilities. Share them only with their intended
user. The person enters credentials in the publisher's page; Newsclip does not
collect passwords or verification codes. Sessions and profiles remain sensitive
even after sign-in. Keep the browser service on a private network, and use HTTPS
when the relay is accessed remotely. Never expose VNC ports.

See [deployment](docs/DEPLOYMENT.md) for network and storage configuration, and
[authentication](docs/AUTHENTICATION.md) for browser restrictions and limitations.
