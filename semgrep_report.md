# Semgrep SAST report

- Input files: semgrep-results.json
- Total findings: 6
- Parse errors (non-code): 4

## Findings by severity
| Severity | Count |
|---|---|
| ERROR | 0 |
| WARNING | 6 |
| INFO | 0 |

## Affected files
| File | Findings |
|---|---|
| templates/base.html | 1 |
| templates/login.html | 1 |
| templates/message_new.html | 1 |
| templates/mfa.html | 1 |
| templates/password.html | 1 |
| templates/profile.html | 1 |

## Most important rule IDs
| Rule | Count | Remediation focus |
|---|---|---|
| django-no-csrf-token | 6 | Django rule on a Flask/Jinja template: CSRF is enforced by Flask-WTF (hidden csrf_token field). False positive. |

## Detail
| Severity | Rule | Location | Message |
|---|---|---|---|
| WARNING | django-no-csrf-token | templates/base.html:7 | Manually-created forms in django templates should specify a csrf_token to prevent CSRF attacks. |
| WARNING | django-no-csrf-token | templates/login.html:2 | Manually-created forms in django templates should specify a csrf_token to prevent CSRF attacks. |
| WARNING | django-no-csrf-token | templates/message_new.html:2 | Manually-created forms in django templates should specify a csrf_token to prevent CSRF attacks. |
| WARNING | django-no-csrf-token | templates/mfa.html:4 | Manually-created forms in django templates should specify a csrf_token to prevent CSRF attacks. |
| WARNING | django-no-csrf-token | templates/password.html:2 | Manually-created forms in django templates should specify a csrf_token to prevent CSRF attacks. |
| WARNING | django-no-csrf-token | templates/profile.html:2 | Manually-created forms in django templates should specify a csrf_token to prevent CSRF attacks. |
