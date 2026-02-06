# 08_security_auth - Authentication & Authorization

> Production-grade security system demonstrating OAuth2, JWT, RBAC, and security best practices.

## 🎯 Overview

This module implements:

- **OAuth2** - Social and enterprise SSO
- **JWT** - Token-based authentication
- **RBAC** - Role-based access control
- **MFA** - Multi-factor authentication
- **Audit Logging** - Security event tracking

## 📁 Structure

```
08_security_auth/
├── src/
│   ├── oauth/               # OAuth2 providers
│   │   ├── google.py        # Google OAuth
│   │   ├── github.py        # GitHub OAuth
│   │   └── saml.py          # SAML SSO
│   ├── jwt/                 # JWT handling
│   │   ├── tokens.py        # Token generation
│   │   └── middleware.py    # Auth middleware
│   ├── rbac/                # Access control
│   │   ├── permissions.py   # Permission system
│   │   └── policies.py      # Authorization policies
│   ├── mfa/                 # Multi-factor auth
│   └── audit/               # Audit logging
├── tests/                   # Security tests
└── pyproject.toml           # Dependencies
```

## 🚀 Quick Start

```bash
pip install -e .
python -m src.main
```

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    AUTHENTICATION                           │
│        OAuth2 │ JWT │ MFA │ Password                        │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                   AUTHORIZATION                             │
│          RBAC │ Policies │ Resource Guards                  │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                   AUDIT & COMPLIANCE                        │
│        Event Logging │ Access History │ Reports             │
└─────────────────────────────────────────────────────────────┘
```

## 📄 License

MIT
