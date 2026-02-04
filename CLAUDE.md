# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

x-auth (`xn-auth` on PyPI) is a JWT cookie-based authentication middleware for Litestar (ASGI framework). It handles Telegram-based authentication via Mini Apps (TMA) and Login Widget (TWA), with automatic token refresh when expired.

## Build & Publish

```bash
# Install dependencies
pip install -e ".[dev]"

# Build package
python -m build

# Publish to PyPI
twine upload dist/*
```

## Architecture

### Authentication Flow

1. **Entry point**: `Auth` class in `controller.py` - initializes `JWTCookieAuth` from Litestar with custom middleware
2. **Endpoints**: `/auth/tma` (Mini App initData) and `/auth/twa` (Login Widget) - both validate Telegram signatures and issue JWT tokens
3. **Token handling**: Custom `Tok` class in `middleware.py` extends `Token` to catch `ExpiredSignatureError` and re-encode with fresh timestamps
4. **Auto-refresh**: `JWTAuthMiddleware` intercepts expired tokens, checks if user is blocked via `User.permissions()`, updates role if changed, and sets new cookie

### Key Components

- **`Auth`** (`controller.py`): Main class instantiated by consuming applications. Pass the Telegram bot token as `sec`, optionally a custom `User` model, excluded paths, and cookie domain.
- **`JWTAuthMiddleware`** (`middleware.py`): Wraps Litestar's `JWTCookieAuthenticationMiddleware`. On `ExpiredSignature`, fetches user permissions from DB and issues refreshed token via `Set-Cookie` header injection.
- **`User`** model (`models.py`): Tortoise ORM model with `tg_upsert()` for login and `permissions()` for token refresh checks. Related to `Username` for Telegram user ID mapping.
- **Role system** (`enums.py`): Bitmask-based roles (`READER=4`, `WRITER=2`, `MANAGER=6`, `ADMIN=7`) using `RoleScope` flags.

### Token Contents

JWT extras stored beyond standard claims:
- `role`: User's current role (refreshed on token renewal)
- `blocked`: Whether user has blocked the bot (checked via `allows_write_to_pm` or `send_chat_action`)

### Dependencies

- `litestar` - ASGI framework (JWT auth support)
- `tortoise-orm` via `xn-model` - Database models
- `aiogram` - Telegram signature validation and bot API
- `kurigram` - Pyrogram fork for session/peer models
- `pyjwt` - JWT encoding/decoding
- `msgspec` - Fast serialization

### Excluded Paths

Default paths excluded from auth: `/schema`, `/auth`, `/public`
