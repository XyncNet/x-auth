# X-Auth
###### JWT authentication for x-api

JWT cookie based Auth Middleware for ASGI framework.
Stores in user_id, issued and expired dates, user role and blocked state.
When token expired, it is automatically fetching user from db, and if he is not blocked now, then updates issue/expire dates, and user role if it was changed after the last user fetch.

#### Requirements
- Python >= 3.12

### INSTALL
```bash
pip install xn-auth
```

---
Made with ❤ on top of the [X-Model](https://github.com/XyncNet/x-model).
