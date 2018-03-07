authorizations = {
    "apikey": {
        "type": "apiKey",
        "in": "header",
        "name": "Authorization",
        "scheme": "bearer",
        "bearerFormat": "JWT"
    },
    "session-cookie": {
        "type": "apiKey",
        "in": "cookie",
        "name": "session"
    }
}
