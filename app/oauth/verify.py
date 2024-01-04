

from functools import wraps
from flask import request
from app.models.user import User

import jwt



def verify_access_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if "Authorization" in request.headers:
            token = request.headers["Authorization"].split(" ")[1]

        if not token:
            return {
                "error_description": "Access denied",
                "error": "Unauthorized"

            }, 401
        try:
            data = jwt.decode(token, 'secret', algorithms=['HS512'])

            current_user = User.query.get(data["user_id"])
            if current_user is None:
                return {
                    "error_description": "Invalid Access Token",
                    "error": "Unauthorized"

                }, 401
        except Exception as e:
            return {
                "error_description": str(e),
                "error": "internal server error"
            }, 500
        return f(current_user, *args, **kwargs)
    return decorated
