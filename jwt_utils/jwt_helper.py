import jwt


def get_from_jwt(jwt_token, secret, label):
    full_jwt = jwt.decode(jwt_token, secret, algorithms=["HS256"])
    return full_jwt[label]
