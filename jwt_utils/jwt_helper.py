import jwt
from utils.config_parser import config_data

def get_from_jwt(jwt_token, label):
    secret = config_data('jwt', 'secret')
    full_jwt = jwt.decode(jwt_token, "my-secret", algorithms=["HS256"])
    return full_jwt[label]
