import jwt
from utils.config_parser import config_data
from flask import jsonify, request, Flask

class NoProtectedDataError(Exception):
    pass

def get_jwt_token(request):
    jwt_token = request.args.get('protected_data')
    if not jwt_token:
        raise NoProtectedDataError('No obligatory protected_data param provided')

def get_from_jwt(jwt_token, label):
    secret = config_data('jwt', 'secret')
    full_jwt = jwt.decode(jwt_token, "my-secret", algorithms=["HS256"])
    return full_jwt[label]
