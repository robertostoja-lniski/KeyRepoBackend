from flask import Flask, request
from flask_restful import Resource, Api

class HelloWorld(Resource):
    def get(self):
        return {'about': 'Hello Worrrrrld!'}

    def post(self):
        some_json = request.get_json()
        return {'you sent': some_json}, 201