from flask_restful import Resource,reqparse
from models.usuario import UserModel
from flask_jwt_extended import create_access_token,jwt_required,get_jwt
from werkzeug.security import safe_str_cmp
from blacklist import BLACKLIST


atributos = reqparse.RequestParser()
atributos.add_argument('login',type=str,required=True,help="The field 'login' cannot be left blank")
atributos.add_argument('senha',type=str,required=True,help="The field 'senha' cannot be left blank")

class User(Resource):
    #/usuario/user_id
    def get(self,user_id):
        user = UserModel.find_user(user_id)
        if user:
            return user.json()
        return {'message':'User not foud.'},404 #not found
    
    @jwt_required()
    def delete(self,user_id):
        user = UserModel.find_user(user_id)
        if user:
            try:
                user.delete_user()
            except:
                return {'message':'An error ocurred trying user hotel'},500
            return {'message':'user deleted'}
            
        return {'message':'User not found.'},404

class UserRegister(Resource):
    #/cadastro
    def post(self):

        dados = atributos.parse_args()

        if UserModel.find_by_login(dados['login']):
            return{"message":"The login '{}'already exists.".format(dados['login'])}
        
        user = UserModel(**dados)
        user.save_user()
        return{"message":"user created soccessfully!"},201


class UserLogin(Resource):

    @classmethod
    def post(cls):
        dados = atributos.parse_args()

        user = UserModel.find_by_login(dados['login'])

        if user and safe_str_cmp(user.senha,dados['senha']):#safe_str_cmp se usa pra fazer uma comparação de maneira mais segura
            token_de_acesso = create_access_token(identity=user.user_id)
            return {'acess_token':token_de_acesso},200
        return {'message':'The username or password is incorrect.'},401#inauthorize

class UserLogout(Resource):
    @jwt_required()#precisa do () atualmente   
    def post(self):
        jwt_id = get_jwt()['jti']#JWT Token Identifier
        BLACKLIST.add(jwt_id)
        return {'message':'Logged out soccessfully!'},200
