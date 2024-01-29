from flask import Flask, jsonify, request
from flask_restful import Api, Resource
from pymongo import MongoClient
import bcrypt

app = Flask(__name__)
api = Api(app)

client = MongoClient("mongodb://db:27017")
db = client.BankAPI
users = db["Users"]

def UserExists(username):
    if users.count_documents({"Username":username}) == 0:
        return False
    else:
        return True
    
class Register(Resource):
    def post(self):
        # Obtenemos el registro del usuario
        postedData = request.get_json()

        # Le pedimos al usuario un nombre y contraseña
        username = postedData["username"]
        password = postedData["password"]

        # Verificamos si el usuario existe
        if UserExists(username):
            retJson = ({
                "status": 301,
                "message" : "Usuario no valido"
            })
            return jsonify(retJson)
        
        # Hasheamos la password
        hashed_pw = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())

        # Almacenamos el usuario en la base
        users.insert_one({
            "Username" : username,
            "Password": hashed_pw,
            "Own": 0,
            "Debt": 0
        })

        # Si todo sale bien, informamos con 200 ok
        retJson = ({
                "status": 200,
                "message" : "Usuario creado correctamente"
            })
        return jsonify(retJson)
   
def verifyPw(username, password):
    if not UserExists(username):
        return False
    
    hashed_pw = users.find({
        "Username": username
    })[0]["Password"]

    if bcrypt.hashpw(password.encode('utf8'), hashed_pw) == hashed_pw:
        return True

    else:
        return False
    
def cashWithUser(username):
    cash = users.find({
        "Username": username
    })[0]["Own"]

    return cash

def debtWithUser(username):
    debt = users.find({
        "Username": username
    })[0]["Debt"]

    return debt

def generateReturnDictionary(status, msg):
    retJson = {
        "status": status,
        "msg": msg
    }
    return retJson

def verifyCredentials(username, password):
    if not UserExists(username):
        return generateReturnDictionary(301, "Usuario Invalido"), True
    
    correct_pw = verifyPw(username, password)

    if not correct_pw:
        return generateReturnDictionary(302, "Contraseña Invalida"), True

    return None, False

def updateAccount(username, balance):
    users.update_one({
        "Username": username
    },{
        "$set":{
            "Own": balance
        }
    })

def updateDebt(username, balance):
    users.update_one({
        "Username": username
    },{
        "$set":{
            "Debt": balance
        }
    })


class Add(Resource):
    def post(self):

        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["password"]
        money = postedData["amount"]

        retJson, error = verifyCredentials(username, password)
        if error:
            return jsonify(retJson)

        if money<=0:
            return jsonify(generateReturnDictionary(304, "El dinero ingresado debe de ser mayo a 0"))

        cash = cashWithUser(username)
        money-= 1 # se le cobra una comision
        # Agrega la comision a la cuenta del user bank
        bank_cash = cashWithUser("BANK")
        updateAccount("BANK", bank_cash+1)

        #Se le agrega el monto menos la comision
        updateAccount(username, cash+money)

        return jsonify(generateReturnDictionary(200, "Dinero ingresado correctamente"))


class Transfer(Resource):
    def post(self):

        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["password"]
        to = postedData["to"]
        money = postedData["amount"]

        retJson, error = verifyCredentials(username, password)

        if error:
            return jsonify(retJson)
        
        cash = cashWithUser(username)
        if cash <= 0:
            return jsonify(generateReturnDictionary(304, "No se puede realizar la transferencia, te quedaste sin dinero"))
        
        if not UserExists(to):
            return jsonify(generateReturnDictionary(301, "Usuario no valido para hacer la operacion"))
        
        cash_from = cashWithUser(username)
        cash_to = cashWithUser(to)
        bank_cash = cashWithUser("BANK")

        updateAccount("BANK", bank_cash+1)
        updateAccount(to, cash_to + money - 1)
        updateAccount(username, cash_from - money)

        return jsonify(generateReturnDictionary(200, "Dinero transferido correctamente"))
    
class Balance(Resource):
    def post(self):

        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["password"]

        retJson, error = verifyCredentials(username, password)

        if error:
            return jsonify(retJson)
            
        retJson = users.find({
            "Username": username
        }, {
            "Password": 0,
            "_id": 0
        })[0]

        return jsonify(retJson)

class TakeLoan(Resource):
    def post(self):

        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["password"]
        money = postedData["amount"]

        retJson, error = verifyCredentials(username, password)

        if error:
            return jsonify(retJson)
            
        cash = cashWithUser(username)
        debt = debtWithUser(username)
        updateAccount(username, cash + money)
        updateDebt(username, debt + money)

        return jsonify(generateReturnDictionary(200, "Prestamo añadido a su cuenta"))
        

class PayLoan(Resource):
    def post(self):

        postedData = request.get_json()

        username = postedData["username"]
        password = postedData["password"]
        money = postedData["amount"]

        retJson, error = verifyCredentials(username, password)

        if error:
            return jsonify(retJson)
            
        cash = cashWithUser(username)

        if cash < money:
            return jsonify(generateReturnDictionary(303, "No hay suficiente dinero en tu cuenta"))
        
        debt = debtWithUser(username)

        updateAccount(username, cash - money)
        updateDebt(username, debt - money)

        return jsonify(generateReturnDictionary(200, "La deuda se pago correctamente"))

api.add_resource(Register, '/register')
api.add_resource(Add, '/add')
api.add_resource(Transfer, '/transfer')
api.add_resource(Balance, '/balance')
api.add_resource(TakeLoan, '/takeloan')
api.add_resource(PayLoan, '/payloan')

if __name__ == "__main__":
    app.run(host='0.0.0.0')