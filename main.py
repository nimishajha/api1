from flask import Flask,request,jsonify
from elasticsearch import Elasticsearch
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required
from datetime import timedelta

es_host="https://0aac7170aba84621ace3b0167dcedaaa.us-central1.gcp.cloud.es.io"
es_password="jbeLRnSMLaOvgys9Tz0TSd4W"
es_username="elastic"
es_index="user"
app=Flask(__name__)
app.config['JWT_SECRET_KEY'] = '1234'  # Set a secret key for JWT
jwt=JWTManager(app)
bcrypt=Bcrypt(app)
es=Elasticsearch(es_host,basic_auth=(es_username,es_password),verify_certs=False)
maps1={
    "mappings":{
        "properties":{
            "username":{"type":"keyword"},
            "password":{"type":"text"}
        }
    }
}
def check_create_index(es_index):
    if es.indices.exists(index=es_index):
        print("index exists")
    else:
        es.indices.create(index=es_index,body=maps1)
        print("index_created")

check_create_index(es_index)

def hashed_password(password):
    return bcrypt.generate_password_hash(password).decode("utf-8")
def check_password(hash_pass,password):
    return bcrypt.check_password_hash(hash_pass,password)


@app.route("/signup",methods=["POST"])
def signup():
    data=request.json
    username=data.get("username")
    password=data.get("password")

    if not username or not password:
        return jsonify({"message:username or password not found"}),400
    query={"query":{"term":{"username":username}}}
    res=es.search(index=es_index,body=query)
    if res["hits"]["total"]["value"]>0:
        return jsonify({"message":"user already exists"}),400
    
    passwordd=hashed_password(password)
    body={"username":username,"password":passwordd}
    es.index(index=es_index,document=body)
    return jsonify({"message":"user created successfully"}),201

@app.route("/login",methods=["POST"])
def login():
    data=request.json
    username=data.get("username")
    password=data.get("password")
    
    if not username or not password:
        return jsonify({"message":"username or password missing"}),400
    
    query={"query":{"term":{"username":username}}}
    res=es.search(index=es_index,body=query)
    if res["hits"]["total"]["value"]==0:
        return jsonify({"message":"invalid username or password"}),401
    user=res["hits"]["hits"][0]["_source"]
    if not check_password(user["password"],password):
        return jsonify({"message":"invalid password"}),401
    
    access_token=create_access_token(identity=username,expires_delta=timedelta(days=1))
    return jsonify({"token":access_token}),200

@app.route("/protected",methods=["GET"])
@jwt_required
def protected():
    return jsonify({"message":"this is a proteched route"})
if __name__=="__main__":
    app.run(debug=True)

