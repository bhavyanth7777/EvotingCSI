import tornado.web
import tornado.httpserver
import tornado.options
import tornado.ioloop
import tornado.websocket
import tornado.httpclient
from tornado import gen
import os.path
import json
import requests
import random
import tornado.escape
from hashlib import sha512
from passlib.hash import pbkdf2_sha256
import re
import datetime
import random
#---------------------------------------------------------------------------

from tornado.options import define, options, parse_command_line
#define('port',address='0.0.0.0',default=8888,type=int)


#---------------------------------------------------------------------------

from pymongo import MongoClient
client = MongoClient()
db = client['Evoting']

#-------------------------------------------------------
class IndexHandler(tornado.web.RequestHandler):
    def get(self):
        if (self.get_secure_cookie('user')):
            self.redirect('/check')
        else:
            self.render('index.html')


class checkLoginHandler(tornado.web.RequestHandler):
    def get(self):
        username = repr(self.get_secure_cookie('user'))
        username = username.split("'")
        username = str(username[1])
        if (username):
            self.db = db
            userCollectionFromDb = self.db.voters.find_one({"UserName":username})
            if userCollectionFromDb:
                self.redirect("/home")
        else:
            self.clear_cookie('user')
            self.clear_cookie('bkey')
            self.redirect('/')

    def post(self):
        if self.get_secure_cookie('user'):
            self.redirect("/home")
        else:
            self.db = db
            username = re.escape(self.get_argument("u"))
            rawPassword = re.escape(self.get_argument("p"))

            ## Password being encrypted with PKBDF2_SHA256 and a salt here and then being checked.

            salted = b'=ruQ3.Xc,G/*i|D[+!+$Mo^gn|kM1m|X[QxDOX-=zptIZhzn,};?-(Djsl,&Fg<r'
            encryptedPassword = pbkdf2_sha256.encrypt(rawPassword, rounds=8000, salt= salted)


            #-----------------------------------------------------------
            # bkey encryption
            concatenatedString = username+rawPassword+str(salted)
            concatenatedString = concatenatedString.encode('utf-8')
            bkey = sha512(concatenatedString)
            bkey = bkey.hexdigest()

            userCollectionFromDb = self.db.voters.find_one({"UserName":username})
            if userCollectionFromDb:

                if encryptedPassword == userCollectionFromDb['Password']:

                    # print(userCollectionFromDb['Name'])
                    ballotID = userCollectionFromDb['EncryptedBallotId']
                    # print ballotID
                    if (self.db.ballots.find_one({"BallotId":ballotID})):
                        ballotFromDB = self.db.ballots.find_one({"BallotId":ballotID})
                        if 'Submitted' in ballotFromDB.keys():
                            ballotFromDBBool = ballotFromDB['Submitted']
                            if ballotFromDBBool is True:
                                self.redirect("/thankyou")
                            else:
                                self.set_secure_cookie('user',username)
                                self.set_secure_cookie('bkey',bkey)
                                self.redirect("/home")
                        else:
                            self.set_secure_cookie('user',username)
                            self.set_secure_cookie('bkey',bkey)
                            self.redirect("/home")
                    else:
                        self.set_secure_cookie('user',username)
                        self.set_secure_cookie('bkey',bkey)
                        self.redirect('/home')
                else:
                    self.redirect('/')
            else:
                self.redirect('/')



class LoginHandler(tornado.web.RequestHandler):
    def get(self):
        self.db = db
        username = repr(self.get_secure_cookie('user'))
        # print type(username)
        if username == "None":
            # print "LOLOLOLOLOOOLOOOL"
            self.redirect("/")
        username = username.split("'")
        username = str(username[1])
        bkey = self.get_secure_cookie('bkey')

        userCollectionFromDb = self.db.voters.find_one({"UserName":username})
        ballotID = userCollectionFromDb['EncryptedBallotId']
        if userCollectionFromDb:
            regionId = userCollectionFromDb['Region']
            regionDoc = self.db.regions.find_one({"RegionId":regionId})
            # print regionDoc
            positions = regionDoc['Positions']

            #------- IP RETRIEVAL-------------
            httpHeaders = repr(self.request)
            httpHeaders = httpHeaders.split(', ')
            ip = httpHeaders[5]
            ip = ip.split('=')
            ip = ip[1].strip('"\'')

            # ips collection, where all the ip requests along with time are logged
            ipDocument = {'Username':username, 'IP':ip, 'Time':repr(datetime.datetime.now())}
            db.ips.insert(ipDocument)
            #----------------------------------
            candidatesList = []
            description = []
            idList = []
            for i in positions:
                # print [x['Name'] for x in db.candidates.find({'Position':i})]
                candidatesList.append([x['Name'] for x in db.candidates.find({'Position':i})])
                description.append([x['Description'] for x in db.candidates.find({'Position':i})])
                idList.append([x['ID'] for x in db.candidates.find({'Position':i})])
            voted = self.db.ballots.find_one({'BallotId':ballotID})
            if (voted):
                voted.pop('_id')
                voted.pop('BallotId')
            else:
                voted = []
            self.render('index2.html',positions=positions,ip=ip,candidatesList=candidatesList, description=description,idList=idList,voted=voted)
        else:
            self.redirect('/')






class LogoutHandler(tornado.web.RequestHandler):
    def get(self):
        self.clear_cookie("user")
        self.redirect('/')

class ThankyouHandler(tornado.web.RequestHandler):
    def get(self):
        self.clear_cookie('user')
        self.clear_cookie('bkey')
        self.render('thankyou.html')
    def post(self):
        self.clear_cookie('user')
        self.clear_cookie('bkey')
        self.render('thankyou.html')

class WSHandler(tornado.websocket.WebSocketHandler):

    def open(self):
        pass
        # print("socket opened server side")

    def on_message(self, message):
        self.db = db
        messageFromClient = json.loads(message)
        messageType = str(messageFromClient['messageType'])
        if messageType == "verifyLoginDetails":
            username = re.escape(messageFromClient['username'])
            rawPassword = re.escape(messageFromClient['password'])

            salted = b'=ruQ3.Xc,G/*i|D[+!+$Mo^gn|kM1m|X[QxDOX-=zptIZhzn,};?-(Djsl,&Fg<r'
            encryptedPassword = pbkdf2_sha256.encrypt(rawPassword, rounds=8000, salt= salted)

            userCollectionFromDb = self.db.voters.find_one({"UserName":username})
            if userCollectionFromDb:
                if encryptedPassword == userCollectionFromDb['Password']:
                    dataDict = {'messageType':'serverVerifiedLoginDetails','verificationStatus':'True', 'message':''}
                    # print "Verified"
                else:
                    dataDict = {'messageType':'serverVerifiedLoginDetails','verificationStatus':'False', 'message':'Wrong Password!'}
            else:
                dataDict = {'messageType':'serverVerifiedLoginDetails','verificationStatus':'False', 'message':'Wrong User Name!'}
            messageToClient = json.dumps(dataDict)
            self.write_message(messageToClient)
        elif messageType == "voted":
            # print 'Enter voted'
            selectedCandidateID = messageFromClient['id']
            selectedCandidateName = messageFromClient['candidateName']
            username = repr(self.get_secure_cookie('user'))
            username = username.split("'")
            username = str(username[1])
            position = str(messageFromClient['position'])
            userFromDB = self.db.voters.find_one({'UserName':username})
            ballotID = userFromDB['EncryptedBallotId']
            ballotFromDB = self.db.ballots.find_one({'BallotId':ballotID})
            if ballotFromDB:

                # print 'Ballot From DB'
                self.db.ballots.update({'BallotId':ballotID}, {"$set": {position:[selectedCandidateID,selectedCandidateName]}},upsert=True)
            else:
                # print 'Inserted'
                self.db.ballots.insert({'BallotId':ballotID, position:[selectedCandidateID,selectedCandidateName]})
            dataDict = {'messageType':'votedVerificaiton', 'message':'Successfully saved your selection!'}
            messageToClient = json.dumps(dataDict)
            self.write_message(messageToClient)
            # print messageToClient
        elif messageType == "getSelectedCandidates":
            # print 'received'
            username = repr(self.get_secure_cookie('user'))
            username = username.split("'")
            username = str(username[1])
            userFromDB = self.db.voters.find_one({'UserName':username})
            ballotID = userFromDB['EncryptedBallotId']
            ballotFromDB = self.db.ballots.find_one({'BallotId':ballotID})
            ballotFromDB.pop('_id')

            dataDict = {'messageType':'selectedCandidate', 'message':ballotFromDB}
            messageToClient = json.dumps(dataDict)
            self.write_message(messageToClient)
            # print messageToClient
        elif messageType == 'submitted':
            # print 'Submitted'
            print("In Submitted")
            username = repr(self.get_secure_cookie('user'))
            username = username.split("'")
            username = str(username[1])
            userFromDB = self.db.voters.find_one({'UserName':username})
            ballotID = userFromDB['EncryptedBallotId']
            self.db.ballots.update({"BallotId":ballotID},{"$set":{'Submitted':True}},upsert=True)


            dataDict = {'messageType':'SubmittedResponse', 'message':''}
            messageToClient = json.dumps(dataDict)
            self.write_message(messageToClient)
            # print messageToClient

    def on_close(self):
        pass
        # print("Socket closed server side")


handlers = [
    (r'/',IndexHandler),
    (r'/ws',WSHandler),
    (r'/check',checkLoginHandler),
    (r'/home',LoginHandler),
    (r'/logout',LogoutHandler),
    (r'/thankyou',ThankyouHandler),
]

#---------------------------------------------------------------------------

if __name__ == "__main__":
    parse_command_line()
    # template path should be given here only unlike handlers
    app = tornado.web.Application(handlers, template_path=os.path.join(os.path.dirname(__file__), "templates"),
                                  static_path=os.path.join(os.path.dirname(__file__), "static"), cookie_secret="61oETzKXQAGaYdkL5gEmGeJJFuYh7EQnp2XdTP1o/Vo=", debug=True)
    http_server = tornado.httpserver.HTTPServer(app)
    http_server.listen(8080, address='0.0.0.0')
    tornado.ioloop.IOLoop.instance().start()
