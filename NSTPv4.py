from struct import *
from collections import defaultdict
import nstp_v4_pb2
import sys
import socket
import _thread
import hashlib
import nacl.secret
import nacl.pwhash
import time
from nacl.bindings.crypto_kx import *
from passlib.hash import *
import passlib.hash


class NSTPv4:
	DEBUG = True

	def __init__(self, address, port, passwordFilePath):
		keypair = crypto_kx_keypair()
		self.publicKey 	= keypair[0]
		self.privateKey = keypair[1]
		self.clientPublicKeys = {}
		self.encryptionBoxes = {}
		self.decryptionBoxes = {}

		self.publicDatabase = {}
		self.privateDatabase = defaultdict(dict)

		self.passwordFilePath = passwordFilePath

		self.numberOfConnections = {}
		self.authenticationAttempts = {}
		self.suspiciousIPs = {}

		self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.socket.bind((address, port))
		self.socket.listen(50)

	def run(self):
		if self.DEBUG:
			print ('Starting server...\n')

		while True:
			clientSocket, clientAddress = self.socket.accept()
			if self.DEBUG:
				print ('Received connection request from ' + str(clientAddress))
			_thread.start_new_thread(self.newClientConnection, (clientSocket, clientAddress))

	def stop(self):
		if self.DEBUG:
			print ('\nStopping server...')
		self.socket.close()

	def getMessageLength(self, clientSocket):
		try:
			msgLength = clientSocket.recv(2)
		except socket.timeout:
			return -2

		if len(msgLength) == 0:
			return -1
		msgLength = int.from_bytes(msgLength, 'big')
		return msgLength

	def recvNSTPMessage(self, clientSocket, clientAddress, msgLength):
		NSTPMessage = nstp_v3_pb2.NSTPMessage()
		msg = clientSocket.recv(msgLength)
		NSTPMessage.ParseFromString(msg)

		if self.DEBUG:
			print ('Received NSTP message from client: ' + str(clientAddress))
			print (str(NSTPMessage))

		return NSTPMessage

	def sendMessage(self, clientSocket, clientAddress, NSTPMessage):
		if self.DEBUG:
			print ('Sending message to client: ' + str(clientAddress))
			print (str(NSTPMessage))			

		data = NSTPMessage.SerializeToString()
		size = len(data)
		msgFormat = '>H' + str(size) + 's'
		packedMessage = pack(msgFormat, size, data)
		clientSocket.sendall(packedMessage)


	def sendErrorMessage(self, clientSocket, clientAddress, message, encrypted = False):
		NSTPMessage = nstp_v3_pb2.NSTPMessage()
		NSTPMessage.error_message.error_message = message

		if self.DEBUG:
			print ('Sending error message (encryption: ' + str(encrypted) + ') to client: ' + str(clientAddress))

		if encrypted:
			DecryptedMessage = nstp_v3_pb2.DecryptedMessage()
			DecryptedMessage.error_message.error_message = message
			NSTPMessage = self.encryptMessage(clientSocket, clientAddress, DecryptedMessage)

		self.sendMessage(clientSocket, clientAddress, NSTPMessage)

		try:
			del self.clientPublicKeys[clientAddress]
		except KeyError:
			pass

		try:
			del self.encryptionBoxes[clientAddress]
		except KeyError:
			pass

		try:
			del self.decryptionBoxes[clientAddress]
		except KeyError:
			pass

		if self.DEBUG:
			print ('Closing connection to client: ' + str(clientAddress))
		self.numberOfConnections[clientAddress[0]] -= 1
		clientSocket.close()

	def encryptMessage(self, clientSocket, clientAddress, DecryptedMessage):
		box = self.encryptionBoxes[clientAddress]
		encryptedMessage = box.encrypt(DecryptedMessage.SerializeToString())

		ciphertext 	= encryptedMessage.ciphertext
		nonce 		= encryptedMessage.nonce

		NSTPMessage = nstp_v3_pb2.NSTPMessage()
		NSTPMessage.encrypted_message.ciphertext 	= ciphertext
		NSTPMessage.encrypted_message.nonce 		= nonce

		return NSTPMessage

	def decryptMessage(self, clientSocket, clientAddress, NSTPMessage):
		box = self.decryptionBoxes[clientAddress]

		ciphertext 	= NSTPMessage.encrypted_message.ciphertext
		nonce 		= NSTPMessage.encrypted_message.nonce

		decrypted = box.decrypt(ciphertext, nonce)
		DecryptedMessage = nstp_v3_pb2.DecryptedMessage()
		DecryptedMessage.ParseFromString(decrypted)
		
		if self.DEBUG:
			print ('DECRYPTED ABOVE MESSAGE TO:')
			print (str(DecryptedMessage))

		return DecryptedMessage

	def newClientConnection(self, clientSocket, clientAddress):
		if clientAddress[0] not in self.numberOfConnections.keys():
			self.numberOfConnections[clientAddress[0]] = 0
		self.numberOfConnections[clientAddress[0]] += 1

		msgLength = self.getMessageLength(clientSocket)

		if msgLength == -1:
			if self.DEBUG:
				print ('Client ' + str(clientAddress) + ' closed connection to server...')
			self.numberOfConnections[clientAddress[0]] -= 1
			clientSocket.close()
			return

		if msgLength == -2:
			if self.DEBUG:
				print ('Closing connection (due to timeout) to client: ' + str(clientAddress))
			self.sendErrorMessage(clientSocket, clientAddress, 'Connection timed out')
			return

		NSTPMessage = self.recvNSTPMessage(clientSocket, clientAddress, msgLength)
		msgType = NSTPMessage.WhichOneof('message_')


		if msgType == 'client_hello':
			publicKey = self.processClientHello(clientSocket, clientAddress, NSTPMessage)
			if publicKey == -1:
				self.sendErrorMessage(clientSocket, clientAddress, 'Major version is not 3.x')
				return
		else:
			self.sendErrorMessage(clientSocket, clientAddress, 'Clients must first send a \'client_hello\' message')
			return

		self.sendServerHello(clientSocket, clientAddress)
		self.clientAuthentication(clientSocket, clientAddress)
		

	def processClientHello(self, clientSocket, clientAddress, NSTPMessage):
		if NSTPMessage.client_hello.major_version != 3:
			return -1

		clientPublicKey = NSTPMessage.client_hello.public_key
		self.clientPublicKeys[clientAddress] = clientPublicKey

		keypair = crypto_kx_server_session_keys(self.publicKey, self.privateKey, clientPublicKey)
		self.encryptionBoxes[clientAddress] = nacl.secret.SecretBox(keypair[1])
		self.decryptionBoxes[clientAddress] = nacl.secret.SecretBox(keypair[0])

		return 0

	def sendServerHello(self, clientSocket, clientAddress):
		NSTPMessage = nstp_v3_pb2.NSTPMessage()
		NSTPMessage.server_hello.major_version 	= 3
		NSTPMessage.server_hello.minor_version 	= 1
		NSTPMessage.server_hello.user_agent 	= 'Krokhmal\'s NSTPv4 server'
		NSTPMessage.server_hello.public_key		= self.publicKey

		self.sendMessage(clientSocket, clientAddress, NSTPMessage)


	def clientAuthentication(self, clientSocket, clientAddress):
		if clientAddress[0] not in self.authenticationAttempts.keys():
			self.authenticationAttempts[clientAddress[0]] = 0

		while True:

			msgLength = self.getMessageLength(clientSocket)

			if msgLength == -1:
				if self.DEBUG:
					print ('Client ' + str(clientAddress) + ' closed connection to server...')
				self.numberOfConnections[clientAddress[0]] -= 1
				clientSocket.close()
				return

			if msgLength == -2:
				if self.DEBUG:
					print ('Closing connection (due to timeout) to client: ' + str(clientAddress))
				self.sendErrorMessage(clientSocket, clientAddress, 'Connection timed out')
				return

			NSTPMessage = self.recvNSTPMessage(clientSocket, clientAddress, msgLength)
			msgType = NSTPMessage.WhichOneof('message_')

			if msgType != 'encrypted_message':
				self.sendErrorMessage(clientSocket, clientAddress, 'Message must be encrypted duing authentication', encrypted = True)
				return

			authenticated, username = self.processAuthenticationRequest(clientSocket, clientAddress, NSTPMessage)
			if authenticated == -1:
				self.sendErrorMessage(clientSocket, clientAddress, 'Message is not an authentication request', encrypted = True)
				return

			if clientAddress[0] in self.suspiciousIPs.keys():
				time.sleep(3 * self.numberOfConnections[clientAddress[0]])

			if self.DEBUG:
				print('Authenticated: ' + str(authenticated))
			self.sendAuthenticationResponse(clientSocket, clientAddress, authenticated)

			if authenticated:
				self.connectionEstablished(clientSocket, clientAddress, username)
				return

			if self.authenticationAttempts[clientAddress[0]] >= 10:
				self.suspiciousIPs[clientAddress[0]] = True

			self.authenticationAttempts[clientAddress[0]] += 1

	def processAuthenticationRequest(self, clientSocket, clientAddress, NSTPMessage):
		DecryptedMessage = self.decryptMessage(clientSocket, clientAddress, NSTPMessage)

		msgType = DecryptedMessage.WhichOneof('message_')
		if msgType != 'auth_request':
			return -1, -1

		username = DecryptedMessage.auth_request.username
		password = DecryptedMessage.auth_request.password

		authenticated = self.checkDatabase(username, password)

		return authenticated, username

	def checkDatabase(self, username, password):
		passwordFile = open(self.passwordFilePath)
		lines = passwordFile.read().splitlines()
		usernameAndPassword = [line.split(':') for line in lines]
		for entry in usernameAndPassword:
			entryUsername		= entry[0]
			entryPasswordHash 	= entry[1]
			hashID 				= entryPasswordHash.split('$')[1]
			if hashID == '1':
				if username == entryUsername and passlib.hash.md5_crypt.verify(password, entryPasswordHash):
					passwordFile.close()
					return True
			if hashID == '5':
				if username == entryUsername and passlib.hash.sha256_crypt.verify(password, entryPasswordHash):
					passwordFile.close()
					return True
			if hashID == '6':
				if username == entryUsername and passlib.hash.sha512_crypt.verify(password, entryPasswordHash):
					passwordFile.close()
					return True
			if hashID == 'argon2id':
				try:
					if username == entryUsername and nacl.pwhash.argon2id.verify(entryPasswordHash.encode('utf-8'), password.encode('utf-8')):
						passwordFile.close()
						return True
				except nacl.exceptions.InvalidkeyError:
					pass
		passwordFile.close()
		return False

	def sendAuthenticationResponse(self, clientSocket, clientAddress, authenticated):
		DecryptedMessage = nstp_v3_pb2.DecryptedMessage()
		DecryptedMessage.auth_response.authenticated = authenticated

		NSTPMessage = self.encryptMessage(clientSocket, clientAddress, DecryptedMessage)
		self.sendMessage(clientSocket, clientAddress, NSTPMessage)

	def connectionEstablished(self, clientSocket, clientAddress, username):
		self.authenticationAttempts[clientAddress[0]] = 0

		while True:
			msgLength = self.getMessageLength(clientSocket)

			if msgLength == -1:
				if self.DEBUG:
					print ('Client ' + str(clientAddress) + ' closed connection to server...')
				self.numberOfConnections[clientAddress[0]] -= 1
				clientSocket.close()
				return

			if msgLength == -2:
				if self.DEBUG:
					print ('Closing connection (due to timeout) to client: ' + str(clientAddress))
				self.sendErrorMessage(clientSocket, clientAddress, 'Connection timed out')
				return

			NSTPMessage = self.recvNSTPMessage(clientSocket, clientAddress, msgLength)
			msgType = NSTPMessage.WhichOneof('message_')
			if msgType != 'encrypted_message':
				self.sendErrorMessage(clientSocket, clientAddress, 'Message must be encrypted duing authentication', encrypted = True)
				return

			DecryptedMessage = self.decryptMessage(clientSocket, clientAddress, NSTPMessage)
			msgType = DecryptedMessage.WhichOneof('message_')

			if msgType == 'auth_request':
				self.sendErrorMessage(clientSocket, clientAddress, 'Client already authenticated', encrypted = True)
				return

			if msgType == 'ping_request':
				dataHash = self.processPingRequest(DecryptedMessage)
				if dataHash == None:
					self.sendErrorMessage(clientSocket, clientAddress, 'Invalid hash algorithm flag', encrypted = True)
					return

				self.sendPingResponse(clientSocket, clientAddress, dataHash)
			elif msgType == 'load_request':
				value = self.processLoadRequest(clientSocket, clientAddress, DecryptedMessage, username)
				self.sendLoadResponse(clientSocket, clientAddress, value)
			elif msgType == 'store_request':
				value = self.processStoreRequest(clientSocket, clientAddress, DecryptedMessage, username)
				self.sendStoreResponse(clientSocket, clientAddress, value)

	def processPingRequest(self, DecryptedMessage):
		data 	= DecryptedMessage.ping_request.data
		hashID 	= DecryptedMessage.ping_request.hash_algorithm

		if hashID == 0:
			dataHash = data
		elif hashID == 1:
			dataHash = hashlib.sha256(data).digest()
		elif hashID == 2:
			dataHash = hashlib.sha512(data).digest()
		else:
			return None

		return dataHash

	def sendPingResponse(self, clientSocket, clientAddress, dataHash):
		DecryptedMessage = nstp_v3_pb2.DecryptedMessage()
		DecryptedMessage.ping_response.hash = dataHash

		NSTPMessage = self.encryptMessage(clientSocket, clientAddress, DecryptedMessage)
		self.sendMessage(clientSocket, clientAddress, NSTPMessage)

	def processLoadRequest(self, clientSocket, clientAddress, DecryptedMessage, username):
		key 	= DecryptedMessage.load_request.key
		public 	= DecryptedMessage.load_request.public

		if public:
			value = self.publicDatabase.get(key, ''.encode('utf-8'))
		else:
			value = self.privateDatabase.get(username, ''.encode('utf-8'))
			if value != ''.encode('utf-8'):
				value = value.get(key, ''.encode('utf-8'))

		return value

	def sendLoadResponse(self, clientSocket, clientAddress, value):
		DecryptedMessage = nstp_v3_pb2.DecryptedMessage()
		DecryptedMessage.load_response.value = value

		NSTPMessage = self.encryptMessage(clientSocket, clientAddress, DecryptedMessage)
		self.sendMessage(clientSocket, clientAddress, NSTPMessage)

	def processStoreRequest(self, clientSocket, clientAddress, DecryptedMessage, username):
		key 	= DecryptedMessage.store_request.key
		value 	= DecryptedMessage.store_request.value
		public 	= DecryptedMessage.store_request.public

		if public:
			self.publicDatabase[key] = value
		else:
			self.privateDatabase[username][key] = value

		return value

	def sendStoreResponse(self, clientSocket, clientAddress, value):
		DecryptedMessage = nstp_v3_pb2.DecryptedMessage()
		DecryptedMessage.store_response.hash 			= hashlib.sha256(value).digest()
		DecryptedMessage.store_response.hash_algorithm 	= 1

		NSTPMessage = self.encryptMessage(clientSocket, clientAddress, DecryptedMessage)
		self.sendMessage(clientSocket, clientAddress, NSTPMessage)


if __name__== "__main__":
	address = sys.argv[1]
	port = int(sys.argv[2])
	configPath = sys.argv[3]
	server = NSTPv4(address, port, configPath)
	try:
		server.run()
	except KeyboardInterrupt:
		server.stop()




