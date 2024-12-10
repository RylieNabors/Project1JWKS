from flask import Flask, jsonify, request, render_template_string
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import time

# create variable app that acts as the source of the web application
app = Flask(__name__)

# POST request form that will be displayed on the main page
form_html = '''
	<h1>Send Post Request</h1>
	<form action="/auth" method = POST>
		<label for= "user">User;</label>
		<input type="text" id="user" name="user"><br><br>
		<input type="submit" value="Submit">
	</form>
'''

# dynamic list to store the keys
key_database = []

# function that creates a RSA key pair
def create_rsa_key():
	private_key = rsa.generate_private_key(
		public_exponent=65537,
		key_size=2048,
		backend=default_backend()
	)
	# generate public key from the private key
	public_key = private_key.public_key()
	return private_key, public_key

# function that convets the public key to JWKS format
def convert_to_jwk(pub_key, kid):
	# public_numbers() function verifies the key. It takes a public key and returns
	# n, the modulus of the key and
	# e, the exponent of the key
	public_numbers = pub_key.public_numbers()
	jwk = {
		"kty": "RSA", # key type
		"use": "sig",
		"kid": kid,
		"alg": "RS256",
		# encode n and e in base64 to transmit the data without issues
		"n": jwt.utils.base64url_encode(public_numbers.n.to_bytes(256,'big')).decode('utf-8'),
		"e": jwt.utils.base64url_encode(public_numbers.e.to_bytes(3,'big')).decode('utf-8')
	}
	return jwk

# function that creates and stores rsa keys with an expiration
def generate_keys(default_time=3600):
	priv_key, pub_key = create_rsa_key()
	kid = str(int(time.time())) # uses current timestamp
	jwk = convert_to_jwk(pub_key, kid)

	# store keys with expiration date
	key_database.append({
		'kid' : kid,
		'private_key' : priv_key,
		'public_key' : pub_key,
		'jwk' : jwk,
		# adds current time to 1 hour to determine expiration time
		'expiration_time' : time.time() + default_time
	})

# Function that makes a copy of the list without the expired keys
def get_nonexpired_keys():
	global key_database
	current_time = time.time()
	key_database = [key for key in key_database if key['expiration_time'] > current_time]

# app will initially display POST form.
# when user presses submit, they are guided to /auth endpoint
@app.route('/')
def initial():
	return render_template_string(form_html)

# RESTful JWKS endpoint that serves only unexpired public keys in JWKS format
@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
	get_nonexpired_keys()
	public_keys = [key['jwk'] for key in key_database]
	return jsonify({'keys': public_keys})

# /auth endpoint to issue a signed JWT on a POST request
@app.route('/auth', methods=['POST'])
def issue_jwt():
	# check if "expired" query parameter is present
	# Flask Request object contains attributes of the URL request.
	# args contains arguments from the URL.
	# get() method will either get the string from the dictionary or
	# return "None" if it is not found.
	expired_parameter = request.args.get('expired', None)

	get_nonexpired_keys()

	if expired_parameter:
		# use expired key
		expired_key = next((key for key in key_database if key['expiration_time'] <= time.time()), None)
		if not expired_key:
			return jsonify({'error': 'No expired keys available'}), 400

		private_key = expired_key['private_key']
		kid = expired_key['kid']
		# issue JWT with expired time
		exp_time = int(time.time()) - 3600 # 1 hour expired
	else:
		# use first non-expired key
		valid_key = next((key for key in key_database if key['expiration_time'] > time.time()), None)
		if not valid_key:
			return jsonify({'error': 'No valid keys available'}), 500

		private_key = valid_key['private_key']
		kid = valid_key['kid']
		exp_time = int(time.time()) + 600 # key expires in 10 minutes

	# Serialize the private key for signing
	private_pem = private_key.private_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PrivateFormat.TraditionalOpenSSL,
		encryption_algorithm=serialization.NoEncryption()
	)

	# Create a JWT payload
	payload = {
        	"user": "test_user",
        	"exp": exp_time
    	}

	# Sign the JWT
	token = jwt.encode(payload, private_pem, algorithm="RS256", headers={"kid": kid})

	return jsonify({"token": token})


# automatically generates a new key before each request
@app.before_request
def before():
	generate_keys()

# Start the Flask server on port 8080
# Generates key before server starts.
if __name__ == '__main__':
	generate_keys()
	app.run(port=8080)

