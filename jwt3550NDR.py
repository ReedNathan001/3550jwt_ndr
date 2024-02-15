
#python3 jwt3550NDR.py to run jwt server
#then pyhton3 jwt-testNDR.py to test with custom suite or
#go run main.go project1 -p 8080 to test with grade-bot

from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from urllib.parse import urlparse, parse_qs
import datetime
import base64
import json
import jwt #encoding and decoding JSON Web Tokens

host_name = "localhost"
server_port = 8080

def generate_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

private_key = generate_key()
expired_key = generate_key()

def key_to_pem_pkcs8(key): # Convert private key to PEM format
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

pempkcs1 = key_to_pem_pkcs8(private_key)
expired_pempkcs1 = key_to_pem_pkcs8(expired_key)

pem_keys = {
    "goodKID": pempkcs1,
    "expiredKID": expired_pempkcs1
}

rsa_numbers = private_key.private_numbers()

def int_to_base64(value):   # Convert an integer to a Base64URL-encoded string to be used to verify the JWT 
                            # (modulus and exponent of RSA public key)
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1: # Ensure even length so that bytes.fromhex doesn't fail
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')# Remove padding
    return encoded.decode('utf-8')# Convert from bytes to UTF-8 string

class jwt_server(BaseHTTPRequestHandler): # Create HTTP server to serve reqs
    def do_PUT(self):
        self.send_response(405) #disallow PUT requests
        self.end_headers()
        return

    def do_PATCH(self): 
        self.send_response(405) #disallow PATCH requests
        self.end_headers()
        return

    def do_DELETE(self):
        self.send_response(405) #disallow DELETE requests
        self.end_headers()
        return

    def do_HEAD(self):
        self.send_response(405) #disallow HEAD requests
        self.end_headers()
        return

    def create_jwt(self, headers, token_payload, selected_pem): # Create JWT token
        return jwt.encode(token_payload, selected_pem, algorithm="RS256", headers=headers)
#NATHAN DIWA REED ndr0057
    def create_jwks(self): # Create JSON Web Key Set (JWKS)
        return {
            "keys": [
                {
                    "alg": "RS256",
                    "kty": "RSA",
                    "use": "sig",
                    "kid": "goodKID",
                    "n": int_to_base64(rsa_numbers.public_numbers.n), # Convert modulus to Base64URL-encoded string
                    "e": int_to_base64(rsa_numbers.public_numbers.e),
                }
            ]
        }

    def do_POST(self): # Serve POST requests
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)

        if parsed_path.path != "/auth":
            self.send_response(405)
            self.end_headers()
            return

        headers = {"kid": "goodKID"}
        token_payload = {
            "user": "username",
            "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        }
        selected_pem = pem_keys["goodKID"]

        if 'expired' in params: # If request contains "expired" parameter, use expired key
            headers["kid"] = "expiredKID"
            token_payload["exp"] = datetime.datetime.utcnow() - datetime.timedelta(minutes=30)
            selected_pem = pem_keys["expiredKID"]

        encoded_jwt = self.create_jwt(headers, token_payload, selected_pem)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(bytes(encoded_jwt, "utf-8"))

    def do_GET(self): # Serve GET requests
        if self.path != "/.well-known/jwks.json":
            self.send_response(405)
            self.end_headers()
            return

        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        pem_keys = self.create_jwks()
        self.wfile.write(bytes(json.dumps(pem_keys), "utf-8")) # Write JWKS to response via wfile

if __name__ == "__main__": # Start server
    web_server = HTTPServer((host_name, server_port), jwt_server)

    try:
        web_server.serve_forever()
    except KeyboardInterrupt:
        pass

    web_server.server_close() # Close server