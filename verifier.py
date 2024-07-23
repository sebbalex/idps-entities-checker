from lxml import etree
from signxml import  XMLVerifier
import base64
from cryptography import x509
from cryptography.hazmat.primitives import serialization
import argparse

parser = argparse.ArgumentParser("verifier")
parser.add_argument("spid_entities_file", help="Required file which contains all IDPs metadata", type=str)
parser.add_argument("-ca_file", help="Certification authority public key", type=str, required=False)
args = parser.parse_args()

data = open(args.spid_entities_file).read().encode()
root = etree.fromstring(data)

ca = None
ca_file = None
decoded_cert = None

if args.ca_file:
  ca_file = args.ca_file
  print("using provided ca file:", ca_file)
  ca = open(ca_file).read()
  decoded_cert = x509.load_pem_x509_certificate(ca.encode())
else:
  print("using extracted ca pk from xml itself")
  namespaces = {"ds": "http://www.w3.org/2000/09/xmldsig#"}
  namespace = "{http://www.w3.org/2000/09/xmldsig#}"
  s = root.find('ds:Signature', namespaces)
  ky = s.find("ds:KeyInfo", namespaces)
  xd = ky.find("ds:X509Data", namespaces)
  xc = xd.find("ds:X509Certificate", namespaces)
  cert_encoded = base64.b64decode(xc.text)
  ca_file = "extracted from xml pem"
  decoded_cert = x509.load_der_x509_certificate(cert_encoded)
  ca = decoded_cert.public_bytes(encoding=serialization.Encoding.PEM)

print(decoded_cert.issuer)
print(f"Not valid before: {decoded_cert.not_valid_before} \nNot valid after: {decoded_cert.not_valid_after}")

try:
  verified_data = XMLVerifier().verify(root, x509_cert=ca).signature_xml
  print(f"XML {args.spid_entities_file} is valid when verified with the {ca_file} file")
except Exception as e:
  print(f"Failed to verify {args.spid_entities_file} with {ca_file} file")
  print(e)