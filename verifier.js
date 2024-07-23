const xmlcrypto = require("xml-crypto");
const fs = require("fs");
const xmldom = require("xmldom");

const reference = process.argv[2];
const key_reference = process.argv[3];
const xmldsig = fs.readFileSync(`${reference}`).toString();
const xmldoc = new xmldom.DOMParser().parseFromString(xmldsig);

const select = xmlcrypto.xpath;

// assuming exactly one EntitiesDescriptor missing XSW protection
console.log(`Processing file ${reference}`);
const entities_signature = select(
  xmldoc,
  "//*[local-name()='EntitiesDescriptor' and namespace-uri()='urn:oasis:names:tc:SAML:2.0:metadata']/*[local-name()='Signature' and namespace-uri()='http://www.w3.org/2000/09/xmldsig#']"
)[0];
let sig = new xmlcrypto.SignedXml();
sig.keyInfoProvider = new xmlcrypto.FileKeyInfo(key_reference);
sig.loadSignature(entities_signature);
let res = sig.checkSignature(xmldsig);
if (!res) {
  console.log(`Failed to verify ${reference} with ${key_reference} file`);
  console.log(sig.validationErrors);
} else {
  console.log(
    `XML ${reference} is valid when verified with the ${key_reference} file`
  );
}
