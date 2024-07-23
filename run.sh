echo "Download all entities files"
mkdir -p data
mkdir -p certs

for i in $(curl -s https://api.is.eng.pagopa.it/idp-keys/spid/ | jq -r '.[]')
  do curl "https://api.is.eng.pagopa.it/idp-keys/spid/$i" > "data/$i.xml"
done

echo "Download CIE metadata"
curl https://idserver.servizicie.interno.gov.it/idp/shibboleth?Metadata >"data/cie.xml"

echo "Extract all certificates from them"
for i in $(ls -1 data/*.xml); do
  BASENAME=$(basename $i)
  xmlstarlet sel -t -v "/*/ds:Signature/ds:KeyInfo/ds:X509Data/ds:X509Certificate" "$i" | base64 -d | openssl x509 -inform der -outform pem -out "certs/$BASENAME.pem"
done

# verifier.py usage:
# python verifier.py data/file.xml -ca_file certs/data.xml.pem
# or can be used extracting ca pk from xml itself
# python verifier.py data/file.xml

echo "Install python packages"
pip install -r requirements.txt

echo "Run verifier.py on all files"
for i in $(ls -1 data/*.xml); do
  echo -e "\nRunning on $i file"
  BASENAME=$(basename $i)
  python verifier.py $i -ca_file certs/$BASENAME.pem
done

echo "Install node packages"
npm ci

# echo "Run verifier.js on all files"
for i in $(ls -1 data/*.xml)
  do echo -e "\nRunning on $i file"; BASENAME=$(basename $i); node verifier.js $i certs/$BASENAME.pem
done

if [ ! -d "./xmlsectool-3.0.0" ]; then
  wget -nc https://shibboleth.net/downloads/tools/xmlsectool/3.0.0/xmlsectool-3.0.0-bin.zip
  echo "./xmlsectool-3.0.0 does not exist, unzipping"
  unzip xmlsectool-3.0.0-bin.zip
fi

echo "Run xmlsectool on all files"
for i in $(ls -1 data/*.xml); do
  echo -e "\nRunning on $i file"
  BASENAME=$(basename $i)
  bash ./xmlsectool-3.0.0/xmlsectool.sh  --verifySignature --certificate certs/$BASENAME.pem --inFile $i 
done