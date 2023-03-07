# Annoyingly New-SelfSignedCertificate at most supports 4096

echo Hello
#printf '%s\n' US WA REDMOND CONTOSO BIGCERTIFICATE BIGCERT EMAIL | openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem

echo world
#openssl x509 -text -noout -in certificate.pem


#echo certificate
printf '%s\n' password password | openssl pkcs12 -inkey key.pem -in certificate.pem -export -out certificate.p12 -stdin

