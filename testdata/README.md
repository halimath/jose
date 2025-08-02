# Generating Key Pairs

## ECDSA

1. Generate the private key in PEM SEC.1 format
2. Extract the corresponding public key
3. Convert private key to PKCS#8

```shell
openssl ecparam -name prime256v1 -genkey -noout -out es256.private.pem
openssl ec -in es256.private.pem -pubout -out es256.public.pem
openssl pkcs8 -topk8 -nocrypt -in es256.private.pem -out es256.private.pkcs8
```

```shell
openssl ecparam -name secp521r1 -genkey -noout -out es512.private.pem
openssl ec -in es512.private.pem -pubout -out es512.public.pem
openssl pkcs8 -topk8 -nocrypt -in es512.private.pem -out es512.private.pkcs8
```

## RSA

1. Generate private key - already in PKCS#8
2. Extract public key

```shell
openssl genpkey -algorithm RSA -out rsa.private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in rsa.private.pem -out rsa.public.pem
```