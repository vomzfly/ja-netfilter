import base64

from Crypto.Hash import SHA1, SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Util.asn1 import DerSequence, DerObjectId, DerNull, DerOctetString
from Crypto.Util.number import ceil_div
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

def load_certificate(file_path):
    with open(file_path, "rb") as cert_file:
        cert_data = cert_file.read()

    if b"-----BEGIN CERTIFICATE-----" in cert_data:
        return x509.load_pem_x509_certificate(cert_data, default_backend())
    else:
        return x509.load_der_x509_certificate(cert_data, default_backend())


# noinspection PyTypeChecker
def pkcs15_encode(msg_hash, emLen, with_hash_parameters=True):
    """
    Implement the ``EMSA-PKCS1-V1_5-ENCODE`` function, as defined
    :param msg_hash: hash object
    :param emLen: int
    :param with_hash_parameters: bool
    :return: An ``emLen`` byte long string that encodes the hash.
    """
    digestAlgo = DerSequence([DerObjectId(msg_hash.oid).encode()])

    if with_hash_parameters:
        digestAlgo.append(DerNull().encode())

    digest = DerOctetString(msg_hash.digest())
    digestInfo = DerSequence([
        digestAlgo.encode(),
        digest.encode()
    ]).encode()

    # We need at least 11 bytes for the remaining data: 3 fixed bytes and
    # at least 8 bytes of padding).
    if emLen < len(digestInfo) + 11:
        raise TypeError("Selected hash algorithm has a too long digest (%d bytes)." % len(digest))
    PS = b'\xFF' * (emLen - len(digestInfo) - 3)
    return b'\x00\x01' + PS + b'\x00' + digestInfo

certBase64 = "MIIExTCCAq2gAwIBAgIUd7aUydfLbUIg5NaqSPMwrsEsPkswDQYJKoZIhvcNAQELBQAwGDEWMBQGA1UEAwwNSmV0UHJvZmlsZSBDQTAeFw0yNDEyMTMxNjMwMDNaFw0zNDEyMTIxNjMwMDNaMCExHzAdBgNVBAMMFk1vWXVuby1mcm9tLTIwMjItMDctMjUwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDJEwJDc4k6YO6LIbUJQ21eFYdxdg0jsWiSXVrISsTrnVShejd8zu3Lu5FRIIgPMIxuzduZW9WSDt8pZV4jtnbd0n3xeHlalAXWWQ7UsIhQx7mo7jnyZbqe101NSoiM2gu4GEWgV9Wh2txBuaXLmFULMdc2R9T/Lm5XPImYKKt77KVA8ahV/W/aF8OMlUPHR1FGkpyS35ES4mdoA8cukWaUX1kI514WznUqvrKnhor67hGPkX8JPEPR7B/zFlZD9OXnyoI+oGf7VPbVHu5Tt70+1r5Q1/rzHQJDMsQyFS8P2Dd54oj3q1VxuUKdhV+We5iy7r/LMy0qR9S4UfDBrE/v2Uz3aOCm+iR8524tUr4+n5YNn2LEYbzCGoQ1lMMWZxrqAH9XPahvepKn3dVN0TsZwFTCrnGdanzHdoUQZe2ArV9vOjA1FBc0h0vIEXQCQEhuTh0XMjAKfLp5TOn10gOkUPtXYqe3uGABYu2EJBpxS4UgRIiZvRqiF4BLqPHlkcpZoQVQsELJF5X2MONeepOyidm5EsgG519XMbokqboZEFYNQsiOSc8+8GnRcPc2ZP6M35B8dHbQht5mq4vGPtZBNK734GJQNGZHopdjngwKyF9zijrS+pvF/8eQ35PWy2d8uLFAmBP0gmM1FA2xyefkQpqc1W8e5pFyTZaOeTxKwwIDAQABMA0GCSqGSIb3DQEBCwUAA4ICAQCkQc9a5VXanjdY/95LCee2huM8CaGvQH7jLHA+SblAK0yW4WOIhgUPYajqJ/Th8nM8+F45VGwfeie8zO6muROhzCy7975AW7dCprcsAeNYArIwtGghXK+R3/BCOSGuejnyCxUM25gMrrimUNbx3UIUU6YVsfxNVrpKl2qBaWHXQkEj4gHU01o2KJJeKzTyqj0mgn0dcSY1h+cn4tcY8EMUS+h1TncrezcZbOQqmiTkAYx0nZOryy9jTGpLuJsu47ys/CvcalTQcvklVwe4RNjUL++Lt6P+ZcJsiseLIzjZ26Acc0S9Y7OL55304rWch6C06kS7pcXQ9Oz7Ve0LocbVqaEitQtjNpptsjEeBuloVx23OcGnZEHjlieqW24oBbJG2Nq9y2NxCBTDhvXDFKNdZ95SMpNinbyuDBxrwnqGYCvn/bbo981T/KbZPTrpN8d6g7CGyjjVKvN4VWMNGZJaW03GXK10luqci/VyBDpwQk31thG1eITBB0iSWy/HhJwOxUlsE54t7d7hJGdwR3pbDDpWWc8CjWkSOpCykITmkkGBAODFJyWWyjl3AmMwVkorrbKV0x6Qrzj3qOXHiPKtTcDD4d9W3XHNJFkPo3HHn3iSVwS/B82drMs+J6gXG+NfKqHHZaOiOSktxrh7JL706kuOicqIIt95zNnItmOfng=="

# cert = load_certificate("ca.crt")
cert = x509.load_der_x509_certificate(base64.b64decode(certBase64))
public_key = cert.public_key()
# print(f"modulus:{public_key.public_numbers().n}")
sign = int.from_bytes(cert.signature, byteorder="big", )
print(f"sign:{sign}")

modBits = public_key.key_size
digest_cert = SHA256.new(cert.tbs_certificate_bytes)
r = int.from_bytes(pkcs15_encode(digest_cert, ceil_div(modBits, 8)), byteorder='big', signed=False)
print(f"result:{r}")

licenseId = 'FV8EM46DQYC5AW9'
licensePart = '{"licenseId":"FV8EM46DQYC5AW9","licenseeName":"menorah parapet","licenseeType":"PERSONAL","assigneeName":"vomzfly","assigneeEmail":"vomzfly@ignore.com","licenseRestriction":"","checkConcurrentUse":false,"products":[{"code":"PCWMP","fallbackDate":"2066-09-14","paidUpTo":"2066-09-14","extended":true},{"code":"PRR","fallbackDate":"2066-09-14","paidUpTo":"2066-09-14","extended":true},{"code":"PDB","fallbackDate":"2066-09-14","paidUpTo":"2066-09-14","extended":true},{"code":"PSI","fallbackDate":"2066-09-14","paidUpTo":"2066-09-14","extended":true},{"code":"II","fallbackDate":"2066-09-14","paidUpTo":"2066-09-14","extended":false}],"metadata":"0220240702PSAX000005X","hash":"12345678/0-541816629","gracePeriodDays":7,"autoProlongated":false,"isAutoProlongated":false,"trial":false,"aiAllowed":true}'

digest = SHA1.new(licensePart.encode('utf-8'))

with open('ca.key') as prifile:
    private_key = RSA.import_key(prifile.read())
    # 使用私钥对HASH值进行签名
    signature = pkcs1_15.new(private_key).sign(digest)

    sig_results = base64.b64encode(signature)
    licensePartBase64 = base64.b64encode(bytes(licensePart.encode('utf-8')))
    public_key.verify(
        base64.b64decode(sig_results),
        base64.b64decode(licensePartBase64),
        padding=padding.PKCS1v15(),
        algorithm=hashes.SHA1(),
    )
    result = licenseId + "-" + licensePartBase64.decode('utf-8') + "-" + sig_results.decode('utf-8') + "-" + certBase64
    print(result)
