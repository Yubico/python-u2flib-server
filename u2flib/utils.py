from M2Crypto import EC
from base64 import b64encode

PUB_KEY_DER_PREFIX = "3059301306072a8648ce3d020106082a8648ce3d030107034200" \
    .decode('hex')


def b64_split(der):
    b64 = b64encode(der)
    return '\n'.join([b64[i:i + 64] for i in range(0, len(b64), 64)])


def pub_key_from_der(der):
    return EC.pub_key_from_der(PUB_KEY_DER_PREFIX + der)


def update_all(cipher, from_buf, to_buf):
    while True:
        buf = from_buf.read()
        if not buf:
            break
        to_buf.write(cipher.update(buf))
    to_buf.write(cipher.final())
    return to_buf.getvalue()


def zeropad(data, blksize=8):
    padded = data + ('\0' * ((blksize - len(data)) % blksize))
    return padded
