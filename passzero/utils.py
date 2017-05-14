import binascii

def base64_encode(bin_data):
    s = binascii.b2a_base64(bin_data)
    if s[-1] == "\n":
        return s[:-1]

