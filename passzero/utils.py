import binascii


def base64_encode(bin_data):
    """
    :type bin_data:     bytes
    :rtype:             bytes
    """
    assert isinstance(bin_data, bytes)
    s = binascii.b2a_base64(bin_data)
    if s[-1] == "\n":
        # this is maddening (python2)
        return s[:-1]
    else:
        return s

