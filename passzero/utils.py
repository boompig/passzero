import binascii
import six


def base64_encode(bin_data):
    """
    :rtype:             8-bit string
    """
    assert isinstance(bin_data, six.binary_type)
    s = binascii.b2a_base64(bin_data)
    if s[-1] == "\n":
        # this is maddening (python2)
        return s[:-1]
    else:
        return s

