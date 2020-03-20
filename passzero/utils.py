import base64


def base64_encode(bin_data: bytes):
    """
    :type bin_data:     bytes
    :rtype:             bytes
    """
    assert isinstance(bin_data, bytes)
    return base64.b64encode(bin_data)
