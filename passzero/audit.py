
def password_strength(password: str, user_inputs):
    # import inside the function because it's a heavyweight library
    from zxcvbn import zxcvbn

    return zxcvbn(password, user_inputs=user_inputs)
