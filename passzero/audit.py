from zxcvbn import zxcvbn


def password_strength(password, user_inputs):
    return zxcvbn(password, user_inputs=user_inputs)

