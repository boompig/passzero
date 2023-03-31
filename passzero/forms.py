from wtforms import Form, PasswordField, StringField, validators


class LoginForm(Form):
    """This is the old (v1) login form and is now depracated"""
    email = StringField("email", [
        validators.DataRequired(),
        validators.Email(),
    ])
    password = PasswordField("password", [validators.DataRequired()])
