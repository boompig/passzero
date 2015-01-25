from wtforms import Form, TextField, PasswordField, validators

class SignupForm(Form):
    email = TextField("email", [
        validators.Required(),
        validators.Email()
    ])
    password = PasswordField("password", [
        validators.Required(),
        validators.EqualTo("confirm_password", message="Passwords must match")
    ])
    confirm_password = PasswordField("confirm password", [
        validators.Required()
    ])

