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

class LoginForm(Form):
    email = TextField("email", [
        validators.Required(),
        validators.Email()
    ])
    password = PasswordField("password", [validators.Required()])

class NewEntryForm(Form):
    account = TextField("account", [
        validators.Required()
    ])
    username = TextField("username", [
        validators.Required()
    ])
    password = PasswordField("password", [
        validators.Required()
    ])

class UpdatePasswordForm(Form):
    old_password = PasswordField("old password", [validators.Required()])
    new_password = PasswordField("new password", [
        validators.Required(),
        validators.EqualTo("confirm_new_password", message="Passwords must match")
    ])
    confirm_new_password = PasswordField("confirm new password", [validators.Required()])
