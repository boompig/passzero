from wtforms import BooleanField, Form, PasswordField, TextField, validators


class SignupForm(Form):
    email = TextField("email", [
        validators.DataRequired(),
        validators.Email()
    ])
    password = PasswordField("password", [
        validators.DataRequired(),
        validators.EqualTo("confirm_password", message="Passwords must match")
    ])
    confirm_password = PasswordField("confirm password", [
        validators.DataRequired()
    ])

class LoginForm(Form):
    email = TextField("email", [
        validators.DataRequired(),
        validators.Email()
    ])
    password = PasswordField("password", [validators.DataRequired()])

class NewEntryForm(Form):
    account = TextField("account", [
        validators.DataRequired()
    ])
    username = TextField("username", [
        validators.DataRequired()
    ])
    password = PasswordField("password", [
        validators.DataRequired()
    ])
    extra = TextField("extra")
    has_2fa = BooleanField("has_2fa", [
        validators.AnyOf([True, False])
    ])

class UpdatePasswordForm(Form):
    old_password = PasswordField("old password", [validators.DataRequired()])
    new_password = PasswordField("new password", [
        validators.DataRequired(),
        validators.EqualTo("confirm_new_password", message="Passwords must match")
    ])
    confirm_new_password = PasswordField("confirm new password", [validators.DataRequired()])
    extra = TextField("extra")

class RecoverPasswordForm(Form):
    email = TextField("email", [
        validators.DataRequired(),
        validators.Email()
    ])

class ActivateAccountForm(Form):
    token = TextField("token", [validators.DataRequired()])

class ConfirmRecoverPasswordForm(Form):
    token = TextField("token", [validators.DataRequired()])
    password = PasswordField("password", [
        validators.DataRequired(),
        validators.EqualTo("confirm_password", message="Passwords must match")
    ])
    confirm_password = PasswordField("confirm password", [
        validators.DataRequired()
    ])
