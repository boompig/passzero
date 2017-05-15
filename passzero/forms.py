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
    extra = TextField("extra")

class NewEncryptedEntryForm(Form):
    account = TextField("account", [
        validators.Required()
    ])
    username = TextField("username", [
        validators.Required()
    ])
    password = PasswordField("password", [
        validators.Required()
    ])
    key_salt = PasswordField("key_salt", [
        validators.Required()
    ])
    iv = PasswordField("iv", [
        validators.Required()
    ])
    extra = TextField("extra")

class UpdatePasswordForm(Form):
    old_password = PasswordField("old password", [validators.Required()])
    new_password = PasswordField("new password", [
        validators.Required(),
        validators.EqualTo("confirm_new_password", message="Passwords must match")
    ])
    confirm_new_password = PasswordField("confirm new password", [validators.Required()])
    extra = TextField("extra")

class RecoverPasswordForm(Form):
    email = TextField("email", [
        validators.Required(),
        validators.Email()
    ])

class ActivateAccountForm(Form):
    token = TextField("token", [validators.Required()])

class ConfirmRecoverPasswordForm(Form):
    token = TextField("token", [validators.Required()])
    password = PasswordField("password", [
        validators.Required(),
        validators.EqualTo("confirm_password", message="Passwords must match")
    ])
    confirm_password = PasswordField("confirm password", [
        validators.Required()
    ])
