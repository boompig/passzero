from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired
from wtforms import BooleanField, Form, PasswordField, TextField, validators, IntegerField

from passzero.limits import MAX_ENTRY_PASSWORD_LENGTH, MAX_GEN_PASSPHRASE_WORDS


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

class DeleteUserForm(Form):
    password = PasswordField("password", [validators.DataRequired()])

class NewEntryForm(Form):
    account = TextField("account", [
        validators.DataRequired()
    ])
    username = TextField("username", [
        validators.DataRequired()
    ])
    password = PasswordField("password", [
        validators.DataRequired(),
        validators.Length(max=MAX_ENTRY_PASSWORD_LENGTH)
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

class RecoverPasswordForm(Form):
    email = TextField("email", [
        validators.DataRequired(),
        validators.Email()
    ])

class UpdatePreferencesForm(Form):
    default_random_password_length = IntegerField("default_random_password_length", [
        validators.Optional(),
        validators.NumberRange(1, MAX_ENTRY_PASSWORD_LENGTH),
    ])
    default_random_passphrase_length = IntegerField("default_random_passphrase_length", [
        validators.Optional(),
        validators.NumberRange(1, MAX_GEN_PASSPHRASE_WORDS),
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


class NewDocumentForm(FlaskForm):
    name = TextField("name", [
        validators.DataRequired()
    ])
    document = FileField("document", [
        FileRequired()
    ])

