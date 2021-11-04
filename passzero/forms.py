from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired
from wtforms import BooleanField, Form, PasswordField, StringField, validators, IntegerField

from passzero.limits import MAX_ENTRY_PASSWORD_LENGTH, MAX_GEN_PASSPHRASE_WORDS


class SignupForm(Form):
    email = StringField("email", [
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
    """This is the old (v1) login form and is now depracated"""
    email = StringField("email", [
        validators.DataRequired(),
        validators.Email(),
    ])
    password = PasswordField("password", [validators.DataRequired()])


class LoginFormV2(Form):
    # allow for either a username or an email
    username_or_email = StringField("username_or_string", [
        validators.DataRequired(),
        # set some arbitrary upper bound on parameters
        validators.Length(min=2, max=64),
    ])
    password = PasswordField("password", [validators.DataRequired()])


class DeleteUserForm(Form):
    password = PasswordField("password", [validators.DataRequired()])


class DeleteAllEntriesForm(Form):
    password = PasswordField("password", [validators.DataRequired()])


class NewEntryForm(Form):
    account = StringField("account", [
        validators.DataRequired()
    ])
    username = StringField("username", [
        validators.DataRequired()
    ])
    password = PasswordField("password", [
        validators.DataRequired(),
        validators.Length(max=MAX_ENTRY_PASSWORD_LENGTH)
    ])
    extra = StringField("extra")
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
    email = StringField("email", [
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
    token = StringField("token", [validators.DataRequired()])


class ConfirmRecoverPasswordForm(Form):
    token = StringField("token", [validators.DataRequired()])
    password = PasswordField("password", [
        validators.DataRequired(),
        validators.EqualTo("confirm_password", message="Passwords must match")
    ])
    confirm_password = PasswordField("confirm password", [
        validators.DataRequired()
    ])


class NewDocumentForm(FlaskForm):
    name = StringField("name", [
        validators.DataRequired()
    ])
    mimetype = StringField("mimetype", [
        validators.DataRequired()
    ])
    document = FileField("document", [
        FileRequired()
    ])
