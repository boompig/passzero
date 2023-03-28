from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired
from wtforms import Form, PasswordField, StringField, validators


class LoginForm(Form):
    """This is the old (v1) login form and is now depracated"""
    email = StringField("email", [
        validators.DataRequired(),
        validators.Email(),
    ])
    password = PasswordField("password", [validators.DataRequired()])


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
