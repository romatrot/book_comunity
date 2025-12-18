from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField
from wtforms.validators import DataRequired, Length


class RegisterForm(FlaskForm):
    username = StringField("Логін", validators=[DataRequired(), Length(min=3)])
    password = PasswordField("Пароль", validators=[DataRequired(), Length(min=4)])


class LoginForm(FlaskForm):
    username = StringField("Логін", validators=[DataRequired()])
    password = PasswordField("Пароль", validators=[DataRequired()])


class ReviewForm(FlaskForm):
    title = StringField("Заголовок", validators=[DataRequired()])
    content = TextAreaField("Текст", validators=[DataRequired(), Length(min=5)])