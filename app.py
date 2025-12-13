from flask import Flask, request, redirect, render_template, session, flash, url_for
from flask_login import LoginManager, login_user, logout_user, UserMixin, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, TextAreaField
from wtforms.validators import DataRequired, Length


app = Flask(__name__)
app.secret_key = "supersecretkey"

app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///bookclub.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    reviews = db.relationship('Review', backref='author', lazy=True)

class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    content = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


class RegisterForm(FlaskForm):
    username = StringField("Логін", validators=[DataRequired(), Length(min=3)])
    password = PasswordField("Пароль", validators=[DataRequired(), Length(min=4)])


class LoginForm(FlaskForm):
    username = StringField("Логін", validators=[DataRequired()])
    password = PasswordField("Пароль", validators=[DataRequired()])


class ReviewForm(FlaskForm):
    title = StringField("Заголовок", validators=[DataRequired()])
    content = TextAreaField("Текст", validators=[DataRequired(), Length(min=5)])


@app.route("/")
def index():
    return render_template("index.html")


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Користувач уже існує. Увійдіть у свій акаунт.', 'info')
            return redirect(url_for('login'))

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password, is_admin=False)
        db.session.add(new_user)
        db.session.commit()

        flash('Реєстрація успішна! Тепер увійдіть у систему.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)



@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()

        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            flash("Вхід успішний!", "success")
            return redirect(url_for("index"))
        else:
            flash("Невірний логін або пароль", "danger")

    return render_template("login.html", form=form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Ви вийшли зі свого акаунту.", "info")
    return redirect(url_for("index"))


@app.route("/add_review", methods=["GET", "POST"])
@login_required
def add_review():
    form = ReviewForm()

    if form.validate_on_submit():
        review = Review(
            title=form.title.data,
            content=form.content.data,
            user_id=current_user.id
        )
        db.session.add(review)
        db.session.commit()
        return redirect("/reviews")

    return render_template("add_review.html", form=form)


@app.route("/reviews")
def reviews():
    all_reviews = (
        Review.query.join(User)
        .add_columns(
            User.username,
            Review.title,
            Review.content,
            Review.id,
            Review.user_id
        )
        .all()
    )

    return render_template(
        "reviews.html",
        reviews=all_reviews,
        is_admin=current_user.is_authenticated and current_user.is_admin
    )


@app.route("/delete_review/<int:review_id>")
@login_required
def delete_review(review_id):
    review = Review.query.get(review_id)
    if not review:
        flash("Відгук не знайдено.", "danger")
        return redirect("/reviews")

    if not current_user.is_admin and review.user_id != current_user.id:
        flash("Доступ заборонено.", "danger")
        return redirect("/reviews")

    db.session.delete(review)
    db.session.commit()
    flash("Відгук успішно видалено!", "success")
    return redirect("/reviews")


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
