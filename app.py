from flask import Flask, request, redirect, render_template, session, flash
from flask import Flask, render_template, request, redirect, url_for, flash

from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.secret_key = "supersecretkey"


app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///bookclub.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(50), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    reviews = db.relationship('Review', backref='author', lazy=True)

class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    content = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


@app.route("/")
def index():
    return render_template("index.html")


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        existing_user = User.query.filter_by(username=username).first()

        if existing_user:
            flash('Користувач уже існує. Увійдіть у свій акаунт.', 'info')
            return redirect(url_for('login'))  

        new_user = User(username=username, password=password, is_admin=False)
        db.session.add(new_user)
        db.session.commit()

        flash('Реєстрація успішна! Тепер увійдіть у систему.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = User.query.filter_by(username=username, password=password).first()
        if user:
            session["user_id"] = user.id
            session["is_admin"] = user.is_admin
            return redirect("/")
        else:
            return "Неправильний логін або пароль"
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/add_review", methods=["GET", "POST"])
def add_review():
    if "user_id" not in session:
        return redirect("/login")
    if request.method == "POST":
        title = request.form["title"]
        content = request.form["content"]
        review = Review(title=title, content=content, user_id=session["user_id"])
        db.session.add(review)
        db.session.commit()
        return redirect("/reviews")
    return render_template("add_review.html")


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
        is_admin=session.get("is_admin")
    )


@app.route("/delete_review/<int:review_id>")
def delete_review(review_id):
    if "user_id" not in session:
        flash("Спочатку увійдіть у систему!", "warning")
        return redirect("/login")

    review = Review.query.get(review_id)
    if not review:
        flash("Відгук не знайдено.", "danger")
        return redirect("/reviews")

    if not session.get("is_admin") and review.user_id != session["user_id"]:
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