from flask import Flask, request, redirect, render_template, session, flash, url_for, jsonify, g
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import time
from models import db, User, Review
from forms import RegisterForm, LoginForm, ReviewForm


app = Flask(__name__)
app.secret_key = "supersecretkey"
#app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///bookclub.db"
app.config['SQLALCHEMY_DATABASE_URI'] = (
    "postgresql://postgres:postgres@db:5432/bookclub"
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


db.init_app(app)


login_manager = LoginManager(app)
login_manager.login_view = "login"


# --- ID EMPOTENCY STORE ---
idempotency_store = {}

# --- REQUEST ID ---
@app.before_request
def generate_request_id():
    g.request_id = str(uuid.uuid4())


rate_limit = {}

@app.before_request
def rate_limit_check():
    ip = request.remote_addr
    now = time.time()

    window = rate_limit.get(ip, [])
    window = [t for t in window if now - t < 60]

    if len(window) >= 100:
        response = redirect(url_for("index"))
        response.status_code = 429
        response.headers["Retry-After"] = "10"
        flash("Забагато запитів. Спробуйте пізніше.", "warning")
        return response

    window.append(now)
    rate_limit[ip] = window


@app.after_request
def add_request_id_header(response):
    response.headers["X-Request-Id"] = g.request_id
    return response

# --- ERROR RESPONSE ---
def error_response(error, code=400, details=None):
    return jsonify({
        "error": error,
        "code": code,
        "details": details,
        "requestId": getattr(g, "request_id", None)
    }), code

# --- LOGIN MANAGER ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- HEALTH CHECK ---
@app.route("/health")
def health():
    start = time.time()
    time.sleep(0.2)
    if time.time() - start > 1:
        return error_response("Timeout", 504)
    return jsonify({"status": "ok"})


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

    # Генеруємо ключ при відкритті форми
    if request.method == "GET":
        session["idempotency_key"] = str(uuid.uuid4())

    if form.validate_on_submit():
        idem_key = request.form.get("idempotency_key")

        # ПОВТОРНИЙ POST
        if idem_key in idempotency_store:
            flash("Цей відгук уже був доданий (повторний запит)", "info")
            return redirect(url_for("reviews"))

        review = Review(
            title=form.title.data,
            content=form.content.data,
            user_id=current_user.id
        )

        db.session.add(review)
        db.session.commit()

        # Запамʼятовуємо виконаний запит
        idempotency_store[idem_key] = review.id

        flash("Відгук успішно додано!", "success")
        return redirect(url_for("reviews"))

    return render_template(
        "add_review.html",
        form=form,
        idempotency_key=session.get("idempotency_key")
    )


@app.route("/reviews")
def reviews():
    all_reviews = Review.query.all()
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
    return redirect("/reviews")


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=8000, debug=True)

