def test_add_review_requires_login(client):
    # Робимо GET-запит до сторінки додавання відгуку без логіну
    response = client.get("/add_review")

    # Перевіряємо, що сталося перенаправлення на /login
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]
