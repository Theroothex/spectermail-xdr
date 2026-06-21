from app import create_app


def test_home_page_renders_with_csrf_token():
    app = create_app()
    app.config["TESTING"] = True

    client = app.test_client()
    response = client.get("/")

    assert response.status_code == 200
    assert b'name="_csrf_token"' in response.data
