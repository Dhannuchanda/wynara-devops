from app import app


def test_health_endpoint_does_not_require_database():
    response = app.test_client().get("/health")

    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}


def test_home_page_loads_for_anonymous_user():
    response = app.test_client().get("/")

    assert response.status_code == 200
    assert b"WAPL" in response.data
