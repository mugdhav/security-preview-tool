"""Must-NOT-detect: debug disabled."""

DEBUG = False


def create_app(app):
    app.config["DEBUG"] = False
    return app
