"""نقطة الدخول لخوادم الإنتاج مثل Render:  gunicorn wsgi:app"""
from werkzeug.middleware.proxy_fix import ProxyFix

from app import create_app
from manage import bootstrap_from_env

app = create_app()
bootstrap_from_env(app)
# خلف وكيل Render نقرأ عنوان IP الحقيقي والبروتوكول من ترويسات X-Forwarded-*
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
