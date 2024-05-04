from django.utils.deprecation import MiddlewareMixin
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.shortcuts import redirect
from django.apps import apps
from django.utils.crypto import constant_time_compare

from . import get_session_auth_hash



class MultiAuthMiddleware(MiddlewareMixin):
    def process_request(self, request):
        if not hasattr(request, "session"):
            raise ImproperlyConfigured(
                "The Django authentication middleware requires session "
                "middleware to be installed. Edit your MIDDLEWARE setting to "
                "insert "
                "'django.contrib.sessions.middleware.SessionMiddleware' before "
                "'django.contrib.auth.middleware.AuthenticationMiddleware'."
            )
        for key, multi_auth_settings in settings.MULTI_AUTH_SETTINGS.items():
            session_key = f"_{key}_user_id"
            if session_key in request.session:
                MultiAuthUser = apps.get_model(multi_auth_settings["model_name"])
                pk = request.session[session_key]
                try:
                    multi_auth_user = MultiAuthUser.objects.get(pk=pk)
                except Exception:
                    setattr(request, key, None)
                    request.session.flush()
                    request.session.cycle_key()
                else:
                    setattr(request, key, multi_auth_user)
                    hash_session_key = f"_{key}_hash"
                    if hash_session_key in request.session:
                        session_auth_hash = request.session[hash_session_key]
                        calclated_auth_hash = get_session_auth_hash(
                            getattr(multi_auth_user, multi_auth_settings["credential_field_name"]),
                            key
                        )
                        if not constant_time_compare(session_auth_hash, calclated_auth_hash):
                            setattr(request, key, None)
                            request.session.flush()
                            request.session.cycle_key()

            else:
                setattr(request, key, None)

            for scope in multi_auth_settings["login_required_scopes"]:
                if request.path.startswith(scope):
                    if not getattr(request, key):
                        return redirect("news:writer_login")
                    else:
                        return None
