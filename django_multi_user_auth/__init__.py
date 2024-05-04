from django.conf import settings
from django.http import HttpRequest
from django.apps import apps
from django.contrib.auth.hashers import make_password, check_password
from django.utils.crypto import salted_hmac

def get_session_auth_hash(encrypted_credential: str, key_salt: str)-> str:
        return salted_hmac(
            key_salt,
            encrypted_credential,
            secret=None,
            algorithm="sha256",
        ).hexdigest()

def login(key: str, request: HttpRequest, id: str, credential: str)-> bool:
    if key not in settings.MULTI_AUTH_SETTINGS:
        raise Exception("todo")
    target_settings = settings.MULTI_AUTH_SETTINGS[key]
    MultiAuthUser = apps.get_model(target_settings["model_name"])
    try:
        multi_auth_user = MultiAuthUser.objects.get(
            **{
                target_settings["id_field_name"]: id,
            }
        )
    except MultiAuthUser.DoesNotExist:
        make_password(credential)
        return False
    encrypted_credential = getattr(multi_auth_user, target_settings["credential_field_name"])
    if not check_password(credential, encrypted_credential):
        return False
    session_key = f"_{key}_user_id"
    request.session[session_key] = str(multi_auth_user.pk)
    setattr(request, key, multi_auth_user)
    hash_session_key = f"_{key}_hash"
    request.session[hash_session_key] = get_session_auth_hash(
        encrypted_credential, key
    )
    request.session.cycle_key()
    return True

def logout(key: str, request: HttpRequest):
    if key not in settings.MULTI_AUTH_SETTINGS:
        raise Exception("todo")
    setattr(request, key, None)
    request.session.flush()


def sign_up(key: str, id: str, credential: str):
    if key not in settings.MULTI_AUTH_SETTINGS:
        raise Exception("todo")
    target_settings = settings.MULTI_AUTH_SETTINGS[key]
    MultiAuthUser = apps.get_model(target_settings["model_name"])
    MultiAuthUser.objects.create(
        **{
            target_settings["id_field_name"]: id,
            target_settings["credential_field_name"]: make_password(credential),
        }
    )
