"""
Brute-force lab login endpoint.

Behavior changes based on settings.SECURITY_MODE ('vulnerable' or 'hardened'):

VULNERABLE MODE:
    - No rate limiting
    - No account lockout
    - Verbose error messages (reveals whether username exists)
    - Every attempt logged, but nothing blocks the attacker

HARDENED MODE:
    - Rate limiting per IP (django-ratelimit)
    - Account lockout after N failed attempts (settings.ACCOUNT_LOCKOUT_THRESHOLD)
    - Generic error message regardless of whether username exists
    - Lockout state tracked via cache
"""
from django.conf import settings
from django.contrib.auth import authenticate
from django.core.cache import cache
from django.utils import timezone
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from django_ratelimit.decorators import ratelimit

from core.models import LabEvent


def _client_ip(request):
    """Best-effort IP extraction for local testing."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR')


def _lockout_cache_key(username):
    return f"bruteforce_lockout:{username}"


def _failed_attempts_cache_key(username):
    return f"bruteforce_failcount:{username}"


def _is_locked_out(username):
    return cache.get(_lockout_cache_key(username), False)


def _record_failed_attempt(username):
    """Increment failure count for a username; lock out if threshold reached."""
    key = _failed_attempts_cache_key(username)
    count = cache.get(key, 0) + 1
    cache.set(key, count, timeout=settings.ACCOUNT_LOCKOUT_DURATION_SECONDS)

    if count >= settings.ACCOUNT_LOCKOUT_THRESHOLD:
        cache.set(
            _lockout_cache_key(username),
            True,
            timeout=settings.ACCOUNT_LOCKOUT_DURATION_SECONDS,
        )
    return count


def _clear_failed_attempts(username):
    cache.delete(_failed_attempts_cache_key(username))
    cache.delete(_lockout_cache_key(username))


def _log_event(request, event_type, username, success, detail=""):
    LabEvent.objects.create(
        lab_name='bruteforce',
        event_type=event_type,
        security_mode=settings.SECURITY_MODE,
        ip_address=_client_ip(request),
        username_attempted=username,
        success=success,
        detail=detail,
    )


@api_view(['POST'])
@ratelimit(key='ip', rate=settings.LOGIN_RATE_LIMIT, method='POST', block=False)
def login_view(request):
    """
    POST /api/bruteforce/login
    Body: {"username": "...", "password": "..."}
    """
    username = request.data.get('username', '')
    password = request.data.get('password', '')

    was_limited = getattr(request, 'limited', False)

    # ---- HARDENED MODE CHECKS ----
    if settings.IS_HARDENED:
        if was_limited:
            _log_event(request, 'rate_limited', username, success=False, detail="Too many requests from this IP")
            return Response(
                {"detail": "Too many requests. Please try again later."},
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )

        if _is_locked_out(username):
            _log_event(request, 'blocked_lockout', username, success=False, detail="Account temporarily locked")
            return Response(
                {"detail": "Account temporarily locked due to repeated failed attempts. Try again later."},
                status=status.HTTP_403_FORBIDDEN,
            )

    # ---- ATTEMPT AUTHENTICATION ----
    user = authenticate(request, username=username, password=password)

    if user is not None:
        _clear_failed_attempts(username)
        _log_event(request, 'login_attempt', username, success=True)
        return Response({"detail": "Login successful.", "username": username}, status=status.HTTP_200_OK)

    # ---- FAILED LOGIN ----
    if settings.IS_HARDENED:
        _record_failed_attempt(username)
        _log_event(request, 'login_attempt', username, success=False, detail="Invalid credentials")
        # Generic message - does NOT reveal whether the username exists
        return Response({"detail": "Invalid username or password."}, status=status.HTTP_401_UNAUTHORIZED)
    else:
        # VULNERABLE: leaks whether the username exists at all
        from django.contrib.auth.models import User
        username_exists = User.objects.filter(username=username).exists()
        detail = "Incorrect password." if username_exists else "User does not exist."
        _log_event(request, 'login_attempt', username, success=False, detail=detail)
        return Response({"detail": detail}, status=status.HTTP_401_UNAUTHORIZED)