"""
Seeds a handful of demo accounts with intentionally weak, common passwords.

This is for the brute-force lab ONLY. These accounts exist purely so the
attacker script has real (but harmless) targets to guess against locally.

Run with:
    python manage.py seed_users
"""
from django.core.management.base import BaseCommand
from django.contrib.auth.models import User


DEMO_USERS = [
    ("alice", "password123"),
    ("bob", "qwerty123"),
    ("carol", "letmein"),
    ("admin", "admin123"),
]


class Command(BaseCommand):
    help = "Seed demo user accounts with weak passwords for the bruteforce lab"

    def handle(self, *args, **options):
        for username, password in DEMO_USERS:
            user, created = User.objects.get_or_create(username=username)
            user.set_password(password)  # Django hashes this properly even though the password is weak
            user.is_staff = False
            user.is_superuser = False
            user.save()

            status = "created" if created else "updated"
            self.stdout.write(self.style.SUCCESS(f"{status}: {username} / {password}"))

        self.stdout.write(self.style.WARNING(
            "\nThese accounts exist ONLY for local brute-force testing. "
            "Never reuse these usernames/passwords anywhere real."
        ))