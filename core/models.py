"""
Shared logging models used across every vulnerability lab.

This is the common ground floor: every lab (bruteforce, xss, csrf, sqli...)
writes its attack/attempt events here so the dashboard can show a unified
view across the whole project, instead of each lab keeping its own
disconnected log.
"""
from django.db import models


class LabEvent(models.Model):
    """
    A single logged event from any lab (a login attempt, an XSS payload
    submission, a CSRF form submission, etc).

    Kept intentionally generic so every future lab can reuse it without
    schema changes - the `lab_name` and `event_type` fields let the
    dashboard group and filter without needing a new table per lab.
    """

    LAB_CHOICES = [
        ('bruteforce', 'Brute Force'),
        ('xss', 'Cross-Site Scripting'),
        ('csrf', 'CSRF'),
        ('sqli', 'SQL Injection'),
    ]

    lab_name = models.CharField(max_length=50, choices=LAB_CHOICES)
    event_type = models.CharField(
        max_length=50,
        help_text="e.g. 'login_attempt', 'lockout_triggered', 'payload_submitted'",
    )
    security_mode = models.CharField(
        max_length=20,
        help_text="'vulnerable' or 'hardened' - which mode was active when this happened",
    )

    ip_address = models.GenericIPAddressField(null=True, blank=True)
    username_attempted = models.CharField(max_length=150, blank=True)
    success = models.BooleanField(default=False)

    # Free-form details specific to the event (e.g. payload text, error shown)
    detail = models.TextField(blank=True)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['lab_name', 'created_at']),
            models.Index(fields=['ip_address']),
        ]

    def __str__(self):
        outcome = 'SUCCESS' if self.success else 'FAIL'
        return f"[{self.lab_name}] {self.event_type} ({outcome}) from {self.ip_address} at {self.created_at:%Y-%m-%d %H:%M:%S}"