from django.contrib import admin
from .models import LabEvent


@admin.register(LabEvent)
class LabEventAdmin(admin.ModelAdmin):
    list_display = ('created_at', 'lab_name', 'event_type', 'username_attempted', 'ip_address', 'success', 'security_mode')
    list_filter = ('lab_name', 'event_type', 'success', 'security_mode')
    search_fields = ('username_attempted', 'ip_address', 'detail')
    ordering = ('-created_at',)