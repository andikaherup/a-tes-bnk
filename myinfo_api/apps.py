from django.apps import AppConfig


class MyInfoApiConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'myinfo_api'
    verbose_name = 'MyInfo API Integration'

    def ready(self):
        """
        Perform initialization tasks when the app is ready.
        """
        # Import any signal handlers if needed
        # from . import signals
        pass