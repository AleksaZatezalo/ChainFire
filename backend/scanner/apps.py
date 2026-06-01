from django.apps import AppConfig


class ScannerConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "scanner"

    def ready(self) -> None:
        import os
        # Only start in the main process, not Django's reloader child process
        if os.environ.get("RUN_MAIN") != "true":
            from .services.scheduler import start_scheduler
            start_scheduler()
