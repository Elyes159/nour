from django.apps import AppConfig


class FlutterAppConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'patient'
    
# from django.db.models.signals import post_migrate
# from django.core.signals import request_started

# class MyAppConfig(AppConfig):
#     default_auto_field = 'django.db.models.BigAutoField'
#     name = 'myapp'

#     def ready(self):
#         from .views import envoyer_rappel_rendez_vous
#         from django.db.models.signals import post_migrate
#         from django.core.signals import request_started

#         # Exécuter la tâche dès que le serveur est prêt
#         post_migrate.connect(envoyer_rappel_rendez_vous)
#         request_started.connect(envoyer_rappel_rendez_vous)

