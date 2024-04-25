from django.contrib import admin
from .models import Hopital, Service, Grade, Groupe, Specialite, Medecin, Gouvernorat, Nationality, User1, Otp, Token, TokenForDoctor, PasswordResetToken, Room, Message, PageAcceuil, RendezVous, Agent, TokenForAgent, payment

# Enregistrement des modèles dans l'interface d'administration

@admin.register(Hopital)
class HopitalAdmin(admin.ModelAdmin):
    list_display = ['id', 'nom', 'adresse']

@admin.register(Service)
class ServiceAdmin(admin.ModelAdmin):
    list_display = ['id', 'service', 'hopitale']

@admin.register(Grade)
class GradeAdmin(admin.ModelAdmin):
    list_display = ['id', 'gradee']

@admin.register(Groupe)
class GroupeAdmin(admin.ModelAdmin):
    list_display = ['id', 'groupe', 'tarif']

@admin.register(Specialite)
class SpecialiteAdmin(admin.ModelAdmin):
    list_display = ['id', 'specialite', 'service']

@admin.register(Medecin)
class MedecinAdmin(admin.ModelAdmin):
    list_display = ['id', 'username', 'groupe', 'grade', 'sepcialite', 'service']

@admin.register(Gouvernorat)
class GouvernoratAdmin(admin.ModelAdmin):
    list_display = ['id', 'options']

@admin.register(Nationality)
class NationalityAdmin(admin.ModelAdmin):
    list_display = ['id', 'nationality']

@admin.register(User1)
class User1Admin(admin.ModelAdmin):
    list_display = ['id', 'email', 'username', 'phone', 'fullname', 'adresse', 'created_at', 'gouvernorat', 'nationalite', 'sexe', 'image', 'date_naiss']

@admin.register(Otp)
class OtpAdmin(admin.ModelAdmin):
    list_display = ['phone', 'otp', 'validity', 'verified']

@admin.register(Token)
class TokenAdmin(admin.ModelAdmin):
    list_display = ['token', 'user', 'created_at']

@admin.register(TokenForDoctor)
class TokenForDoctorAdmin(admin.ModelAdmin):
    list_display = ['token', 'user', 'created_at']

@admin.register(PasswordResetToken)
class PasswordResetTokenAdmin(admin.ModelAdmin):
    list_display = ['token', 'user', 'validity', 'created_at']

@admin.register(Room)
class RoomAdmin(admin.ModelAdmin):
    list_display = ['code']

@admin.register(Message)
class MessageAdmin(admin.ModelAdmin):
    list_display = ['value', 'date', 'user', 'room']

@admin.register(PageAcceuil)
class PageAcceuilAdmin(admin.ModelAdmin):
    list_display = ['postwithimage', 'postwithtet']

@admin.register(RendezVous)
class RendezVousAdmin(admin.ModelAdmin):
    list_display = ['date_rendez_vous', 'patient', 'medecin']

@admin.register(Agent)
class AgentAdmin(admin.ModelAdmin):
    list_display = ['id_agent', 'username', 'password']

@admin.register(TokenForAgent)
class TokenForAgentAdmin(admin.ModelAdmin):
    list_display = ['token', 'user', 'created_at']

@admin.register(payment)
class PaymentAdmin(admin.ModelAdmin):
    list_display = ['id', 'patient', 'date']

# Enregistrez les autres modèles de la même manière
