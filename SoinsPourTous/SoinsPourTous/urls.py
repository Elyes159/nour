"""SoinsPourTous URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import include, path
from patient.views import  add_medecin, add_service, add_specialite, ajout_rendez_vous_par_agent, checkview, create_account, delete_medecin, delete_service, delete_specialite, deleteRendezVousA, deleteRendezVousD, envoyer_rappel_rendez_vous, gestion_agent, get_agent_rendezvous_apc, getApcForAgent, getChatMedecin, getChatPatient, getPaiementHistorique, getProfileAgent, getProfileDoctor, getProfilePatient, getRendezVousHDoctor, getRendezVousHPatient, getRendezVousPatient, getmessage, login, login_pour_agent, login_pour_medecin, logout_Agent, logout_medecin, logout_patient, modify_medecin, password_reset_confirm, password_reset_form, password_updated, request_otp, resend_otp, suivi_apc, updateRendezVousDateA, updateRendezVousDateD, user1Data, verify_otp,password_reset_email ,send,getPageAcceuil
from SoinsPourTous import settings
from django.conf.urls.static import static
urlpatterns = [
    path('admin/', admin.site.urls),
    path('api-auth/', include('rest_framework.urls')),
    path('request_otp/',request_otp, name = 'request_otp'),
    path('resend_otp/',resend_otp,name='resend_otp'),
    path('verify_otp/', verify_otp),
    path('create_account/',create_account, name = 'create_account'),
    path('password_reset_email/',password_reset_email,name='password_reset_email'),
    path('password_reset_form/<email>/<token>/', password_reset_form, name='password_reset_form'),
    path('login/',login,name='login'),
    path('password_reset_confirm/<email>/<token>',password_reset_confirm,name='password_reset_confirm'),
    path('password_updated/', password_updated, name='password_updated'),
    path('userdata/',user1Data,name='userdata'),
    path('medecinlogin/',login_pour_medecin),
    path('<token>/<username>/checkview/', checkview, name='checkview'),
    path('<token>/<username>/<room_code>/send/', send, name='send'),
    path('<token>/getMessage/<str:room>/', getmessage),
    path('agentlogin/',login_pour_agent),
    path('ajoutRendezVousParAgent/<token>/',ajout_rendez_vous_par_agent),
    path('getpageacceuil/<str:token>/',getPageAcceuil),
    path('getProfilePatient/<token>/',getProfilePatient),
    path('getProfileDoctor/<token>/',getProfileDoctor),
    path('envoyer_rappel_rendez_vous/', envoyer_rappel_rendez_vous, name='envoyer_rappel_rendez_vous'),
    path('getpaiementHistorique/<token>/',getPaiementHistorique),
    path('agentprofile/<token>/',getProfileAgent),
    path('suivi_apc/<token>/',suivi_apc),
    path('gestionagent/<token>/',gestion_agent),
    path('delete_service/<token>/<id>/', delete_service, name='delete_service'),
    path('delete_specialite/<token>/<id>/', delete_specialite, name='delete_specialite'),
    path('delete_medecin/<token>/<id>/', delete_medecin, name='delete_medecin'),
    path('add_service/<token>/', add_service, name='add_service'),
    path('add_specialite/<token>/', add_specialite, name='add_specialite'),
    path('add_medecin/<token>/', add_medecin, name='add_medecin'),
    path('modify_medecin/<int:token>/', modify_medecin, name='modify_medecin'),
    path('get_agent_rendezvous_apc/<int:token>/',get_agent_rendezvous_apc, name='get_agent_rendezvous_apc'),
    path('getPatientRdvH/<token>/',getRendezVousHPatient),
    path("getPatientRdv/<token>/",getRendezVousPatient),
    path("getRdvHDoctor/<token>/",getRendezVousHDoctor),
    path("updateRdvDateDoctor/<token>/<rendez_vous_id>/",updateRendezVousDateD),
    path("updateRdvDateAgent/<token>/<rendez_vous_id>/",updateRendezVousDateA),
    path("deleteRendezVousDoctor/<token>/<rendez_vous_id>/",deleteRendezVousD),
    path("deleteRendezVousAgent/<token>/<rendez_vous_id>/",deleteRendezVousA),
    path("getApcForAgent/<token>/",getApcForAgent),
    path("logoutAgent/<token>/",logout_Agent),
    path("logoutMedecin/<token>/",logout_medecin),
    path("logoutPatient/<token>/",logout_patient),
    path('getPatientRooms/<token>/',getChatPatient),
    path('getMedecinRooms/<token>/',getChatMedecin),
    


    

]

if settings.DEBUG:
    urlpatterns+= static(settings.MEDIA_URL,document_root=settings.MEDIA_ROOT)