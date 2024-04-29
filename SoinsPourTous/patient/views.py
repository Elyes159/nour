import datetime
import json
import logging
from random import randint
from django.http import HttpResponse, HttpResponseServerError, JsonResponse
from django.shortcuts import get_object_or_404,redirect
from rest_framework.response import Response
from rest_framework.authentication import SessionAuthentication, BasicAuthentication
from patient.models import  Otp, PasswordResetToken, Token, User1,Message,Payment
from patient.utils import IsAuthenticatedUser, new_token, send_otp, send_password_reset_email, token_response, token_response_Agent, token_response_doctor
from rest_framework.parsers import FormParser
from rest_framework.decorators import api_view
from django.contrib.auth.hashers import make_password,check_password
from django.shortcuts import render
from django.views.decorators.csrf import ensure_csrf_cookie,csrf_protect
from django.views.decorators.csrf import csrf_exempt
from django.template.loader import get_template
from django.template import loader
from patient.serializers import   UserSerializer
from SoinsPourTous.settings import TEMPLATES_BASE_URL
from rest_framework.decorators import permission_classes
from rest_framework.permissions import IsAuthenticated ,DjangoModelPermissions,AllowAny
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from django.http import Http404
from django.utils import timezone
from datetime import timedelta
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.decorators import login_required, permission_required

from django.contrib.auth.models import  User


@api_view(['POST'])
@authentication_classes([SessionAuthentication, BasicAuthentication])
def request_otp(request):
    email = request.data.get('email')
    phone = request.data.get('phone')

    if email and phone:
        if User1.objects.filter(email=email).exists():
            return JsonResponse({'error': 'Email already exists'}, status=400)

        if User1.objects.filter(phone=phone).exists():
            return JsonResponse({'error': 'Phone already exists'}, status=400)

        return send_otp(phone)
    else:
        return JsonResponse({'error': 'Data missing'}, status=400)
    
@api_view(['POST'])
@authentication_classes([SessionAuthentication, BasicAuthentication])
def resend_otp(request) : 
    phone = request.data.get('phone')
    if not phone : 
        return Response('data_missing',400)
    return send_otp(phone)


# Créer un objet logger
logger = logging.getLogger(__name__)
#tabda
@api_view(['POST'])
@authentication_classes([SessionAuthentication, BasicAuthentication])
def verify_otp(request):
    try:
        phone = request.data.get('phone')
        otp = request.data.get('otp')

        print(f"Received OTP: {otp}")
        print(f"Received phone: {phone}")

        if not phone or not otp:
            return JsonResponse({'error': 'Phone or OTP missing in the request'}, status=400)

        otp_obj = get_object_or_404(Otp, phone=phone, verified=False)

        
            # Si la validité n'est pas définie, créez une validité de 10 minutes à partir du temps actuel
        validity_duration = timedelta(minutes=10)
        otp_obj.validity = timezone.now() + validity_duration
        otp_obj.save()

        # Utilisez make_aware pour ajouter le fuseau horaire par défaut
        validity_datetime = timezone.make_aware(datetime.datetime.combine(otp_obj.validity, datetime.datetime.now().time()))

        print(f"Validity datetime: {validity_datetime}")
        print(f"Current datetime: {timezone.now()}")

        
        if otp_obj.otp == int(otp):
            try:
                otp_obj.verified = True
                otp_obj.save()
                return JsonResponse({'message': 'otp_verified successfully'})
            except Exception as e:
                print(f"An error occurred during OTP verification: {e}")
                return JsonResponse({'error': 'Error during OTP verification'}, status=500)
        else:
            print("Incorrect otp")
            return JsonResponse({'error': 'Incorrect otp'}, status=400)

        
    except AuthenticationFailed as e:
        logger.error(f'Authentication failed: {e}', exc_info=True)
        return JsonResponse({'error': 'Authentication failed'}, status=401)
    except Http404:
        logger.error('Otp not found', exc_info=True)
        return JsonResponse({'error': 'Otp not found'}, status=404)
    except Exception as e:
        logger.error(f'Error in verify_otp: {e}', exc_info=True)
        print(f'ouni 3asba {e}')
        return JsonResponse({'error': 'Internal Server Error'}, status=500)


@csrf_exempt
@api_view(['POST'])
@authentication_classes([SessionAuthentication, BasicAuthentication])
def create_account(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body.decode('utf-8'))

            email = data.get('email')
            phone = data.get('phone')
            password = data.get('password')
            fullname = data.get('fullname')

            print(f"Received data - Email: {email}, Phone: {phone}, Password: {password}, Fullname: {fullname}")

            if email and phone and password and fullname:
                print(f"Trying to find Otp for phone: {phone}")
                # otp_obj = get_object_or_404(Otp, phone=phone, verified=True)
                # print("houni : ",otp_obj)
                # print(f"Found Otp: {otp_obj}")
                User1.objects.create(email=email, phone=phone, fullname=fullname, password=password)
                # otp_obj.delete()
                return JsonResponse({"message": "account created successfully"})
            else:
                error_message = "Invalid data provided. "
                if not email:
                    error_message += "Email is required. "
                if not phone:
                    error_message += "Phone is required. "
                if not password:
                    error_message += "Password is required. "
                if not fullname:
                    error_message += "Fullname is required. "

                print(f"Error message: {error_message.strip()}")

                return JsonResponse({"error": error_message.strip()}, status=400)

        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON format in the request body"}, status=400)

        except Exception as e:
            print(f"Error: {str(e)}")
            return JsonResponse({"error": "An error occurred while processing the request"}, status=500)

    return JsonResponse({"error": "Invalid request method"}, status=405)

@csrf_exempt 
@api_view(['POST'])
@authentication_classes([SessionAuthentication, BasicAuthentication])
def login(request):
    email = request.data.get('email')
    phone = request.data.get('phone')
    password = request.data.get('password')

    if email:
        user1 = User1.objects.filter(email=email).first()
        
        password1 = user1.password if user1 else None
    elif phone:
        user1 = User1.objects.filter(phone=phone).first()
        password1 = user1.password if user1 else None
    else:
        return JsonResponse({'error': 'data missing'}, status=400)

    if user1 :
        if password == password1:
            return token_response(user1)
        else :
            return JsonResponse({'response':'mdpincorrecte'})
    else:
        return JsonResponse({'error': 'incorrect password'}, status=400)
    
    
    
from .models import Agent, Apc, Grade, Groupe, Medecin, PageAcceuil, RendezVous, Room, Service, Specialite, TokenForAgent, TokenForDoctor  # Importez le modèle Medecin
  
    
@csrf_exempt 
@api_view(['POST'])
@authentication_classes([SessionAuthentication, BasicAuthentication])
def login_pour_medecin(request):
    print("bfab5c9efb8011eea494845cf3a65946")
    username = request.data.get('username')
    password = request.data.get('password')

    if username:
        user1 = Medecin.objects.filter(username=username).first()
        
        password1 = user1.password if user1 else None
    
    else:
        return JsonResponse({'error': 'data missing'}, status=400)

    if user1 :
        if password == password1:
            return token_response_doctor(user1)
        else :
            return JsonResponse({'response':'mdpincorrecte'})
    else:
        return JsonResponse({'error': 'incorrect password'}, status=400)
    
    
    
@csrf_exempt 
@api_view(['POST'])
@authentication_classes([SessionAuthentication, BasicAuthentication])
def login_pour_agent(request):
    username = request.data.get('username')
    password = request.data.get('password')

    if username:
        user1 = Agent.objects.filter(username=username).first()
        
        password1 = user1.password if user1 else None
    
    else:
        return JsonResponse({'error': 'data missing'}, status=400)

    if user1 :
        if password == password1:
            return token_response_Agent(user1)
        else :
            return JsonResponse({'response':'mdpincorrecte'})
    else:
        return JsonResponse({'error': 'incorrect password'}, status=400)
    

@csrf_exempt 
@api_view(['POST'])
@authentication_classes([SessionAuthentication, BasicAuthentication])
def ajout_rendez_vous_par_agent(request , token) : 
        token = TokenForAgent.objects.filter(token=token).first()
        if request.method == 'POST':
            date_de_rdv = request.data.get('date_de_rdv')
            medecin = request.data.get('medecin')
            patient = request.data.get('patient')
            dateExist = RendezVous.objects.filter(date_rendez_vous = date_de_rdv)
            medecinExist = Medecin.objects.filter(username = medecin).exists()
            patientExist = User1.objects.filter(username = patient)
            
            if not(dateExist) and patientExist and medecinExist : 
               rdv =  RendezVous.objects.create(date_rendez_vous = date_de_rdv,patient = patient , medecin = medecin)
               rdv.save()
               return JsonResponse({'success': 'Rendez-vous ajouté avec succès'}, status=201)

            elif dateExist and patientExist and medecinExist : 
                return JsonResponse({'erreur rendez-vous': 'Rendez vous avec ce medecin et ce patient existe déja'}, status=400)
            else : 
                return JsonResponse({'Donnee erreur ': 'Il y a quelque donnees manquante'}, status=400)
        else : 
            return JsonResponse({"error": "Invalid request method"}, status=405)

                
@api_view(['GET', 'POST'])
@authentication_classes([SessionAuthentication, BasicAuthentication])
def password_reset_email(request):
    if request.method == 'GET':
        return render(request, 'emails/reset-password.html')
    
    elif request.method == 'POST':
        email = request.data.get('email')
        if not email:
            return JsonResponse({'error': 'params_missing'}, status=400)

        user1 = User1.objects.filter(email=email).first()
        
        send_password_reset_email(user1)
        return JsonResponse({'message': 'password_reset_email_sent'}, status=200)
    
    return JsonResponse({'error': 'Method Not Allowed'}, status=405)

@api_view(['GET'])
@authentication_classes([SessionAuthentication, BasicAuthentication])
def password_reset_form(request, email, token):
    token_instance = PasswordResetToken.objects.filter(user__email=email, token=token).first()
    link_expired = loader.get_template('pages/link-expired.html').render()

    if token_instance:
        if datetime.datetime.utcnow() < token_instance.validity.replace(tzinfo=None):
            return render(request, 'pages/new-password-form.html', {
                'email': email,
                'token': token,
                'base_url': TEMPLATES_BASE_URL,
            })
        else:
            token_instance.delete()
            return HttpResponse(link_expired)

    else:
        return HttpResponse(link_expired)
        
@api_view(['POST'])
@authentication_classes([SessionAuthentication, BasicAuthentication])
def password_reset_confirm(request, email, token):
    email = request.data.get('email')
    token = request.data.get('token')
    password1 = request.data.get('password1')
    password2 = request.data.get('password2')
    print(password1)
    
    token_instance = PasswordResetToken.objects.filter(user__email=email, token=token).first()
    link_expired = get_template('pages/link-expired.html').render()
    if token_instance:
        if datetime.datetime.utcnow() < token_instance.validity.replace(tzinfo=None):
            if len(password1) < 8:
                return render(request, 'pages/new-password-form.html', {
                    'email': email,
                    'token': token,
                    'base_url': TEMPLATES_BASE_URL,
                    'error': 'Password length must be at least 8'
                })

            if password1 == password2:
                link_success = get_template('pages/password-updated.html').render()
                user1 = token_instance.user
                User1.objects.filter(email=user1.email).update(password=password1)
                token_instance.delete()
                Token.objects.filter(user=user1).delete()
                return HttpResponse(link_success)
            else:
                return render(request, 'pages/new-password-form.html', {
                    'email': email,
                    'token': token,
                    'base_url': TEMPLATES_BASE_URL,
                    'error': 'Password 1 must be equal to password 2'
                })
        else:
            token_instance.delete()
            return HttpResponse(link_expired)
    else:
        return HttpResponse(link_expired)
@api_view(['GET'])
@authentication_classes([SessionAuthentication, BasicAuthentication])
def password_updated(request) : 
    return render(request,'pages/password-updated.html')
@api_view(['GET'])
@authentication_classes([SessionAuthentication, BasicAuthentication])
@permission_classes([IsAuthenticated])
@login_required
def user1Data(request):
    print("Vue user1Data atteinte")
    if request.user1.is_authenticated:
        user1 = request.user1
        print("houni : ",user1)
        # Vous pouvez adapter cette logique en fonction de votre modèle User1
        data = {
            'email': user1.email,
            'fullname': user1.fullname,
            'phone': user1.phone,
            # Ajoutez d'autres champs si nécessaire
        }

        return JsonResponse(data)
    else:
        return JsonResponse({'detail': 'User1 not authenticated'}, status=401)
    
    
def room(request) : 
    pass

@api_view(['POST'])
@authentication_classes([SessionAuthentication, BasicAuthentication])
def checkview(request,token,username):
    token = TokenForDoctor.objects.filter( token=token, user__username = username ).exists()
    if request.method == 'POST':
        room_code = request.data.get('room_code')
        if room_code and username and token:
            if Room.objects.filter(code=room_code).exists() and Medecin.objects.filter(username = username).exists():
                return JsonResponse({'message': 'Bienvenue dans votre chat'}, status=200)
            elif (Medecin.objects.filter(username = username).exists() and not(Room.objects.filter(code=room_code).exists())):
                new_room = Room.objects.create(code=room_code)
                new_room.save()
                return JsonResponse({'message': 'Un nouveau chat créé'}, status=200)
            else : 
                return JsonResponse({'erreurre': 'docteur nexiste pas'}, status=200)

        else:
            return JsonResponse({'message': 'Code de salle non fourni'}, status=400)
    else:
        return JsonResponse({'message': 'Méthode non autorisée'}, status=405)
    
    
from django.http import JsonResponse
from .models import Message


@api_view(['POST'])
@authentication_classes([SessionAuthentication, BasicAuthentication])
def send(request,token,username,room_code):
    token = TokenForDoctor.objects.filter(token=token , user__username=username).exists() if token else Token.objects.filter(token=token,user__username=username).exists()

    if request.method == 'POST':
        message = request.data.get('message')
        
        if message and username and room_code and token:
            # Vérifier si le username appartient à un utilisateur ou à un médecin
            if (User1.objects.filter(username=username).exists() or Medecin.objects.filter(username=username).exists()) and Room.objects.filter(code = room_code).exists():
                # Créez un nouvel objet Message avec les données fournies
                user_type = 'patient' if User1.objects.filter(username=username).exists() else 'medecin'
                
                # Créer un nouvel objet Message avec les données fournies
                new_message = Message.objects.create(value=message, user=f'{username}-{user_type}', room=room_code)
                new_message.save()
                
                return JsonResponse({'message': 'Message envoyé avec succès'}, status=201)
            else:
                return JsonResponse({'error': 'Nom d\'utilisateur invalide'}, status=400)
        else:
            return JsonResponse({'error': 'Données manquantes'}, status=400)
    else:
        return JsonResponse({'error': 'Méthode non autorisée'}, status=405)



@api_view(['GET'])
@authentication_classes([SessionAuthentication, BasicAuthentication])
def getmessage(request, room,token):
    token = TokenForDoctor.objects.filter( token=token).exists()

    try:
        room_details = Room.objects.get(code=room)
        messages = Message.objects.filter(room=room_details.code).order_by('date')
        return JsonResponse({'messages': list(messages.values())}, status=200)
    except Room.DoesNotExist:
        return JsonResponse({'error': 'La salle spécifiée n\'existe pas'}, status=404)



from django.http import HttpResponse, JsonResponse
from rest_framework.decorators import api_view
from rest_framework.authentication import SessionAuthentication, BasicAuthentication
from .models import PageAcceuil

import base64

@api_view(['GET'])
@authentication_classes([SessionAuthentication, BasicAuthentication])
def getPageAcceuil(request, token):
    token_obj = TokenForDoctor.objects.filter(token=token).exists() if token else Token.objects.filter(token=token).exists()
    if request.method == 'GET':
        if token_obj:
            page_acceuil_data = PageAcceuil.objects.values()  # Obtenir toutes les données
            for data in page_acceuil_data:
                postwithimage_path = data['postwithimage']
                with open(postwithimage_path, "rb") as image_file:
                    encoded_string = base64.b64encode(image_file.read()).decode('utf-8')
                data['postwithimage'] = encoded_string  # Remplacer le chemin d'accès par la représentation base64
            return JsonResponse(list(page_acceuil_data), safe=False)  # Renvoyer les données au format JSON
        else:
            return JsonResponse({"error": "Token invalide"}, status=400)
        
        
        
from django.http import JsonResponse
import base64

@api_view(['GET'])
@authentication_classes([SessionAuthentication, BasicAuthentication])
def getProfilePatient(request, token):
    token_obj = Token.objects.filter(token=token).first()
    if request.method == 'GET':
        if token_obj:
            user_obj = token_obj.user
            username_patient = user_obj.username
            email_patient = user_obj.email
            phone_patient = user_obj.phone
            fullname_patient = user_obj.fullname
            image_path = user_obj.image.path
            with open(image_path, "rb") as image_file:
                encoded_string = base64.b64encode(image_file.read()).decode('utf-8')
            user_data = {
                'username': username_patient,
                'email': email_patient,
                'phone': phone_patient,
                'fullname': fullname_patient,
                'image': encoded_string
            }

            # Retour des données sous forme de réponse JSON
            return JsonResponse(user_data)
        else:
            return JsonResponse({"error": "Token invalide"}, status=400)
        
        
@api_view(['GET'])
@authentication_classes([SessionAuthentication, BasicAuthentication])
def getProfileDoctor(request, token):
    token_obj = TokenForDoctor.objects.filter(token=token).first()
    if request.method == 'GET':
        if token_obj:
            user_obj = token_obj.user
       
            username_patient = user_obj.username

            
            user_data = {
                'username': username_patient,
            }

            # Retour des données sous forme de réponse JSON
            return JsonResponse(user_data)
        else:
            return JsonResponse({"error": "Token invalide"}, status=400)
        
        
@api_view(['GET'])
@authentication_classes([SessionAuthentication, BasicAuthentication])
def getProfileAgent(request, token):
    token_obj = TokenForAgent.objects.filter(token=token).first()
    if request.method == 'GET':
        if token_obj:
            user_obj = token_obj.user
       
            username_patient = user_obj.username

            
            user_data = {
                'username': username_patient,
            }

            # Retour des données sous forme de réponse JSON
            return JsonResponse(user_data)
        else:
            return JsonResponse({"error": "Token invalide"}, status=400)
        
        
@api_view(['GET'])
@authentication_classes([SessionAuthentication, BasicAuthentication])
def getRendezVousDoctor(request, token):
    token_obj = TokenForDoctor.objects.filter(token=token).first()
    if request.method == 'GET':
        if token_obj:
            user_obj = token_obj.user
            username_medecin = user_obj.username
            date_rdv = RendezVous.objects.filter(medecin = username_medecin )
            user_data = {
                'username': username_medecin,
                'date_rdv' : date_rdv
            }
            return JsonResponse(user_data)
        else:
            return JsonResponse({"error": "Token invalide"}, status=400)
        
        
        
@api_view(['GET'])
@authentication_classes([SessionAuthentication, BasicAuthentication])
def getRendezVousPatient(request, token):
    token_obj = Token.objects.filter(token=token).first()
    if request.method == 'GET':
        if token_obj:
            user_obj = token_obj.user
            username_patient = user_obj.username
            date_rdv = RendezVous.objects.filter(patient = username_patient )
            user_data = {
                'username': username_patient,
                'date_rdv' : date_rdv
            }
            return JsonResponse(user_data)
        else:
            return JsonResponse({"error": "Token invalide"}, status=400)
        
@api_view(['GET'])
@authentication_classes([SessionAuthentication, BasicAuthentication])
def getPaiementHistorique(request, token):
    token_obj = Token.objects.filter(token=token).first()
    if request.method == 'GET':
        if token_obj:
            user_obj = token_obj.user
            username_email = user_obj.email
            paiements = Payment.objects.filter(patient__email = username_email )
            
            paiements_data = []
            for paiement in paiements:
                # Ajouter les données du paiement à la liste
                paiement_data = {
                    "montant": paiement.payé,
                    "date": paiement.date,  # Convertir la date en format string
                    # Ajoutez d'autres champs de paiement si nécessaire
                }
                paiements_data.append(paiement_data)
            
            # Renvoyer la liste des paiements sous forme de réponse JSON
            return JsonResponse(paiements_data, safe=False)
        else:
            return JsonResponse({"error": "Token invalide"}, status=400)

from django.core.mail import send_mail
from celery import shared_task


@shared_task
def envoyer_rappel_rendez_vous(request):
    aujourd_hui = timezone.now().date()
    demain = aujourd_hui + timezone.timedelta(days=1)

    rendez_vous_demain = RendezVous.objects.filter(date_rendez_vous=demain)

    for rendez_vous in rendez_vous_demain:
        # Récupérez l'objet patient individuel
        patient = rendez_vous.patient

        message = f"""
        Rappel de rendez-vous:

        Patient: {patient.username}
        Médecin: {rendez_vous.medecin.username}
        Date: {rendez_vous.date_rendez_vous}

        N'oubliez pas votre rendez-vous !
        """

        send_mail(
            "Rappel de rendez-vous",
            message,
            "elyesmlik307@gmail.com",
            [patient.email],
            fail_silently=False
        )

        data = {
            "message": message
        }

        return JsonResponse(data)

    data = {
        "message": "Aucun rendez-vous n'est prévu pour demain."
    }
    return JsonResponse(data)

from django.db.models import Count


from django.db.models import Count
from datetime import datetime

@api_view(['POST'])
@authentication_classes([SessionAuthentication, BasicAuthentication])
def suivi_apc(request, token):
    if request.method == 'POST':
        token = TokenForDoctor.objects.filter(token=token).first()
        if token:
            month = request.data.get("month")
            month_date = datetime.strptime(month, "%Y-%m")
            
            rendez_vous = RendezVous.objects.filter(date_rendez_vous__year=month_date.year,
                                                     date_rendez_vous__month=month_date.month)
            apc = Apc.objects.filter(date__year=month_date.year,
                                     date__month=month_date.month)
            
            total_patients = rendez_vous.aggregate(num_patients=Count('patient'))['num_patients'] + \
                             apc.aggregate(num_patients=Count('patient'))['num_patients']
            
           
            rendez_vous_list = [rv.id for rv in rendez_vous]
            apc_list = [a.id for a in apc]
            
            return Response({
                'rendez_vous': rendez_vous_list,
                'apc': apc_list,
                'total_patients': total_patients
            })
            
@api_view(['POST'])
@authentication_classes([SessionAuthentication, BasicAuthentication])
def gestion_agent(request, token):
    if request.method == "POST":
        token_agent = TokenForAgent.objects.filter(token=token).first()
        agent = token_agent.user
        if agent:
            hopital = agent.hopital
            services = Service.objects.filter(hopitale=hopital)

            specialites = Specialite.objects.filter(service__in=services)

            medecins = Medecin.objects.filter(hopitale=hopital)

           
            groupes = list(medecins.values_list('groupe__groupe', flat=True))

            return Response({
                'services': [service.service for service in services],
                'specialites': [specialite.specialite for specialite in specialites],
                'grades': [medecin.grade.gradee for medecin in medecins],  # Access gradee field
                'groupes': groupes
            })
        else:
            return Response({'message': 'Agent non trouvé'}, status=400)
        
@api_view(['DELETE'])
@authentication_classes([SessionAuthentication, BasicAuthentication])
def delete_service(request, token,id):
    if request.method == "DELETE":
        service = get_object_or_404(Service,pk=id)
        token_agent = TokenForAgent.objects.filter(token = token).first()
        agent = token_agent.user
        if service.hopitale.id == agent.hopital.id:  # Check if agent belongs to the same hospital
            service.delete()
            return Response({'message': 'Service supprimé avec succès'})
        else:
            return Response({'message': 'Vous ne pouvez pas supprimer un service d\'un autre hôpital'}, status=403)
        
        
@api_view(['DELETE'])
@authentication_classes([SessionAuthentication, BasicAuthentication])
def delete_specialite(request, token,id):
    if request.method == "DELETE":
        specialite = get_object_or_404(Specialite, pk=id)
        token_agent = TokenForAgent.objects.filter(token = token).first()
        agent = token_agent.user
        if specialite.service.hopitale.id == agent.hopital.id:
            specialite.delete()
            return Response({'message': 'Spécialité supprimée avec succès'})
        else:
            return Response({'message': 'Vous ne pouvez pas supprimer une spécialité d\'un autre hôpital'}, status=403)
        
@api_view(['DELETE'])
@authentication_classes([SessionAuthentication, BasicAuthentication])
def delete_medecin(request, token,id):
    if request.method == "DELETE":
        medecin = get_object_or_404(Medecin, pk=id)
        token_agent = TokenForAgent.objects.filter(token = token).first()
        agent = token_agent.user
        if medecin.hopitale.id == agent.hopital.id:
            medecin.delete()
            return Response({'message': 'Médecin supprimé avec succès'})
        else:
            return Response({'message': 'Vous ne pouvez pas supprimer un médecin d\'un autre hôpital'}, status=403)
        
from rest_framework import viewsets, permissions
from .models import Hopital, Service, Specialite, Medecin, Agent, TokenForAgent
from rest_framework.decorators import api_view, authentication_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from django.shortcuts import get_object_or_404

@api_view(['POST'])
@authentication_classes([SessionAuthentication, BasicAuthentication])
def add_service(request, token):
    if request.method == "POST":
        token_agent = TokenForAgent.objects.filter(token=token).first()
        agent = token_agent.user
        if agent:
            hopital = agent.hopital
            data = request.data

            service_name = data.get('service')
            if not service_name:
                return Response({'message': 'Le nom du service est obligatoire'}, status=400)

            # Check if service with the same name already exists in the hospital
            existing_service = Service.objects.filter(hopitale=hopital, service=service_name ).first()
            if existing_service:
                return Response({'message': 'Un service avec ce nom existe déjà dans cet hôpital'}, status=400)

            # Create the new service
            new_service = Service.objects.create(hopitale=hopital, service=service_name)
            return Response({'message': 'Service ajouté avec succès', 'service': new_service.id})
        else:
            return Response({'message': 'Agent non trouvé'}, status=400)

@api_view(['POST'])
@authentication_classes([SessionAuthentication, BasicAuthentication])
def add_specialite(request, token):
    if request.method == "POST":
        token_agent = TokenForAgent.objects.filter(token=token).first()
        agent = token_agent.user
        if agent:
            hopital = agent.hopital
            data = request.data

            service_id = data.get('service')
            specialite_name = data.get('specialite')

            if not service_id or not specialite_name:
                return Response({'message': 'Le service et la spécialité sont obligatoires'}, status=400)

            # Get the service object
            service = get_object_or_404(Service, pk=service_id, hopitale=hopital)

            # Check if specialty with the same name already exists in the service
            existing_specialite = Specialite.objects.filter(service=service, specialite=specialite_name).first()
            if existing_specialite:
                return Response({'message': 'Une spécialité avec ce nom existe déjà dans ce service'}, status=400)

            # Create the new specialty
            new_specialite = Specialite.objects.create(service=service, specialite=specialite_name)
            return Response({'message': 'Spécialité ajoutée avec succès', 'specialite': new_specialite.id})
        else:
            return Response({'message': 'Agent non trouvé'}, status=400)

@api_view(['POST'])
@authentication_classes([SessionAuthentication, BasicAuthentication])
def add_medecin(request, token):
    if request.method == "POST":
        token_agent = TokenForAgent.objects.filter(token=token).first()
        agent = token_agent.user
        if agent:
            hopital = agent.hopital
            data = request.data

            groupe_id = data.get('groupe')
            grade_id = data.get('grade')
            specialite_id = data.get('specialite')
            service_id = data.get('service')
            username = data.get('username')
            password = data.get('password')

            if not (groupe_id and grade_id and specialite_id and service_id and username and password):
                return Response({'message': 'Tous les champs obligatoires ne sont pas renseignés'}, status=400)

            try:
                # Check for missing service
                if not service_id:
                    return Response({'message': 'Le service est obligatoire'}, status=400)

                # Get the groupe, grade, specialite, and service objects
                groupe = Groupe.objects.get(pk=groupe_id)
                grade = Grade.objects.get(pk=grade_id)
                specialite = Specialite.objects.get(pk=specialite_id)
                service = Service.objects.get(pk=service_id)

                if groupe and grade and specialite and service:
                    doctor = Medecin.objects.create(
                        username=username,
                        password=password,
                        hopitale=hopital,
                        groupe=groupe,
                        grade=grade,
                        sepcialite=specialite,
                        service=service  # Assign the retrieved service object
                    )
                    return Response({'message': 'Médecin ajouté avec succès', 'medecin': doctor.id})
            except (Groupe.DoesNotExist, Grade.DoesNotExist, Specialite.DoesNotExist, Service.DoesNotExist):
                return Response({'message': 'Groupe, grade, spécialité ou service introuvable'}, status=400)
            except Exception as e:  # Catch other potential errors
                return Response({'message': f'Une erreur est survenue: {str(e)}'}, status=500)

        else:
            return Response({'message': 'Agent non trouvé'}, status=400)
        
        
@api_view(['POST'])
@authentication_classes([SessionAuthentication, BasicAuthentication])
def modify_medecin(request, token):
    if request.method == "POST":
        token_agent = TokenForAgent.objects.filter(token=token).first()
        agent = token_agent.user
        if agent:
            hopital = agent.hopital
            data = request.data

            medecin_id = data.get('medecin')
            garde_id = data.get('garde')
            groupe_id = data.get('groupe')
            username = data.get('username')

            if not (medecin_id and (garde_id or groupe_id or username)):
                return Response({'message': 'Veuillez renseigner au moins un champ à modifier'}, status=400)

            try:
                # Get the doctor object
                medecin = Medecin.objects.get(pk=medecin_id)

                # Check if the doctor belongs to the agent's hospital
                if medecin.hopitale != hopital:
                    return Response({'message': 'Vous ne pouvez pas modifier un médecin d\'un autre hôpital'}, status=400)

                # Update fields based on provided values
                if garde_id:
                    medecin.garde_id = garde_id
                if groupe_id:
                    medecin.groupe_id = groupe_id
                if username:
                    medecin.username = username

                medecin.save()
                return Response({'message': 'Médecin modifié avec succès'})
            except Medecin.DoesNotExist:
                return Response({'message': 'Médecin introuvable'}, status=400)
            except Exception as e:
                return Response({'message': f'Une erreur est survenue: {str(e)}'}, status=500)

        else:
            return Response({'message': 'Agent non trouvé'}, status=400)



@api_view(['GET'])
@authentication_classes([SessionAuthentication, BasicAuthentication])
def get_agent_rendezvous_apc(request, token):
    if request.method == "GET":
        token_agent = TokenForAgent.objects.filter(token=token).first()
        agent = token_agent.user
        if agent:
            hopital = agent.hopital

            # Get all appointments for the agent's hospital
            rendez_vous = RendezVous.objects.filter(medecin__hopitale=hopital)
            apc = Apc.objects.filter(medecin__hopitale=hopital)

            # Prepare data for response
            rendez_vous_data = []
            for rv in rendez_vous:
                rendez_vous_data.append({
                    "id": rv.id,
                    "date_rendez_vous": rv.date_rendez_vous.strftime("%Y-%m-%d"),  # Format date
                    "patient": rv.patient.username,  # Assuming username for patient identification
                    "medecin": rv.medecin.username,  # Assuming username for doctor identification
                })

            apc_data = []
            for a in apc:
                apc_data.append({
                    "id": a.id,
                    "date": a.date.strftime("%Y-%m-%d %H:%M:%S"),  # Format date and time
                    "patient": a.patient.username,  # Assuming username for patient identification
                    "medecin": a.medecin.username,  # Assuming username for doctor identification
                })

            return Response({
                "rendez_vous": rendez_vous_data,
                "apc": apc_data,
            })
        else:
            return Response({'message': 'Agent non trouvé'}, status=400)







        
       


            
    




    
    