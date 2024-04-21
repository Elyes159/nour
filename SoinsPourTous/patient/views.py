import datetime
import json
import logging
from random import randint
from django.http import HttpResponse, HttpResponseServerError, JsonResponse
from django.shortcuts import get_object_or_404,redirect
from rest_framework.response import Response
from rest_framework.authentication import SessionAuthentication, BasicAuthentication
from patient.models import  Otp, PasswordResetToken, Token, User1,Message
from patient.utils import IsAuthenticatedUser, send_otp, send_password_reset_email, token_response, token_response_Agent, token_response_doctor
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
    
    
    
from .models import Agent, Medecin, PageAcceuil, RendezVous, Room, TokenForAgent, TokenForDoctor  # Importez le modèle Medecin
  
    
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

            
    




    
    