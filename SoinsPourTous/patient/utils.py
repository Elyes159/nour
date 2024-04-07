import datetime
from email.message import EmailMessage
from random import randint
import uuid
from django.http import JsonResponse
from rest_framework.response import Response
from django.template.loader import get_template
from django.utils.html import strip_tags
from django.template import Context
from patient.models import Otp, PasswordResetToken, Token
from SoinsPourTous.settings import TEMPLATES_BASE_URL
from rest_framework.permissions import BasePermission
from django.utils import timezone
from twilio.rest import Client # type: ignore



def send_otp(phone):
    # Génération de l'OTP
    otp = randint(100000, 999999)
    
    # Calcul de la validité de l'OTP (10 minutes à partir de maintenant)
    validity = datetime.datetime.now() + datetime.timedelta(minutes=10)
    
    # Sauvegarde de l'OTP dans la base de données
    Otp.objects.update_or_create(phone=phone, defaults={"otp": otp, "verified": False, "validity": validity})
    
    # Envoi de l'OTP par SMS via Twilio
    try:
        # Remplacez 'TWILIO_ACCOUNT_SID', 'TWILIO_AUTH_TOKEN', 'TWILIO_PHONE_NUMBER' par vos informations Twilio
        client = Client('ACf4c36e8d499a2bcdd4fa2a9e34c7d642', 'be330ae24f67a533ff54695e537c43e6')
        message = client.messages.create(
            body=f"Votre code OTP est : {otp}",
            from_='+12052368057',
            to=phone
        )
        print("OTP sent successfully:", message.sid)
        
        response_data = {
            'message': 'OTP sent successfully',
            'phone': phone,
            # Ajoutez d'autres données si nécessaire
        }
        return JsonResponse(response_data)
    except Exception as e:
        print("Failed to send OTP:", str(e))
        return JsonResponse({'message': 'Failed to send OTP'}, status=500)
def new_token() : 
    token = uuid.uuid1().hex
    return token
def token_response(user):
    token = new_token()
    Token.objects.create(token=token, user=user) 
    response_data = {
        'message': 'login successful',
        'token': token,
        'email' : user.email,
        'fullname' : user.fullname,
        'phone' : user.phone

    }
    print(token)

    return JsonResponse(response_data)
from django.core.mail import send_mail

def send_password_reset_email(user):
    token = new_token()
    exp_time = timezone.now() + timezone.timedelta(minutes=10)

    PasswordResetToken.objects.update_or_create(user=user, defaults={'user': user, 'token': token, 'validity': exp_time})

    email_data = {
        'token': token,
        'email': user.email,
        'base_url': TEMPLATES_BASE_URL
    }

    email_template = get_template('emails/reset-password.html')
    message = email_template.render(email_data)

    subject = 'Reset Password'
    recipients = [user.email]

    try:
        send_mail(subject, message, from_email=None, recipient_list=recipients, html_message=message)
        return JsonResponse({'message': 'reset_password_email_sent'})
    except Exception as e:
        print(f"Erreur lors de l'envoi de l'e-mail : {e}")
        return JsonResponse({'error': 'Failed to send reset password email'}, status=500)
    
class IsAuthenticatedUser(BasePermission) :
    message = 'unauthenticated_user'

    def has_permission(self,request,view) : 
        return bool(request.user)
