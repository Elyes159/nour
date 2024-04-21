import uuid
from django.utils import timezone  # Assurez-vous d'importer correctement le module timezone
from django.db import models
from secure import PermissionsPolicy
from django.contrib.auth.hashers import make_password
from django.core.validators import MinLengthValidator
from datetime import datetime


class Medecin(models.Model):
    # Pas besoin de définir manuellement une colonne 'id'
    username = models.CharField(max_length=50,unique=True)
    password = models.CharField(max_length=5000)


class User1( models.Model) : 
    email = models.EmailField(unique=True)

    username = models.CharField(max_length=50)

    phone = models.CharField(max_length = 10)
    fullname = models.CharField(max_length = 50)
    password = models.CharField(max_length = 5000)
    created_at = models.DateTimeField(auto_now_add = True)
    image = models.ImageField(upload_to='categories/')

    def __str__(self) : 
        return self.email
    def update_password(self, new_password):
        # Hasher le nouveau mot de passe avant la mise à jour
        hashed_password = make_password(new_password)
        User1.objects.filter(pk=self.pk).update(password=hashed_password)
        
class Otp(models.Model) : 
    phone = models.CharField(max_length = 10)
    otp = models.IntegerField()
    validity = models.DateField(auto_now_add = True)
    verified = models.BooleanField(default = False)

    def __str__ (self) : 
        return self.phone
    

class Token(models.Model) : 
    token = models.CharField(max_length = 5000)
    user = models.ForeignKey(User1, on_delete= models.CASCADE,related_name="tokens_set")
    created_at = models.DateTimeField(auto_now_add = True)

    def __str__(self) : 
        return self.user.email
    
    
class TokenForDoctor(models.Model) : 
    token = models.CharField(max_length = 5000)
    user = models.ForeignKey(Medecin, on_delete= models.CASCADE,related_name="tokens_set")
    created_at = models.DateTimeField(auto_now_add = True)

    def __str__(self) : 
        return self.user.username
    

    
class PasswordResetToken(models.Model) : 
    token = models.CharField(max_length = 5000)
    user = models.ForeignKey(User1, on_delete=models.CASCADE, related_name='password_reset_tokens')
    validity = models.DateTimeField(default=timezone.now) 
    created_at = models.DateTimeField(auto_now_add = True)

    def __str__(self) : 
        return self.user.email
    
    
class Room (models.Model) : 
    code = models.CharField(max_length=100,unique=True)
    
class Message(models.Model):
    value = models.CharField(max_length=1000000)
    date = models.DateTimeField(default=datetime.now , blank = True)
    user = models.CharField(max_length=1000000)
    room = models.CharField(max_length=1000000)
    

class PageAcceuil(models.Model) : 
    postwithimage = models.ImageField(upload_to='categories/')
    postwithtet = models.CharField(max_length=1000)
    
    
class RendezVous(models.Model) : 
    date_rendez_vous = models.DateField()
    patient = models.CharField(max_length =  100)
    medecin = models.CharField(max_length =  100)


    
class Agent(models.Model) : 
    username = models.CharField(max_length=50)
    password = models.CharField(max_length=1000)


class TokenForAgent(models.Model) : 
    token = models.CharField(max_length = 5000)
    user = models.ForeignKey(Agent, on_delete= models.CASCADE,related_name="tokens")
    created_at = models.DateTimeField(auto_now_add = True)

    def __str__(self) : 
        return self.user.username

    



