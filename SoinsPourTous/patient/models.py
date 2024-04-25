import uuid
from django.utils import timezone  # Assurez-vous d'importer correctement le module timezone
from django.db import models
from secure import PermissionsPolicy
from django.contrib.auth.hashers import make_password
from django.core.validators import MinLengthValidator
from datetime import datetime




class Hopital(models.Model) : 
    id = models.CharField(max_length=1000,unique=True,primary_key=True)
    nom = models.CharField(max_length=100)
    adresse = models.CharField(max_length=100)
    def __str__(self) : 
        return self.nom
    
class Service(models.Model) : 
    id = models.CharField(max_length=1000,unique=True,primary_key=True)
    service = models.CharField(max_length=100)
    hopitale = models.ForeignKey(Hopital, on_delete= models.CASCADE,related_name="hop")

class Grade(models.Model) : 
    id = models.CharField(max_length=1000,unique=True,primary_key=True)
    gradee = models.CharField(max_length=100)
    def __str__(self) : 
        return self.grade
class Groupe(models.Model) : 
    id = models.CharField(max_length=1000,unique= True,primary_key=True)
    groupe = models.CharField(max_length=100)
    tarif = models.DecimalField(max_digits=5,decimal_places=5)
    def __str__(self) : 
        return self.groupe
class Specialite(models.Model) : 
    id = models.CharField(max_length=1000,unique= True,primary_key=True)
    specialite = models.CharField(max_length=100)
    service = models.ForeignKey(Service,on_delete= models.CASCADE,related_name="serv")
class Medecin(models.Model):
    id = models.CharField(max_length=50,unique=True,primary_key=True)
    groupe = models.ForeignKey(Groupe, on_delete= models.CASCADE,related_name="group")
    grade = models.ForeignKey(Grade, on_delete= models.CASCADE,related_name="grade")
    username = models.CharField(max_length=50)
    password = models.CharField(max_length=5000)
    sepcialite = models.ForeignKey(Specialite,on_delete= models.CASCADE,related_name="spec")
    service = models.ForeignKey(Service,on_delete= models.CASCADE,related_name="servic")
    hopitale = models.ForeignKey(Hopital,on_delete= models.CASCADE,related_name="hopp")
    def __str__(self) : 
        return self.username
class Gouvernorat(models.Model):
    id = models.CharField(unique=True,max_length=1000000,primary_key=True)
    options = models.CharField(max_length=255, choices=[
        ('Ariana', 'Ariana'),
        ('Béja', 'Béja'),
        ('Ben Arous', 'Ben Arous'),
        ('Bizerte', 'Bizerte'),
        ('Gabès', 'Gabès'),
        ('Gafsa', 'Gafsa'),
        ('Jendouba', 'Jendouba'),
        ('Kairouan', 'Kairouan'),
        ('Kasserine', 'Kasserine'),
        ('Kébili', 'Kébili'),
        ('Le Kef', 'Le Kef'),
        ('Mahdia', 'Mahdia'),
        ('La Manouba', 'La Manouba'),
        ('Médenine', 'Médenine'),
        ('Monastir', 'Monastir'),
        ('Nabeul', 'Nabeul'),
        ('Sfax', 'Sfax'),
        ('Sidi Bouzid', 'Sidi Bouzid'),
        ('Siliana', 'Siliana'),
        ('Sousse', 'Sousse'),
        ('Tataouine', 'Tataouine'),
        ('Tozeur', 'Tozeur'),
        ('Tunis', 'Tunis'),
        ('Zaghouan', 'Zaghouan'),
    ])
class Nationality(models.Model) : 
    id = models.CharField(unique=True,max_length=1000,primary_key=True)
    nationality = models.CharField(max_length=40)

class User1( models.Model) : 
    id = models.CharField(unique=True,max_length=1000000,primary_key=True)
    email = models.EmailField(unique=True)
    username = models.CharField(max_length=50)
    phone = models.CharField(max_length = 10)
    fullname = models.CharField(max_length = 50)
    password = models.CharField(max_length = 5000)
    adresse = models.CharField(max_length=1000)
    created_at = models.DateTimeField(auto_now_add = True)
    gouvernorat = models.ForeignKey(Gouvernorat, on_delete= models.CASCADE,related_name="gouv")
    nationalite = models.ForeignKey(Nationality, on_delete= models.CASCADE,related_name="nat")
    sexe = models.CharField(max_length=5)
    image = models.ImageField(upload_to='categories/')
    date_naiss = models.DateField()
    def __str__(self) : 
        return self.email
    def update_password(self, new_password):
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
    id = models.CharField(unique=True,max_length=1000,primary_key=True)
    date_rendez_vous = models.DateField()
    patient = models.CharField(max_length =  100)
    medecin = models.CharField(max_length =  100)


    
class Agent(models.Model) : 
    id_agent =  models.CharField(max_length=1000,unique=True)
    username = models.CharField(max_length=50)
    password = models.CharField(max_length=1000)


class TokenForAgent(models.Model) : 
    token = models.CharField(max_length = 5000)
    user = models.ForeignKey(Agent, on_delete= models.CASCADE,related_name="tokens")
    created_at = models.DateTimeField(auto_now_add = True)

    def __str__(self) : 
        return self.user.username
    
class payment (models.Model) : 
    id = models.CharField(unique=True,max_length=1000,primary_key=True)
    patient = models.ForeignKey(User1, on_delete= models.CASCADE,related_name="pay")
    date = models.DateField(auto_now_add=True)
    
class Apc(models.Model) : 
    id = models.CharField(unique=True,max_length=1000,primary_key=True)
    date = models.DateTimeField()
    medecin = models.ForeignKey(Medecin,on_delete= models.CASCADE,related_name="medd")
    patient = models.ForeignKey(User1,on_delete= models.CASCADE,related_name="patt")
    
class Planning(models.Model) : 
    medecin = models.ForeignKey(Medecin,on_delete= models.CASCADE,related_name="meddcin")
    patient = models.ForeignKey(User1,on_delete= models.CASCADE,related_name="pattien")
    date = models.DateField()
    rdv = models.ForeignKey(RendezVous,on_delete= models.CASCADE,related_name="rdvv")
    


