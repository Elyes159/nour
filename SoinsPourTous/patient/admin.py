from typing import __all__
from django.contrib import admin
from django.contrib.admin import register

from patient.models import  Agent, Medecin, Otp, PageAcceuil, PasswordResetToken, RendezVous,  Token, TokenForAgent, TokenForDoctor, User1,Message,Room
# Register your models here.



@register(User1)
class UserAdmin(admin.ModelAdmin):
    list_display = ['email','phone','fullname','created_at']
@register(RendezVous)
class RAdmin(admin.ModelAdmin):
    list_display = ['date_rendez_vous','medecin','patient']

    
@register(Medecin)
class MedecinAdmin(admin.ModelAdmin) : 
    list_display = ['id','username']

@register(Otp)
class OtpAdmin(admin.ModelAdmin) : 
    list_display = ['phone', 'otp','validity','verified']

@register(Token)
class TokenAdmin(admin.ModelAdmin) : 
    list_display = ['token','user','created_at']
    
    
@register(TokenForDoctor)
class TokenAdmin(admin.ModelAdmin) : 
    list_display = ['token','user','created_at']


@register(TokenForAgent)
class TokenAdmin(admin.ModelAdmin) : 
    list_display = ['token','user','created_at']


@register(PasswordResetToken)
class PasswordResetTokenAdmin(admin.ModelAdmin) : 
    list_display=['token','user','created_at']
    
    
@register(Message)
class MessageAdmin(admin.ModelAdmin):
    list_display = ['value','date','user','room']
    

@register(Room)
class RoomAdmin(admin.ModelAdmin):
    list_display = ['code']

@register(Agent)
class RoomAdmin(admin.ModelAdmin):
    list_display = ['username','password']

@register(PageAcceuil)
class PageAcceuilAdmin(admin.ModelAdmin):
    list_display = ['postwithimage','postwithtet']

# class ProductOptionInline(admin.TabularInline) : 
#     list  = ['id','product','option','quantity']
#     model = ProductOption


# @register(Product)
# class ProductAdmin(admin.ModelAdmin):

#     inlines = [ProductOptionInline]

#     list_display  = ['id','category','title','price','offer_price','delivery_charge','cod','created_at','updated_at']


# class ProductImageInline(admin.TabularInline) : 
#     list = ['image','position']
#     model = ProductImage


# @register(ProductOption)
# class ProductOptionAdmin(admin.ModelAdmin):
#     inlines = [ProductImageInline]
#     list_display=['id','product','option','quantity']


# @register(PageItem)
# class PageItemAdmin(admin.ModelAdmin):
#     list_display=['id','title','position','image','category','viewtype']



