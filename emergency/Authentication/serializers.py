from .models import User, Estate
from rest_framework import serializers
import re

import django.contrib.auth.password_validation as validators
from django.core.exceptions import ValidationError

regex = "^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*+=]).{8,}$"


class ListUserSerializer(serializers.ModelSerializer):
    class Meta:
        depth=1
        model=User
        fields = [
            'email', 'house_address',
            'name', 'estate_name', 'tenant_id',
            "estate"
            ]


"""A User serializer"""
class UserSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = [
            'email', 'house_address', 'password', 
            'name', 'estate_name', 'tenant_id'
            ]
        extra_kwargs = {
            'password':{ 
                'write_only':True
            },
        }
    def validate(self, data):
   
        """Checks for password strength. It takes in a regex and a password argument
        returns an error if password doesn't match the regex
        """
        password = data.get("password")
        if not re.match(regex, password):
            raise serializers.ValidationError({
                'password':'Your Password Is Weak',
                'Hint': 'Min. 8 characters, 1 Uppercase, 1 lowercase, 1 number, and 1 special character'
            })
        
        return data

    def save(self):
        user = User(
            email=self.validated_data['email'],
            name=self.validated_data['name'],
            estate_name=self.validated_data['estate_name'],
            house_address=self.validated_data['house_address'],    
        )
        password = self.validated_data['password']
        user.set_password(password)
        user.is_active = True
        user.is_user = True
        # user.save()
        # Room.objects.get_or_create(user=user)
        return super().save() 





"""A User serializer"""
class EstateAdminSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = [
            'email','password', "tenant_id"
            ]
        extra_kwargs = {
            'password':{ 
                'write_only':True
            },
        } 

    def validate(self, password: str):
        """Checks for password strength. It takes in a regex and a password argument
        returns an error if password doesn't match the regex
        """
        if not re.match(regex, password):
            raise serializers.ValidationError({
                'password':'Your Password Is Weak',
                'Hint': 'Min. 8 characters, 1 Uppercase, 1 lowercase, 1 number, and 1 special character'
            })
        return password

    def save(self):
        user = User(
            email=self.validated_data['email'],    
        )
        password = self.validated_data['password']
        user.set_password(password)
        user.is_active = True
        user.is_estate_admin = True
        return super().save()


class EstateSerializer(serializers.ModelSerializer):
    estate_admin_email = serializers.EmailField()

    class Meta:
        model = Estate
        fields = [
            "estate_name", "estate_address", "estate_country", 
            "estate_admin_email", "estate_id"
            ]
        extra_kwargs = {
            "estate_admin_email":{
                "read_only": True
            }
        }

    def save(self):
        estate = Estate(
            estate_name=self.validated_data['estate_name'],
            estate_country=self.validated_data['estate_country'],
            estate_address=self.validated_data['estate_address'],     
        )
    
        super().save()
        return estate




class EsatatesSerializer(serializers.ModelSerializer):
    class Meta:
        depth=1
        model = Estate
        fields = ["estate_name", "estate_address", "estate_country", "estate_id", 'user_serializer', 'member']        




class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(
        style={'input_type': 'password'}, 
        trim_whitespace=False
        )

    class Meta:
        ref_name = "my_login"

    def __str__(self):
        return self.email

class CustomPasswordResetSerializer(serializers.Serializer):
    password =  serializers.CharField(
        max_length=100, min_length=8, 
        style={'input_type':'password'}, 
        write_only=True
        )
    confirm_password = serializers.CharField(
        max_length=100, min_length=8, 
        style={'input_type':'password'}, 
        write_only=True
        )



class GenrateOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()
    def __str__(self):
        return self.email
