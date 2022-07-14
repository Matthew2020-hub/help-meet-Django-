
# Create your views here.
import email
from pkg_resources import get_supported_platform
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from .serializers import( 
    EstateSerializer, UserSerializer, 
    LoginSerializer, EstateAdminSerializer,
    CustomPasswordResetSerializer, EstatesSerializer,
    ListUserSerializer, MyTokenObtainPairSerializer
)
from .models import User, Estate
from django.shortcuts import get_object_or_404
from rest_framework import serializers, viewsets
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from rest_framework import generics
from rest_framework import mixins
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated,AllowAny
from rest_framework.authtoken.models import Token
from django.contrib.auth import logout, login
from django.utils.translation import gettext_lazy as _

from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from django.shortcuts import render
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.exceptions import AuthenticationFailed
import datetime
from django.contrib.sites.shortcuts import get_current_site
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
import os
import environ
from django.conf import settings
import jwt
# from Authentication.serializers import
from mailjet_rest import Client
from rest_framework_simplejwt.views import TokenObtainPairView
from django.contrib.auth import authenticate

from rest_framework_simplejwt.backends import TokenBackend



env = environ.Env()
environ.Env.read_env('housefree.env')
from_email= os.environ.get('EMAIL_HOST_USER')
api_key = os.environ.get('MJ_API_KEY')
api_secret = os.environ.get('MJ_API_SECRET') 




# Create your views here.



class EstateRegistration(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = EstateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            verify_estate_admin = User.objects.get(email=serializer.validated_data['estate_admin_email'])
            if verify_estate_admin.is_verify is False: 
                return Response ("Estate admin's email is not verified. Kindly verify your email", status=status.HTTP_401_UNAUTHORIZED)
            if verify_estate_admin.is_user == True:
                return Response ("Only estate admin can create an estate", status=status.HTTP_401_UNAUTHORIZED)
            estate = serializer.save()
            return Response (serializer.data, status=status.HTTP_201_CREATED)
        except User.DoesNotExist:
            return Response("Estate admin with this email does not exist, kidnly register", status=status.HTTP_404_NOT_FOUND)
        
      

       

class EstateAdminRegistration(APIView):
    serializer_class = EstateAdminSerializer
    permisssion_classes = [AllowAny]

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        validated_data = serializer.validated_data 
        user = User.objects.create_user(**validated_data)
        user.is_admin =True
        user.save()
        # Room.objects.get_or_create(user=user) 
        return Response({'success': 'Account created, check your email and verify'}, status=status.HTTP_201_CREATED)
    


class ListEstateAPIView(generics.GenericAPIView, mixins.ListModelMixin):
    """An endpoint to list available Estate(s)
    Filters the database for available estate

    Response:
        HTTP_200_OK - a success response

    Raise:
        HTTP_404_NOT_FOUND - if no estate found in the database
    """
    serializer_class = EstatesSerializer
    # select_related was used instead of .all() because I want to optimise my database cos I'm using a nested serializer
    queryset = Estate.objects.select_related("member")
    lookup_field = 'estate_name'
    authentication_classes = [TokenAuthentication]
    permisssion_classes = [IsAuthenticated]
    def get(self, request):
        if self.get_queryset():
            # instead of EstateSerializer(estate.objects.all(), many=True).data
            return Response(
                self.serializer_class(self.get_queryset(), many=True).data, 
                status=status.HTTP_200_OK
                )
        return Response({"error": "No available Estate"}, status=status.HTTP_404_NOT_FOUND)



class ListEstateAdminAPIView(generics.GenericAPIView, mixins.ListModelMixin):
    """An endpoint to list available Estate-admin
    Filters the database base on the user permission class

    Response:
        HTTP_200_OK - a success response

    Raise:
        HTTP_404_NOT_FOUND - if no estate-admin found in the database
    """
    serializer_class = EstateAdminSerializer
    queryset = User.objects.filter(is_user=False)
    lookup_field = 'email'
    authentication_classes = [TokenAuthentication]
    permisssion_classes = [IsAuthenticated]
    def get(self, request):
        if self.get_queryset():
            return Response(
                self.serializer_class(self.get_queryset(), 
                many=True).data,
                status=status.HTTP_200_OK
                )
        return Response({"error": "No available Estate Admin"}, status=status.HTTP_404_NOT_FOUND)




class UserAPIView(generics.GenericAPIView, mixins.ListModelMixin):

    """An endpoint to list available Users
    Filters the database base on the user permission class

    Response:
        HTTP_200_OK - a success response

    Raise:
        HTTP_404_NOT_FOUND - if no user found in the database
    """
    serializer_class = ListUserSerializer
    queryset = User.objects.filter(is_user=True)
    lookup_field = 'email'
    authentication_classes = [TokenAuthentication]
    permisssion_classes = [IsAuthenticated]
    def get(self, request):
        if self.get_queryset():  
            return Response(
                self.serializer_class(self.get_queryset(),
                many=True).data, 
                status=status.HTTP_200_OK
                )
        return Response({"error": "No available user"}, status=status.HTTP_404_NOT_FOUND)




class UserRegistration(APIView):
    serializer_class = UserSerializer
    permisssion_classes = [AllowAny]

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        estate_public_id = serializer.validated_data.pop('estate_id')
        validated_data = serializer.validated_data
        # Verify is the estate details exist in the database
        estate = Estate.objects.filter(
            estate_name=validated_data['estate_name'],
            public_id=estate_public_id)
        if not estate.exists():
            return Response("Estate with information does not exist", status=status.HTTP_404_NOT_FOUND) 
        user = User.objects.create_user(**validated_data)
        user.is_user = True
        user.save()
        estate.update(member=user)
        # Room.objects.get_or_create(user=user) 
        return Response({
            'Success': 'Account created successfully, check your email for verification'}, 
            status=status.HTTP_201_CREATED
            )
    
   


@api_view(['GET'])
@permission_classes([AllowAny])
def User_Email_Verification_Token( request, email):
    get_token = get_object_or_404(User, email=email)
    if get_token.is_verify is True:
        return Response("User's Email already verified", status=status.HTTP_208_ALREADY_REPORTED)
    email_verification_token = RefreshToken.for_user(get_token).access_token
    # current_site = get_current_site(request).domain
    absurl = f'http://127.0.0.1:8000/api/v1/user/email-verify?token={email_verification_token}' 
    email_body = 'Hi '+ ' ' + get_token.name+':\n'+ 'Use link below to verify your email' '\n'+ absurl
    data = {
        'email_body': email_body,'to_email':get_token.email,
        'subject': 'Verify your email'
    }
    mailjet = Client(auth=(api_key, api_secret), version='v3.1')
    data = {
    'Messages': [
        {
        "From": {
            "Email": f"akinolatolulope24@gmail.com",
            "Name": "freehouse"
        },
        "To": [
            {
            "Email": f"{get_token.email}",
            "Name": f"{get_token.name}"
            }
        ],
        "Subject": "Email Verification",
        "TextPart": "Click on the below link to verify your Email!",
        "HTMLPart":  email_body
        }
    ]
    }
    result = mailjet.send.create(data=data)
    return Response(result.json(), 
        status=status.HTTP_201_CREATED)




"""Verify user email endpoint"""
class VerifyUserEmail(APIView):
    permisssion_classes = [AllowAny]
    def get(self, request):
        token = request.GET.get('token')
        access_token_str = str(token)
        try:
            # access token verification
            access_token_obj = AccessToken(access_token_str) 
        except Exception as e:
            return Response(
        'No token Input or Token already expired', 
        status= status.HTTP_400_BAD_REQUEST
        )
        user_id = access_token_obj['user_id']
        user = get_object_or_404(User, user_id=user_id)
        if not user.is_verify:
            user.is_verify = True
            user.save()   
        return Response({
            'email': 'Email successfully activated, kindly return to the login page'}, 
            status=status.HTTP_200_OK
            )




class MyTokenObtainPairView(TokenObtainPairView):
    """A login endpoint using default JWT login"""
    serializer_class = MyTokenObtainPairSerializer
    permission_classes = (AllowAny,)

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        token = serializer.validated_data['access']
        valid_data =  jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.SIMPLE_JWT['ALGORITHM']])
        user = User.objects.filter(email=valid_data['email'])
        if not user[0].is_verify is True:
            user = user.first()
            user.is_verify = True
            user.save()
            # return Response({'error':'Email not verified'}, status=status.HTTP_400_BAD_REQUEST)
        
        return Response({
                "access": token, "refresh":serializer.validated_data['refresh']}, 
                status=status.HTTP_200_OK
                )
   

class LogoutView(APIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request):
        try:
            refresh_token = request.data["refresh_token"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response(status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response(status=status.HTTP_400_BAD_REQUEST)



class PasswordReset(APIView):
    permisssion_classes = [AllowAny]
    def put(self, request, email):
        # email = request.GET.get('email')
        email=email
        try:
            user = get_object_or_404(User, email=email)
            if user.is_verify is False:
                return Response(
                    "This email hasn't been verified, kindly verify your email",
                    status=status.HTTP_401_UNAUTHORIZED
                    )
            serializer = CustomPasswordResetSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            password = serializer.validated_data['password']
            get_user = get_object_or_404(User, email=email)
            get_user.set_password(password)
            get_user.save()
            return Response(
                'Password change is successful, return to login page', 
                status= status.HTTP_200_OK
                )
        except User.DoesNotExist:
            return Response('User Not Found', status=status.HTTP_404_NOT_FOUND)


