
# Create your views here.
import email
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from .serializers import( 
    EstateSerializer, UserSerializer, 
    LoginSerializer, EstateAdminSerializer,
    CustomPasswordResetSerializer, EsatatesSerializer,
    ListUserSerializer
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
# from Authentication.serializers import
from mailjet_rest import Client



env = environ.Env()
environ.Env.read_env('housefree.env')
from_email= os.environ.get('EMAIL_HOST_USER')
api_key = os.environ.get('MJ_API_KEY')
api_secret = os.environ.get('MJ_API_SECRET') 




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
            if verify_estate_admin.is_estate_admin == False:
                return Response ("Only estate admin can create an estate", status=status.HTTP_401_UNAUTHORIZED)
            serializer.save()
            return Response (serializer.data, status=status.HTTP_201_CREATED)
        except User.DoesNotExist:
            return Response("Estate admin with this email does not exist, kidnly register", status=status.HTTP_404_NOT_FOUND)
        
      

       

class EstateAdminRegistration(APIView):
    authentication_classes = [TokenAuthentication]
    permisssion_classes = [AllowAny]
    def post(self, request):
        serializer = EstateAdminSerializer(data=request.data)  
        serializer.is_valid(raise_exception=True)
        password_check = serializer.validate_password(serializer.validated_data['password'])
        if not password_check:
            raise serializer.errors()
        email_check = serializer.validate_email(serializer.validated_data['email'])
        user = serializer.save()
        user_token = Token.objects.get_or_create(user=user)
        print(user_token)
        context = {
            'token': user_token[0].key,
            'message': 'Check your email and verify',
            "data": serializer.data
        }
        return Response(context, status=status.HTTP_201_CREATED)





"""An endpoint to list available Users"""
class ListEstateAPIView(generics.GenericAPIView, mixins.ListModelMixin):
    serializer_class = EstateSerializer
    queryset = Estate.objects.all()
    lookup_field = 'email'
    authentication_classes = [TokenAuthentication]
    permisssion_classes = [IsAuthenticated]
    def get(self, request):
        
        return self.list(self.queryset, exclude='estate_admin_email')




"""An endpoint to list available estate admin"""
class ListEstateAdminAPIView(generics.GenericAPIView, mixins.ListModelMixin):
    serializer_class = EstateAdminSerializer
    queryset = User.objects.filter(is_estate_admin=True)
    lookup_field = 'email'
    authentication_classes = [TokenAuthentication]
    permisssion_classes = [IsAuthenticated]
    def get(self, request):
        
        return self.list(self.queryset)




"""An endpoint to list available Users"""
class UserAPIView(generics.GenericAPIView, mixins.ListModelMixin):
    serializer_class = ListUserSerializer
    queryset = User.objects.filter(is_estate_admin=False)
    lookup_field = 'email'
    authentication_classes = [TokenAuthentication]
    permisssion_classes = [IsAuthenticated]
    def get(self, request):
        user = User.objects.filter(is_estate_admin=False)
        get_users = ListUserSerializer(user, many=True)
        return Response(get_users.data, status=status.HTTP_200_OK)




class UserRegistration(APIView):
    authentication_classes = [TokenAuthentication]
    permisssion_classes = [AllowAny]
    def post(self, request):
        serializer = UserSerializer(data=request.data)  
        serializer.is_valid(raise_exception=True)
        estate_name = serializer.validated_data['estate_name']
        try:
            estate=Estate.objects.get(estate_name = estate_name)
            user = serializer.save()
            user.is_verify =True
            user.save()
            update_estate = User.objects.filter(email=serializer.validated_data["email"]).update(estate=estate)
            user_token = Token.objects.get_or_create(user=user)
            context = {
                'token': user_token[0].key,
                'message': 'Check your email and verify',
                "data": serializer.data
            }
            return Response(context, status=status.HTTP_201_CREATED)
        except Estate.DoesNotExist:
            return Response("Estate with this name not found", status=status.HTTP_404_NOT_FOUND)
        





@api_view(['GET'])
@permission_classes([AllowAny])
def User_Email_Verification_Token( request, email):
    get_token = get_object_or_404(User, email=email)
    if get_token.is_verify is True:
        return Response("User's Email already verified", status=status.HTTP_208_ALREADY_REPORTED)
    email_verification_token = RefreshToken.for_user(get_token).access_token
    current_site = get_current_site(request).domain
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





"""
N.B: A custom login View where user signs in manually, i.e., without google authentication
 """

@api_view(["POST"])
@permission_classes([AllowAny])
def login_user(request):
    serializer = LoginSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    email = serializer.validated_data['email']
    password = serializer.validated_data['password']
    user = get_object_or_404(User, email=email)
    # user.backend = 'django.contrib.auth.backends.ModelBackend'    
    if not user.check_password(password):
        return Response({
        "message": "Incorrect Login credentials"},
        status=status.HTTP_401_UNAUTHORIZED
        )
    if not user.is_verify is True:
        user.is_verify = True
        user.save()
        # return Response({
        # 'message': 'Email is not yet verified, kindly do that!'}, 
        # status= status.HTTP_400_BAD_REQUEST
        # )
    if user.is_active is True:
        token, created = Token.objects.get_or_create(user=user)
        login(request, user)
        return Response({'Token':token.key}, status= status.HTTP_200_OK)    
    return Response({
        "message": "Account not active, kindly register!!"}, 
        status=status.HTTP_404_NOT_FOUND
        )




"""User logout Endpoint"""
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def signout(request):
    try:
        # Token created during login is deleted before user is being logged out
        request.user.auth_token.delete()
        logout(request)
        return Response({"success": _("Successfully logged out.")},
                    status=status.HTTP_200_OK)
    except (AttributeError, User.DoesNotExist):
        return Response ({"Error": _("User not found, enter a valid token.")},
        status=status.HTTP_404_NOT_FOUND)





class PasswordReset(APIView):
    permisssion_classes = [AllowAny]
    def put(self, request):
        email = request.GET.get('email')
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
            password2 = serializer.validated_data['confirm_password']
            if password != password2:
                return Response({'Error': 'Password must match!'}, status=status.HTTP_400_BAD_REQUEST)
            get_user = get_object_or_404(User, email=email)
            if password.lower() == password or password.upper() == password or password.isalnum()\
            or not any(i.isdigit() for i in password):
                raise serializers.ValidationError({
                    'password':'Your Password Is Weak',
                    'Hint': 'Min. 8 characters, 1 letter, 1 number and 1 special character'
                })
            get_user.password = password
            get_user.set_password(password)
            get_user.save()
            return Response(
                'Password change is successful, return to login page', 
                status= status.HTTP_200_OK
                )
        except User.DoesNotExist:
            return Response('User Not Found', status=status.HTTP_404_NOT_FOUND)


