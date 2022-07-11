from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from .views import (
    EstateRegistration, 
    UserRegistration, login_user, VerifyUserEmail, 
    User_Email_Verification_Token, signout, EstateAdminRegistration,
    PasswordReset, ListEstateAPIView, UserAPIView, ListEstateAdminAPIView
)


urlpatterns = [
    path('api/v1/login/', login_user, name='user-login'),
    path('api/v1/logout/', signout, name='logout-endpoint'),
    path('api/v1/password-reset/', PasswordReset.as_view()),
    path('api/v1/user/email-verifcation/token/', User_Email_Verification_Token, name='email-verification'),
    path('api/v1/user/registration/', UserRegistration.as_view()),
    path('api/v1/estate-admin/registration/', EstateAdminRegistration.as_view()),
    path('api/v1/estate/registration/', EstateRegistration.as_view()),
    path('api/v1/estate/all/', ListEstateAPIView.as_view()),
    path('api/v1/estate-admin/all/', ListEstateAdminAPIView.as_view()),
    path('api/v1/user/all/', UserAPIView.as_view()),
    path('api/v1/user/registration/', UserRegistration.as_view()),
    path('api/v1/user/email-verififcation/', VerifyUserEmail.as_view()),
    
]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
