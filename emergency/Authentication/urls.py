from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from .views import (
    EstateRegistration,
    UserRegistration,
    VerifyUserEmail,
    User_Email_Verification_Token,
    PasswordReset,
    ListEstateAPIView,
    UserAPIView,
    ListEstateAdminAPIView,
    MyTokenObtainPairView,
    LogoutView,
)

from rest_framework_simplejwt.views import (
    TokenRefreshView,
)


urlpatterns = [
    path(
        "api/v1/login/",
        MyTokenObtainPairView.as_view(),
        name="token_obtain_pair",
    ),
    path(
        "api/v1/token/refresh/",
        TokenRefreshView.as_view(),
        name="token_refresh",
    ),
    # path('api/v1/login/', login_user, name='user-login'),
    path("api/v1/logout/", LogoutView.as_view(), name="logout-endpoint"),
    path("api/v1/password-reset/<str:email>", PasswordReset.as_view()),
    path(
        "api/v1/user/email-verifcation/token/",
        User_Email_Verification_Token,
        name="email-verification",
    ),
    path("api/v1/user/registration/", UserRegistration.as_view()),
    path("api/v1/estate/registration/", EstateRegistration.as_view()),
    path("api/v1/estate/all/", ListEstateAPIView.as_view()),
    path("api/v1/estate-admin/all/", ListEstateAdminAPIView.as_view()),
    path("api/v1/user/all/", UserAPIView.as_view()),
    path("api/v1/user/registration/", UserRegistration.as_view()),
    path("api/v1/user/email-verififcation/", VerifyUserEmail.as_view()),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
