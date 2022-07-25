from .models import User, Estate
from rest_framework import serializers
from .validators import password_regex_pattern
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken, TokenError


"""Simple JWT Serializer configuration"""


class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)

        # Add custom claims
        token["email"] = user.email
        # ...

        return token


class MyTokenObtainPairView(TokenObtainPairView):
    serializer_class = MyTokenObtainPairSerializer


class ListUserSerializer(serializers.ModelSerializer):
    class Meta:
        depth = 1
        model = User
        fields = [
            "email",
            "house_address",
            "name",
            "estate_name",
            "tenant_id",
        ]


"""A User serializer"""


class UserSerializer(serializers.ModelSerializer):
    estate_id = serializers.CharField(max_length=15)
    password = serializers.CharField(validators=[password_regex_pattern])

    class Meta:
        model = User
        fields = [
            "email",
            "house_address",
            "password",
            "name",
            "estate_name",
            "tenant_id",
            "estate_id",
        ]
        extra_kwargs = {
            "password": {"write_only": True},
        }


"""A User serializer"""


class EstateAdminSerializer(serializers.ModelSerializer):
    password = serializers.CharField(validators=[password_regex_pattern])

    class Meta:
        model = User
        fields = ["email", "password", "tenant_id"]
        extra_kwargs = {
            "password": {"write_only": True},
        }


class EstateSerializer(serializers.ModelSerializer):
    estate_admin = EstateAdminSerializer()

    class Meta:
        model = Estate
        fields = [
            "estate_name",
            "estate_address",
            "estate_country",
            "estate_admin_email",
            "estate_id",
            "estate_admin",
        ]

    def save(self):
        estate = Estate(
            estate_name=self.validated_data["estate_name"],
            estate_country=self.validated_data["estate_country"],
            estate_address=self.validated_data["estate_address"],
        )

        return estate.save()


class ReturnUserInfoSerializer(serializers.ModelSerializer):
    class Meta:
        depth = 1
        model = User
        fields = ["name", "email", "house_address", "date_joined"]


class EstatesSerializer(serializers.ModelSerializer):
    member = ReturnUserInfoSerializer(read_only=True)

    class Meta:
        depth = 1
        model = Estate
        fields = [
            "estate_name",
            "estate_address",
            "estate_country",
            "estate_id",
            "member",
        ]


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(
        style={"input_type": "password"}, trim_whitespace=False
    )

    class Meta:
        ref_name = "my_login"

    def __str__(self):
        return self.email


class CustomPasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(
        max_length=100,
        min_length=8,
        style={"input_type": "password"},
        write_only=True,
    )


class GenrateOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def __str__(self):
        return self.email


class LogoutSerializer(serializers.Serializer):
    refresh_token = serializers.CharField()
    default_error_message = {"bad_token": "Token is expired or invalid"}

    def validate(self, attrs):
        self.token = attrs["refresh_token"]
        return attrs

    def save(self, **kwargs):
        try:
            RefreshToken(self.token).blacklist()
        except TokenError:
            self.fail("bad_token")
