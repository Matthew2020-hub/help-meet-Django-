from django.db import models
from django.db import models
from django.contrib.auth.models import AbstractUser, UserManager
from django.utils.translation import gettext_lazy as _
from django_countries.fields import CountryField
from cloudinary.models import CloudinaryField
import uuid
from .estate_code_generator import generate_short_id


class CustomUserManager(UserManager):
    use_in_migrations = True
    """
    Custom user model manager where email is the unique identifiers
    for authentication instead of usernames.
    """
    def _create_user(self, email, password, **extra_fields):
        """
        Creates and saves a User with the given email and password.
        """
        if not email:
            raise ValueError('The given email must be set')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_superuser', False)
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email, password):
        """
        Create and save a SuperUser with the given email and password.
        """
        user = self._create_user(email=email, password=password
        )
        user.is_admin = True
        user.is_staff = True
        user.is_superuser = True
        user.is_active = True
        user.is_verified = True
        user.save(using=self.db)
        return user


# Create your models here.
class User(AbstractUser):
    username = None
    name = models.CharField(max_length=250, verbose_name="Full Name", blank=False, null=True)
    house_address = models.CharField(max_length=500, unique=True, blank=False, null=True)
    estate_name= models.CharField(max_length=250, blank=False, null=True)
    email = models.EmailField(_('email address'), unique=True)
    tenant_id = models.UUIDField(default=uuid.uuid4, editable=False, unique=True, null=True, blank=True)
    profile_image = models.ImageField(upload_to= "profile_image/", null=True)
    date_created = models.DateTimeField(auto_now_add=True)
    is_user = models.BooleanField(default=False)
    is_admin = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_verify = models.BooleanField(default=False)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []
    objects = CustomUserManager()

    def __str__(self):
        return self.email

    def has_perm(self, perm, obj=None):
        return self.is_superuser

    def has_module_perms(self, app_label):
        return self.is_superuser


class Estate(models.Model):
    member = models.ForeignKey(User, on_delete=models.CASCADE, null=True)
    estate_name = models.CharField(max_length=200, unique=True, blank=False)
    estate_profile_image = models.ImageField(upload_to='estate/', null=True)
    estate_id = models.UUIDField(default=uuid.uuid4, editable=False,  unique=True, null=True, blank=True)
    estate_address = models.CharField(max_length=400, unique=True, blank=False)
    estate_country = CountryField()
    public_id = models.CharField(max_length=15, default=generate_short_id, unique=True)
    date_created = models.DateTimeField(auto_now_add=True)


