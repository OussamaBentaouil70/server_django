from django.db import models
from django.contrib.auth.models import AbstractUser

class User(AbstractUser):
    email = models.EmailField(unique=True)
    role = models.CharField(max_length=50)
    fonction = models.CharField(max_length=100)

    # Specify unique related_name to avoid conflicts
    groups = models.ManyToManyField(
        'auth.Group',
        related_name='myapp_users',  # Change related_name
        blank=True,
        help_text='The groups this user belongs to. A user will get all permissions granted to each of their groups.',
        verbose_name='groups',
    )
    user_permissions = models.ManyToManyField(
        'auth.Permission',
        related_name='myapp_users_permissions',  # Change related_name
        blank=True,
        help_text='Specific permissions for this user.',
        verbose_name='user permissions',
    )

class Member(models.Model):
    username = models.CharField(max_length=150, unique=True)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=128)
    role = models.CharField(max_length=50)
    fonction = models.CharField(max_length=100)
    owner = models.ForeignKey('Owner', on_delete=models.CASCADE, related_name='member_set')
    last_login = models.DateTimeField(null=True, blank=True)  # Add this line
class Owner(models.Model):
    username = models.CharField(max_length=150, unique=True)
    email = models.EmailField(unique=True)
    password = models.CharField(max_length=128)
    role = models.CharField(max_length=50)
    fonction = models.CharField(max_length=100)
    members = models.ManyToManyField('Member', related_name='owner_set')
    last_login = models.DateTimeField(null=True, blank=True)  # Add this line
class Rule(models.Model):
    name = models.CharField(max_length=255)
    description = models.TextField()
    tag = models.CharField(max_length=100)
