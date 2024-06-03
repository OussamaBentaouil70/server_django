from django.contrib.auth.backends import BaseBackend
from .models import Member, Owner
from django.contrib.auth.hashers import check_password
from django.utils import timezone

class CustomAuthenticationBackend(BaseBackend):
    def authenticate(self, request, email=None, password=None):
        try:
            user = Member.objects.get(email=email)
        except Member.DoesNotExist:
            try:
                user = Owner.objects.get(email=email)
            except Owner.DoesNotExist:
                return None
        
        if check_password(password, user.password):
            user.last_login = timezone.now()  # Update last login time
            user.save(update_fields=['last_login'])
            return user
        else:
            return None

    def get_user(self, user_id):
        try:
            return Member.objects.get(pk=user_id)
        except Member.DoesNotExist:
            try:
                return Owner.objects.get(pk=user_id)
            except Owner.DoesNotExist:
                return None
