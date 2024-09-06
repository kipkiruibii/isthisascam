from django.contrib.auth.models import User
from django.db import models
from django.utils import timezone


class UserDetails(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    subscription_type = models.TextField(default='')
    subscription_active = models.BooleanField(default=False)
    subscription_date = models.DateTimeField(default=timezone.now)
    subscription_expiry = models.DateTimeField(default=timezone.now)
    request_remaining = models.IntegerField(default=0)

    def __str__(self):
        return f'{self.user.username}, sub: {self.subscription_type} , Active: {self.subscription_active}'


class Articles(models.Model):
    pass
