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


class FunFact(models.Model):
    title = models.TextField(default='')
    content = models.TextField(default='')

    def __str__(self):
        return f'{self.title}, sub: {self.content} , '


class ReportedScams(models.Model):
    title = models.TextField(default='')
    content = models.TextField(default='')
    location = models.TextField(default='')
    date_shared = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f'{self.title}, sub: {self.content} , '


class ScamAnalysis(models.Model):
    extracted_text = models.TextField(default='')
    additional_context = models.TextField(default='')
    model_asks_user_respond = models.JSONField(default=list, blank=True)
    user_asks_model_respond = models.JSONField(default=list, blank=True)
    date_submitted = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f'Context: {self.additional_context} '


class ScamAnalysisResults(models.Model):
    scam = models.ForeignKey(ScamAnalysis, on_delete=models.CASCADE)
    is_scam = models.BooleanField(default=False)
    scam_score = models.IntegerField(default=0)
    score_desc = models.TextField(default='')
    scam_type = models.TextField(default='')
    scam_desc = models.TextField(default='')
    scam_variation = models.JSONField(default=list, blank=True)
    result_desc = models.JSONField(default=list, blank=True)
    result_advice = models.JSONField(default=list, blank=True)
    result_recovery = models.JSONField(default=list, blank=True)
    result_conclusion = models.JSONField(default=list, blank=True)


class ReportedScamsImageEvidence(models.Model):
    scam = models.ForeignKey(ReportedScams, on_delete=models.CASCADE)

    def __str__(self):
        return f'EVIDENCE {self.scam.title}, '


class RequestFeature(models.Model):
    title = models.TextField(default='')
    content = models.TextField(default='')
    upvotes = models.IntegerField(default=0)
    feature_introduced = models.BooleanField(default=False)

    def __str__(self):
        return f'FEATURE: {self.title}  {self.upvotes}'
