from django.contrib.auth.models import User
from django.db import models
from django.utils import timezone


class UserDetails(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    subscription_type = models.TextField(default='basic')
    subscription_active = models.BooleanField(default=False)
    subscription_date = models.DateTimeField(default=timezone.now)
    subscription_expiry = models.DateTimeField(default=timezone.now)
    request_remaining = models.IntegerField(default=0)
    dark_mode = models.BooleanField(default=False)
    is_verified = models.BooleanField(default=False)
    awarded_free_trial = models.BooleanField(default=False)

    def __str__(self):
        return f'{self.user.username}, sub: {self.subscription_type} , Active: {self.subscription_active}'


class Articles(models.Model):
    pass


class FunFact(models.Model):
    title = models.TextField(default='')
    content = models.TextField(default='')

    def __str__(self):
        return f'{self.title}, sub: {self.content} , '


class ScamAnalysis(models.Model):
    identifier = models.TextField(default='')
    first_prompt = models.TextField(default='', null=True)
    first_response = models.TextField(default='', null=True)
    follow_up_res = models.TextField(default='', null=True)
    model_conclusion = models.TextField(default='', null=True)
    date_submitted = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f'RESPONSE: {self.first_response} '


class ScamCount(models.Model):
    total_analysis = models.IntegerField(default=0)
    scam_reported = models.IntegerField(default=0)

    def __str__(self):
        return f'TOTAL: {self.total_analysis} Scams: {self.scam_reported}'


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


class ReportedScams(models.Model):
    title = models.TextField(default='', null=True)
    content = models.TextField(default='', null=True)
    location = models.TextField(default='', null=True)
    scam_type = models.TextField(default='', null=True)
    action_taken = models.TextField(default='', null=True)
    action_result = models.TextField(default='', null=True)
    date_shared = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f'{self.title}, sub: {self.content} , '


class ReportedScamsImageEvidence(models.Model):
    scam = models.ForeignKey(ReportedScams, on_delete=models.CASCADE)
    image = models.ImageField(upload_to='reportedScamEvidences/', null=True)

    def __str__(self):
        return f'EVIDENCE {self.scam.title}, '


class RequestFeature(models.Model):
    title = models.TextField(default='')
    content = models.TextField(default='')
    upvotes = models.IntegerField(default=0)
    feature_introduced = models.BooleanField(default=False)
    users_liked = models.ManyToManyField(User, related_name='liked', blank=True)

    def __str__(self):
        return f'FEATURE: {self.title}  {self.upvotes}'


class CustomerContact(models.Model):
    name = models.TextField(default='')
    email = models.TextField(default='')
    message = models.TextField(default='')
    date_submitted = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f'NAME: {self.name}  MESSAGE: {self.message}'


class CustomerReviews(models.Model):
    name = models.TextField(default='')
    email = models.TextField(default='')
    message = models.TextField(default='')
    date_submitted = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f'REVIEWER: {self.name}  MESSAGE:{self.message}'


class UserTransactions(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    subscriber_id = models.TextField(null=True)
    receiver_email = models.TextField(null=True)
    payment_date = models.TextField(null=True)
    transactionId = models.TextField(null=True)
    subscription_type = models.TextField(null=True)
    amount = models.FloatField(null=True)
    dateSub = models.DateTimeField(default=timezone.now)
    is_successful = models.BooleanField(default=False)

    def __str__(self):
        return str(self.user.username)
