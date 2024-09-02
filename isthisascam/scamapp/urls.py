from django.urls import path
from . import views

urlpatterns = [
    path('', views.landingPage, name='landing'),
    path('home/', views.homePage, name='home'),
    path('log-in/', views.loginPage, name='login'),
    path('sign-up/', views.registerPage, name='sign-up'),
    path('pricing/', views.pricingPage, name='pricing'),
    path('community/', views.communityPage, name='community'),

]
