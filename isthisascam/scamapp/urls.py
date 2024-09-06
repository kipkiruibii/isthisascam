from django.urls import path
from . import views

urlpatterns = [
    path('', views.landingPage, name='landing'),
    path('home/', views.homePage, name='home'),
    path('log-in/', views.loginPage, name='login'),
    path('log-out/', views.logOut, name='logout'),
    path('pricing/', views.pricingPage, name='pricing'),
    path('community/', views.communityPage, name='community'),
    path('privacy/', views.privacy, name='privacy'),
    path('terms/', views.termsandCo, name='terms'),

]
