from django.urls import path, include
from . import views
from paypal.standard.ipn import views as paypal_views

urlpatterns = [
    path('', views.landingPage, name='landing'),
    path('home/', views.homePage, name='home'),
    path('log-in/', views.loginPage, name='login'),
    path('log-out/', views.logOut, name='logout'),
    path('pricing/', views.pricingPage, name='pricing'),
    # path('process-payment/', views.processPayment, name='p'),
    path('community/', views.communityPage, name='community'),
    path('privacy/', views.privacy, name='privacy'),
    path('terms/', views.termsandCo, name='terms'),
    #     payments
    path('paypal/ipn/', include("paypal.standard.ipn.urls")),

    path('payment-success/', views.successful_payment, name='payment-success'),
    path('payment-failed/', views.failed_payment, name='payment-failed'),
    path('paypal_notification/', views.paypal_notification, name='paypal_notification'),
]
