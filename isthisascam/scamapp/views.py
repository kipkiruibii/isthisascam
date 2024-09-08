from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.shortcuts import render, redirect
from django.http import JsonResponse
from PIL import Image
import pytesseract
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response
from .forms import FileUploadForm
from .website_scan import *
from .models import *


# from .utils import scan_file


def extract_text_from_image(image_path):
    try:
        # Open image file
        img = Image.open(image_path)

        # Extract text
        text = pytesseract.image_to_string(img)
        return text
    except Exception as e:
        print(f"An error occurred: {e}")
        return None


@login_required
def homePage(request):
    '''
    Accept images(screenshots) \n
    User interacts with LLM over interactive chat.\n
    Protected through login(login required)
    '''
    if request.method == 'POST':
        feature = request.POST.get('feature', None)
        if feature == 'website-scan':
            url = request.POST.get('url', None)
            if url:
                domain_info = get_domain_info(url)
                ssl_cert = check_ssl_cert(url)
                redirections = check_redirections(url)
        if feature == 'analyse-convo':
            form = FileUploadForm(request.POST, request.FILES)
            if form.is_valid():
                uploaded_file = request.FILES['file']

                # Call the scan_file function
                # file_clean = scan_file(uploaded_file)
                file_clean = True
                if file_clean:
                    image_path = 'test.jfif'
                    text = extract_text_from_image(image_path)

                    if text:
                        print("Extracted Text:")
                        print(text)
                        return JsonResponse({
                            'result': text
                        }, status=status.HTTP_200_OK)

                else:
                    return JsonResponse({
                        'result': 'Content extracted'
                    }, status=status.HTTP_403_FORBIDDEN)

        if feature == 'reverse-image':
            pass

        if feature == 'community':
            pass

        if feature == 'scam-trends':
            pass

        if feature == 'fraud-education':
            pass
        if feature == 'scam-recovery':
            pass
        if feature == 'scam-heatmap':
            pass

        return JsonResponse({
            'result': 'failed'
        }, status=status.HTTP_202_ACCEPTED)

    context = {
        # 'theme': 'dark-mode',
        'ffact': FunFact.objects.order_by('?').first()
    }
    if request.user_agent.is_pc:
        return render(request, 'home_page.html', context=context)
    return render(request, 'home_page_mobile.html', context=context)


def communityPage(request):
    return render(request, 'community_page.html')


def landingPage(request):
    '''First time users are redirected here. Checkout registration accepted here'''

    return render(request, 'index.html')


@api_view(['POST', 'GET'])
def loginPage(request):
    if request.user.is_authenticated:
        return redirect('home')
    if request.method == 'POST':
        name = request.POST.get('username', None)
        email = request.POST.get('email', None)
        password = request.POST.get('password', None)
        cpassword = request.POST.get('cpassword', None)
        type_ = request.POST.get('type', None)
        if not all([name, password]):
            return Response({'result': False, 'message': 'Please provide required details'},
                            status.HTTP_200_OK)
        if type_ == 'login':
            user = authenticate(request, username=name.strip(), password=password.strip())
            if user is not None:
                login(request, user)
                return Response({'result': True, 'message': 'success'},
                                status.HTTP_200_OK)
            return Response({'result': False, 'message': 'Invalid credentials'},
                            status.HTTP_200_OK)
        elif type_ == 'signup':
            us = User.objects.filter(email=email.strip()).exists()
            nm = User.objects.filter(username=name.strip()).exists()
            if us or nm:
                return Response({'result': False, 'message': 'User already exists'},
                                status.HTTP_200_OK)
            if cpassword != password:
                return Response({'result': False, 'message': 'passwords do not match'},
                                status.HTTP_200_OK)

            user = User.objects.create_user(username=name.strip(), password=password.strip(), email=email.strip())
            user.save()
            print('registered')
            login(request, user)
            return Response({'result': True, 'message': 'login success'},
                            status.HTTP_200_OK)

    if request.user_agent.is_pc:
        return render(request, 'login_signup.html')
    return render(request, 'login_signup_mobile.html')


@login_required
def logOut(request):
    logout(request)
    return redirect('landing')


def pricingPage(request):
    return render(request, 'pricing_page.html')


def termsandCo(request):
    return render(request, 'terms.html')


def privacy(request):
    return render(request, 'privacy.html')
