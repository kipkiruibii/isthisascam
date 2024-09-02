from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from django.http import JsonResponse
from PIL import Image
import pytesseract
from rest_framework import status

from .forms import FileUploadForm
from .utils import scan_file


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
        form = FileUploadForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_file = request.FILES['file']

            # Call the scan_file function
            file_clean = scan_file(uploaded_file)
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

        return JsonResponse({
            'result': 'failed'
        }, status=status.HTTP_202_ACCEPTED)
    return render(request, 'home_page.html')


def communityPage(request):
    return render(request, 'community_page.html')


def landingPage(request):
    return render(request, 'landing_page.html')


def loginPage(request):
    return render(request, 'login_page.html')


def registerPage(request):
    return render(request, 'register_page.html')


def pricingPage(request):
    return render(request, 'pricing_page.html')
