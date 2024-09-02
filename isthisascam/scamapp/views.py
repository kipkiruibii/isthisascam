from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
from PIL import Image
import pytesseract


def home(request):
    return JsonResponse({'result': 'success'})


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


image_path = 'test.jfif'
text = extract_text_from_image(image_path)

if text:
    print("Extracted Text:")
    print(text)
else:
    print("Failed to extract text.")
