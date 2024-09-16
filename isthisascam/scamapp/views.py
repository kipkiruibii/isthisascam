import json
import traceback
from datetime import timedelta
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.shortcuts import render, redirect
from django.http import JsonResponse, HttpResponse
from PIL import Image
import pytesseract
from django.template.loader import render_to_string
from django.views.decorators.csrf import csrf_exempt
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response
from .forms import FileUploadForm
from .website_scan import *
from .models import *
from paypal.standard.forms import PayPalPaymentsForm
from django.conf import settings
import uuid
from django.urls import reverse
# firebase.py
import firebase_admin
from firebase_admin import credentials, auth

# from .utils import scan_file

if settings.ISLOCAL:
    with open('../config.json') as file:
        config = json.load(file)
    cred = credentials.Certificate('../firebase-services.json')
    firebase_admin.initialize_app(cred)
else:
    with open('/etc/config.json') as file:
        config = json.load(file)
    cred = credentials.Certificate('/etc/firebase-services.json')
    firebase_admin.initialize_app(cred)


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


def reduceRequests(user):
    m = UserDetails.objects.filter(user=user).first()
    if m:
        if m.request_remaining > 0:
            m.request_remaining -= 1
            m.save()


@login_required
def homePage(request):
    '''
    Accept images(screenshots) \n
    User interacts with LLM over interactive chat.\n
    Protected through login(login required)
    '''
    rendered_html = 'home_page_mobile.html'
    # check if user is verified
    if request.user_agent.is_pc:
        rendered_html = 'home_page.html'
    #     check if user days has expired
    uss = UserDetails.objects.filter(user=request.user).first()
    expired = (uss.subscription_expiry - timezone.now()).total_seconds() <= 0
    if expired:
        uss.subscription_active = False
        uss.request_remaining = 0
        uss.save()

    firebase_user = auth.get_user_by_email(request.user.email)
    if firebase_user.email_verified:
        if not uss.is_verified:
            uss.is_verified = True
        if not uss.awarded_free_trial:
            uss.awarded_free_trial = True
            uss.request_remaining = 5
            uss.subscription_expiry = timezone.now() + timedelta(days=7)
        uss.save()

    custom_token = auth.create_custom_token(firebase_user.uid)
    if request.method == 'POST':
        feature = request.POST.get('feature', None)
        if feature == 'settings':
            theme = request.POST.get('theme', None)
            if theme:
                u = UserDetails.objects.filter(user=request.user).first()
                if u.dark_mode:
                    u.dark_mode = False
                else:
                    u.dark_mode = True
                u.save()
                return JsonResponse({
                    'result': 'success',
                })

        if feature == 'website-scan':
            url = request.POST.get('website-link', None)
            us = request.user
            u = UserDetails.objects.filter(user=us).first()
            if u.request_remaining == 0:
                return JsonResponse({
                    'result': 'failed',
                    'message': 'Your are out of credits. Upgrade your account to continue '
                }, status=status.HTTP_202_ACCEPTED)
            if url:
                try:
                    domain_info = get_domain_info(url)
                    if domain_info['domain_name'] is None:
                        raise Exception
                    ssl_cert = check_ssl_cert(url)
                    redirections = check_redirections(url)
                    if ssl_cert['sslRisk'] == 'Dangerous' or redirections['redirectionRisk'] == 'Dangerous':
                        overallRisk = 'Dangerous'
                    elif ssl_cert['sslRisk'] == 'Moderate' or redirections['redirectionRisk'] == 'Moderate' or \
                            domain_info['domainRisk'] == 'Moderate':
                        overallRisk = 'Moderate'
                    else:
                        overallRisk = 'Safe'
                    recommendation = ''
                    respnse = {
                        'result': 'success',
                        'hasDomainInfo': domain_info['success'],
                        'hasRedirectionInfo': redirections['success'],
                        'hasSSLInfo': ssl_cert['success'],
                        'domainInfo': domain_info,
                        'sslInfo': ssl_cert,
                        'redirectionInfo': redirections,
                        'overallRisk': overallRisk,
                        'recommendation': getFinalRecommendation(ssl_summary=ssl_cert['summary'],
                                                                 domain_summary=domain_info['summary'],
                                                                 redirection_summary=redirections['summary'],
                                                                 overall_risk=overallRisk)

                    }

                    rendered_template = render_to_string(rendered_html, respnse)
                    # Return the rendered template as part of the JSON response
                    u.request_remaining -= 1
                    u.save()
                    return JsonResponse({
                        'result': 'success',
                        'request': u.request_remaining,
                        'html': rendered_template
                    })

                except Exception as e:
                    print(e)
                    pass
            return JsonResponse({
                'result': 'failed',
                'message': 'The link you provided cannot be reached. Check and try again'
            }, status=status.HTTP_202_ACCEPTED)

        if feature == 'analyse-convo':
            description = request.POST.get('details', None)
            sc_id = request.POST.get('id', None)
            files = request.FILES.getlist('files[]')  # Get the list of uploaded files
            if not description:
                return JsonResponse({
                    'result': 'failed',
                    'message': 'Please provide additional details on the input box',
                }, status=status.HTTP_202_ACCEPTED)

            us = request.user
            u = UserDetails.objects.filter(user=us).first()
            if u.request_remaining == 0:
                return JsonResponse({
                    'result': 'failed',
                    'message': 'Your are out of credits. Upgrade your account to continue '
                }, status=status.HTTP_202_ACCEPTED)

            has_screenshot = True if files else False
            content = []
            for f in files:
                text = extract_text_from_image(f)
                if text:
                    content.append(text)
            if files and not content:
                return JsonResponse({
                    'result': 'failed',
                    'message': 'We were unable to extract text from your screenshots. Please ensure that the images are clear for better accuracy.'
                }, status=status.HTTP_202_ACCEPTED)
            if sc_id:
                sc = ScamAnalysis.objects.filter(identifier=sc_id).first()
                vl = analyseConversation(stage=2, prev_prompt=sc.first_prompt, model_res=sc.first_response,
                                         users_res=sc.follow_up_res)
                # vl = json.dumps(vl)

                f_val = json.loads(vl)
                try:
                    respnse = {
                        'result': 'success',
                        'page': 'results',
                        'do_you_think_this_is_a_scam': f_val['do_you_think_this_is_a_scam'],
                        'reasons_for_the_answer': f_val['reasons_for_the_answer'],
                        'scam_type': f_val['scam_type'],
                        'definition_of_scam': f_val['definition_of_scam'],
                        'variants_of_scam': f_val['variants_of_scam'],
                        'ways_to_protect_yourself': f_val['ways_to_protect_yourself'],
                        'what_to_do_if_fallen_victim': f_val['what_to_do_if_fallen_victim'],
                        'what_to_watch_out_for': f_val['what_to_watch_out_for'],
                    }
                    rendered_template = render_to_string(rendered_html, respnse)
                    u.request_remaining -= 1
                    u.save()

                    return JsonResponse({
                        'result': 'success',
                        'request': u.request_remaining,
                        'html': rendered_template
                    })
                except Exception as e:
                    print(e)
                    return JsonResponse({
                        'result': 'failed',
                        'message': 'An error occured while generating response.Kindly try again ',
                    }, status=status.HTTP_202_ACCEPTED)

            idf, vl = analyseConversation(stage=1, sc_content=content, description=description)
            # vl = json.dumps(vl)
            f_val = json.loads(vl)
            try:
                vv = f_val['follow_up_questions']
                # save to model
                respnse = {
                    'result': 'success',
                    'request': u.request_remaining,
                    'follow_up': f_val['follow_up_questions'],
                }
                rendered_template = render_to_string(rendered_html, respnse)
                u.request_remaining -= 1
                u.save()
                return JsonResponse({
                    'result': 'success',
                    'request': u.request_remaining,
                    'page': 'follow_up',
                    'scam_id': idf,
                    'html': rendered_template
                })

            except:
                return JsonResponse({
                    'result': 'failed',
                    'message': 'Sorry ,Give Mistral a minute to wake up and try again ',
                }, status=status.HTTP_202_ACCEPTED)
            # form = FileUploadForm(request.POST, request.FILES)
            # if form.is_valid():
            #     uploaded_file = request.FILES['file']
            #
            #     # Call the scan_file function
            #     # file_clean = scan_file(uploaded_file)
            #     file_clean = True
            #     if file_clean:
            #         image_path = 'test.jfif'
            #         text = extract_text_from_image(image_path)
            #
            #         if text:
            #             print("Extracted Text:")
            #             print(text)
            #             return JsonResponse({
            #                 'result': text
            #             }, status=status.HTTP_200_OK)
            #
            #     else:
            #         return JsonResponse({
            #             'result': 'Content extracted'
            #         }, status=status.HTTP_403_FORBIDDEN)

        if feature == 'reverse-image-search':
            file = request.FILES.get('image', None)
            if file:  # Get the list of uploaded files
                print(file.name)
                return JsonResponse({
                    'result': 'success',
                })
            return JsonResponse({
                'result': 'failed',
            })

        if feature == 'verify-contact':
            company_name = request.POST.get('company_name', None)
            contact_info = request.POST.get('contact', None)

            if not all([company_name, contact_info]):
                return JsonResponse({
                    'result': 'failed',
                    'message': 'Please provide all required information',
                }, status=status.HTTP_202_ACCEPTED)
            us = request.user
            u = UserDetails.objects.filter(user=us).first()
            if u.request_remaining == 0:
                return JsonResponse({
                    'result': 'failed',
                    'message': 'Your are out of credits. Upgrade your account to continue '
                }, status=status.HTTP_202_ACCEPTED)

            try:
                res = verifyCompanyContact(company_name, contact_info)
                if res:
                    f_val = json.loads(res)
                    respnse = {
                        'provided_contact': f_val['summary']['provided_contact'],
                        'title': f_val['summary']['results_title'],
                        'is_contact': f_val['summary']['is_contact'],
                        'findings': f_val['summary']['findings'],
                        'all_official_contacts': f_val['all_official_contacts'],
                        'common_scams_against_such_companies': f_val['common_scams_against_such_companies'],
                    }

                    rendered_template = render_to_string(rendered_html, respnse)
                    u.request_remaining -= 1
                    u.save()
                    return JsonResponse({
                        'result': 'success',
                        'request': u.request_remaining,
                        'html': rendered_template
                    })

                else:
                    print('no res')
            except Exception as e:
                print(e)
                return JsonResponse({
                    'result': 'failed',
                    'message': f'An error occurred, Please try again later {e}',
                }, status=status.HTTP_202_ACCEPTED)
            return JsonResponse({
                'result': 'failed',
                'message': f'Response timed out.Try after some time',
            }, status=status.HTTP_202_ACCEPTED)

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
        if feature == 'verify-account':
            pass
        if feature == 'report-scam':
            title = request.POST.get('title', None)
            description = request.POST.get('description', None)
            location = request.POST.get('location', None)
            type_ = request.POST.get('type', None)
            action = request.POST.get('action', None)
            action_result = request.POST.get('action_result', None)
            files = request.FILES.getlist('files[]')  # Get the list of uploaded files

            r = ReportedScams(
                title=title,
                content=description,
                location=location,
                scam_type=type_,
                action_taken=action,
                action_result=action_result,

            )
            r.save()

            for f in files:
                rep = ReportedScamsImageEvidence(
                    scam=r,
                    image=f
                )
                rep.save()
                #     add to database

            return JsonResponse({
                'result': 'success',
            })

        if feature == 'feature-request':
            title = request.POST.get('title', None)
            description = request.POST.get('description', None)
            inccount = request.POST.get('increaseID', None)
            if inccount:
                fl = RequestFeature.objects.filter(id=inccount).first()
                if fl:
                    if not fl.users_liked.filter(username=request.user.username).exists():
                        fl.users_liked.add(request.user)
                        fl.upvotes += 1
                        fl.save()
                        return JsonResponse({
                            'result': 'success',
                        })
                return JsonResponse({
                    'result': 'failed',
                })

            if not all([title, description]):
                return JsonResponse({
                    'result': 'failed',
                    'message': 'Kindly provide all details'
                }, status=status.HTTP_202_ACCEPTED)
            rq = RequestFeature(
                title=title,
                content=description,
                upvotes=0
            )
            rq.save()
            context = {
                'freqs': RequestFeature.objects.all().order_by('-upvotes')
            }
            rendered_template = render_to_string(rendered_html, context)

            return JsonResponse({
                'result': 'success',
                'html': rendered_template
            })

        return JsonResponse({
            'result': 'failed'
        }, status=status.HTTP_202_ACCEPTED)
    usr = request.user
    dmode = UserDetails.objects.filter(user=usr).first()
    context = {
        'theme': 'dark-mode' if dmode.dark_mode else "",
        'account_info': dmode,
        'firebase_user': custom_token.decode('utf-8'),
        'ffact': FunFact.objects.order_by('?').first(),
        'freqs': RequestFeature.objects.all().order_by('-upvotes')
    }
    if request.user_agent.is_pc:
        return render(request, 'home_page.html', context=context)
    return render(request, 'home_page_mobile.html', context=context)


def communityPage(request):
    return render(request, 'community_page.html')


@csrf_exempt
def successful_payment(request):
    print('payment successful')
    if request.method == "POST":
        data = request.POST
        print(data)

    # save the client payment database
    return render(request, 'payment_successful.html')
    pass


@csrf_exempt
def failed_payment(request):
    print('payment failed')
    return render(request, 'payment_failed.html')


@api_view(['POST', 'GET'])
def landingPage(request):
    '''First time users are redirected here. Checkout registration accepted here'''
    if request.method == 'POST':
        # Extract relevant data from the frontend (e.g., amount, currency)
        req_type = request.POST.get('request_type', None)
        if req_type == 'payment':
            plan_type = request.POST.get('plan_type', None)
            if plan_type == 'one_time':
                amount = 1.99
                name = "No Commitment Plan"
                print('payment amount', amount)

            else:
                if plan_type == 'personal':
                    amount = 9.99
                    name = "Personal Plan (monthly)"
                else:
                    amount = 19.999
                    name = "Business Plan (monthly)"
        elif req_type == 'contact':
            print('in comtacefr')
            name = request.POST.get('name', None)
            email = request.POST.get('email', None)
            message = request.POST.get('message', None)
            if not all([name, email, message]):
                return Response({'result': False, 'message': 'Please provide required details'},
                                status.HTTP_200_OK)

            cc = CustomerContact(
                name=name,
                email=email,
                message=message,
            )
            cc.save()
            print('contact message successfully saved')
            return Response({'result': True, 'message': 'Your message has been received'},
                            status.HTTP_200_OK)

    host = request.get_host()

    one_time_paypal_checkout = {
        'business': settings.PAYPAL_RECEIVER_EMAIL,
        'amount': '1.99',
        'item_name': 'One Off Payment',
        'invoice': uuid.uuid4(),
        "custom": request.user.username,
        'currency_code': 'USD',
        'notify_url': request.build_absolute_uri(reverse('paypal_notification')),
        'return_url': f"http://{host}{reverse('payment-success')}",
        'cancel_url': f"http://{host}{reverse('payment-failed', )}",
    }
    personal_paypal_checkout = {
        'business': settings.PAYPAL_RECEIVER_EMAIL,
        'a3': '9.99',  # Recurring price
        'p3': '1',  # Payment interval (every 1 month)
        't3': 'M',  # Time unit (M for months)
        'item_name': 'Monthly Subscription Plan(Personal)',
        'src': '1',  # Recurring payments enabled
        'sra': '1',  # Reattempt on payment failure
        "custom": request.user.username,
        'currency_code': 'USD',
        'invoice': str(uuid.uuid4()),  # unique identifier for each transaction
        'notify_url': request.build_absolute_uri(reverse('paypal_notification')),
        'return_url': f"http://{host}{reverse('payment-success')}",
        'cancel_return': f"http://{host}{reverse('payment-failed')}",
        'cmd': '_xclick-subscriptions',  # Specify that this is a subscription button
    }
    one_paypal_payment = PayPalPaymentsForm(initial=one_time_paypal_checkout, )
    pers_paypal_payment = PayPalPaymentsForm(initial=personal_paypal_checkout, button_type='subscribe')

    context = {
        'one_time_checkout': one_paypal_payment,
        'pers_paypal_payment': pers_paypal_payment,
    }
    return render(request, 'index.html', context)


@csrf_exempt
def paypal_notification(request):
    if request.method == "POST":
        data = request.POST
        try:
            payment_status = data.get('payment_status', '')
            currency = data.get('mc_currency', '')
            amount = data.get('mc_gross', '')
            email = data.get('payer_email', '')
            transaction_id = data.get('txn_id', '')
            transaction_subject = data.get('transaction_subject', '')
            payment_date = data.get('payment_date', '')
            receiver_email = data.get('receiver_email', '')
            profile_id = data.get('subscr_id', '')
            userDetails = request.POST.get('custom', '')

            if payment_status == 'Completed':
                if userDetails:
                    user_paying = User.objects.filter(username=userDetails).first()
                    if user_paying:
                        if currency == 'USD':
                            request_remaining = None
                            subscription_type = None
                            if float(amount) >= 1.99:
                                request_remaining = 10
                                subscription_type = 'One Time'
                            elif float(amount) >= 9.99:
                                request_remaining = 2000
                                subscription_type = 'Personal Monthly'
                            if request_remaining:
                                u = UserDetails.objects.filter(user=user_paying).first()
                                u.subscription_active = True
                                u.request_remaining += request_remaining
                                u.subscription_expiry = timezone.now() + timedelta(days=30)
                                u.subscription_type = subscription_type
                                u.save()
                            us = UserTransactions(
                                user=user_paying,
                                subscriber_id=profile_id,
                                receiver_email=email,
                                payment_date=payment_date,
                                transactionId=transaction_id,
                                subscription_type=subscription_type,
                                amount=amount,
                                is_successful=True
                            )
                            us.save()

        except:
            traceback.print_exc()

    return render(request, "index.html")


@api_view(['POST', 'GET'])
def loginPage(request):
    if request.user.is_authenticated:
        return redirect('home')
    next_url = request.GET.get('next') or request.POST.get('next') or '/home'
    if next_url == '/':
        next_url = f'{next_url}#pricing'
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

                return Response({'result': True, 'message': 'success', 'redirect': next_url},
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
            ud = UserDetails(
                user=user
            )
            ud.save()
            # print('registered')
            # login(request, user)
            return Response({'result': True,
                             'message': 'Registration successfull. Account verification link sent to your email. Please verify',
                             'redirect': next_url},
                            status.HTTP_200_OK)

    if request.user_agent.is_pc:
        return render(request, 'login_signup.html', {'next': next_url})
    return render(request, 'login_signup_mobile.html', {'next': next_url})


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
