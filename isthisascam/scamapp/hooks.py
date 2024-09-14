from paypal.standard.models import ST_PP_COMPLETED
from paypal.standard.ipn.signals import valid_ipn_received, invalid_ipn_received
from django.conf import settings

def show_me_the_money(sender, **kwargs):
    ipn_obj = sender
    print('gheeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee')
    if ipn_obj.payment_status == ST_PP_COMPLETED:
        # Check that the receiver email matches the expected one
        if ipn_obj.receiver_email != settings.PAYPAL_RECEIVER_EMAIL:
            return  # Not a valid payment

        # Check the amount and currency
        expected_amount = 1.99  # Example amount
        if ipn_obj.mc_gross == expected_amount and ipn_obj.mc_currency == 'USD':
            print('success 1')
            # Process the valid payment here
            # if ipn_obj.custom == "premium_plan":
            #     # Handle premium plan payment
            #     pass
            # else:
            #     # Handle other types of payments
            #     pass
        expected_amount = 9.99  # Example amount

        if ipn_obj.mc_gross == expected_amount and ipn_obj.mc_currency == 'USD':
            print('done success')
            # Process the valid payment here
            # if ipn_obj.custom == "premium_plan":
            #     # Handle premium plan payment
            #     pass
            # else:
            #     # Handle other types of payments
            #     pass
        else:
            # Handle discrepancies in amount or currency
            pass
    else:
        # Handle other payment statuses or errors
        pass


def handle_invalid_ipn(sender, **kwargs):
    # Log or handle invalid IPN
    ipn_obj = sender
    pass


# Connect the signals
valid_ipn_received.connect(show_me_the_money)
invalid_ipn_received.connect(handle_invalid_ipn)
