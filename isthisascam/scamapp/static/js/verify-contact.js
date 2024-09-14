 $(document).ready(function() {
    $('#submit-contact-ver-form').click(function(){
        var homeUrl = window.DjangoURLs.home;

        var contact = $('#contact-title').val();
        var company =  $('#company-name').val();
        if (contact == ''|| company == ''){return;}
         $('#vcontact-instruction').css('display','none');
        $('#loading-state-verif').css('display','block');
        var csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');

        $.ajax({
            url: homeUrl,  // Django URL tag to resolve the view
            type: "POST",
            data: {
                feature: 'verify-contact',
                company_name: company,
                contact: contact,
            },
            headers: {
                'X-CSRFToken': csrfToken
            },
            success: function(response) {
                if(response['result'] != 'success' ){
                    toastr.error(response['message']);
                    $('#loading-state-verif').css('display','none');
                    $('#vcontact-instruction').css('display','block');
                    $('#vcontact-results').css('display','none');

                    return;
                }
                var tempDiv = $('<div>').html(response.html);

               // Extract the specific element from the new HTML
                var newElementContent = tempDiv.find('#vcontact-results').html();
                $('#vcontact-results').html(newElementContent);
                 $('#loading-state-verif').css('display','none');
                $('#vcontact-instruction').css('display','none');
                 $('#vcontact-results').css('display','block');
                $('#request-count').text(response['request']);

                },
            error: function(xhr, status, error) {
                // Handle the error case
                 toastr.error('Error fetching. Try again');

            }
        });


        });


});