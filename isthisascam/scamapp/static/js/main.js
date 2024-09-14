$(document).ready(function() {
    var homeUrl = window.DjangoURLs.home;
    var preferences="{{ theme }}"
    if(preferences =='dark-mode'){
        $('.mode-toggle-checkbox').each(function() {
            $(this).prop('checked', true);
        });
     }

    $('#request-btn').click(function (){
        $('#requests-section').css('display','none');
        $('#request-btn').css('display','none');
        $('#request-form').css('display','flex');
        $('#cancel-request-btn').css('display','inline-block');

    });
    $('#search-again').click(function (){
        var text=$('#reverse-instruction');
        var revContainer=$('#reverse-result');
        text.css('display','block');
        revContainer.css('display','none');

    });
    $('#cancel-request-btn').click(function (){
        $('#requests-section').css('display','block');
        $('#request-input-form').trigger("reset");;
        $('#request-btn').css('display','block');
        $('#request-form').css('display','none');
        $('#cancel-request-btn').css('display','none');

    });
    $('#cancel-report-btn').click(function (){
        $('#report-input-form').trigger("reset");;
        $('#report-form').css('display','none');
        $('#report-placeholder').css('display','block');
        $('#preview').empty();
        $('#image-delete-instruction').css('display', 'none');
    });
    $('#report-redirect').click(function (){
        $('#report-form').css('display','flex');
        $('#report-placeholder').css('display','none');

    });



    toastr.options = {
        'closeButton': true,
        'debug': false,
        'newestOnTop': false,
        'progressBar': false,
        'positionClass': 'toast-top-right',
        'preventDuplicates': false,
        'showDuration': '1000',
        'hideDuration': '1000',
        'timeOut': '5000',
        'extendedTimeOut': '1000',
        'showEasing': 'swing',
        'hideEasing': 'linear',
        'showMethod': 'fadeIn',
        'hideMethod': 'fadeOut',
    }

    // Define the class you want to toggle
    var toggleClass = 'dark-mode';
    var csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');

    // Attach a click event handler to the button
    $('.mode-toggle-checkbox').click(function() {
        $('body').toggleClass(toggleClass);
        //update settings in the server
        $.ajax({
            url: homeUrl,  // Django URL tag to resolve the view
            type: "POST",
            data: {
                feature: 'settings',
                theme: 'toggle',
            },
            headers: {
                'X-CSRFToken': csrfToken
            },
            success: function(response) {
            if(!response['result']){
                $('#errorLog').text(response['message']);
                toastr.error('Could not save changes. Try again');

                return;
            }
            toastr.success('Changes updated');
            },
            error: function(xhr, status, error) {
                // Handle the error case
                console.log(error);
                toastr.error('Could not save changes. Try again');

            }
        });

    });
});


