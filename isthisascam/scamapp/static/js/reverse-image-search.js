$(document).ready(function() {
    var homeUrl = window.DjangoURLs.home;
    $('#image-search-btn').click(function(){
    var imageInput = $('#myFile')[0];

    if (!imageInput.files[0]) {
        return;
    }
    $('#ld-status').text('Loading...');
    $('#ld-status').css('color','');

    var text=$('#reverse-instruction');
    var revContainer=$('#reverse-result');
    var subImage=$('#subject-img');
    var resImage=$('#grid-cont');
    text.css('display','none');
    revContainer.css('display','block');
    subImage.addClass('slide-right');
    resImage.addClass('fade-in');
    var data = new FormData();
    data.append('image', imageInput.files[0]);
    data.append('feature', 'reverse-image-search');
    var csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
    $.ajax({
            url: homeUrl,  // Adjust URL to your Django view
            type: 'POST',
            headers: {
                'X-CSRFToken': csrfToken
            },
            data: data,
            processData: false,  // Prevent jQuery from automatically transforming the data into a query string
            contentType: false,  // Prevent jQuery from setting the Content-Type header
            success: function(response) {

                if (response['result'] != 'success'){
                    $('#ld-status').text('Failed to get the data. Try again');
                    $('#ld-status').css('color','#e63939');

                    return;
                }
                $('#ld-status').text('Results');
                $('#ld-status').css('color','#39e656');

//                $('#suc-mess-report').text('Your report was submitted successfully!');
//                $('#suc-mess-report').css('display','block');
//                $('#image-delete-instruction').css('display','none');
//                $('#preview').empty();
//                $('#report-title').val('');
//                $('#report-details').val('');
                valideImages = [];
                imageContainer = [];


            },
            error: function(xhr, status, error) {
                alert('File upload failed.');
                console.error('Error:', error);
                    $('#error-mess-request').text('Your message could not be sent. Try again');
                    $('#error-mess-request').css('display','block');

            }
        });
      });

});
