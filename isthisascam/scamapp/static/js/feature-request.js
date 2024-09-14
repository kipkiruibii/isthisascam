$(document).ready(function() {
    var homeUrl = window.DjangoURLs.home;
    $('#submit-request-form').click(function(){
        $('#error-mess-request').css('display','none');
        $('#suc-mess-request').css('display','none');
        var title=$('#request-title').val();
        var desc=$('#request-details').val();
        if(title == '' || desc == ''){
            $('#error-mess-request').text('Please fill all the fields');
            $('#error-mess-request').css('display','block');
            return;
        }
        $('#error-mess-website').css('display','none');

        var csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
        var data = new FormData();
        data.append('feature', 'feature-request');
        data.append('title',title);
        data.append('description',desc);
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
                        $('#error-mess-request').text('Your message could not be sent. Try again');
                        $('#error-mess-request').css('display','block');

                        return;
                    }
                    var tempDiv = $('<div>').html(response.html);
                    $('#suc-mess-request').text('Your message was sent successfully');
                    $('#suc-mess-request').css('display','block');
                    $('#request-title').val('');
                    $('#request-details').val('');

                    // Extract the specific element from the new HTML
                    var newElementContent = tempDiv.find('#all-feature-requests').html();
                    $('#all-feature-requests').html(newElementContent);

                },
                error: function(xhr, status, error) {
                    alert('File upload failed.');
                    console.error('Error:', error);
                        $('#error-mess-request').text('Your message could not be sent. Try again');
                        $('#error-mess-request').css('display','block');

                }
            });
      });

//upvote

    $('.game-likes').click(function(){
        var itemId=$(this).data('id');
        var likeCountElement = $(this).find('.game-like-count'); // Get the .game-like-count within the same div
        var currentLikes = parseInt(likeCountElement.text())

        var csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
        var data = new FormData();
        data.append('feature', 'feature-request');
        data.append('increaseID',itemId);
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
                        return;
                    }

                    likeCountElement.text(currentLikes + 1); //

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
