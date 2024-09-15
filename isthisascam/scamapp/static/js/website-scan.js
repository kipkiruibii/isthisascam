
$(document).ready(function() {
        function isValidUrl(url) {
            // Improved regex to validate a wide range of URL formats
            const urlPattern = /^(https?:\/\/)?([\w-]+\.)+[a-zA-Z]{2,}(\/[\w\-\.~%!$&'()*+,;=:@/]*)?(\?[;&a-zA-Z0-9%_=\-\.]*)?(#[\w\-]*)?$/;

            // Check if URL matches the pattern
            return urlPattern.test(url);
        }
        function formatSummary(text) {
            // Convert '**text**' to HTML <strong> tags
            let formattedText = text.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');

            // Convert '*text*' to HTML <em> tags
            formattedText = formattedText.replace(/\*(.*?)\*/g, '<em>$1</em>');

            // Convert '\n' to <br> tags for new lines
            formattedText = formattedText.replace(/\n/g, '<br>');

            // Convert lists, if applicable (for simplicity, only basic unnumbered lists are considered)
            formattedText = formattedText.replace(/- (.*?)(?=<br>)/g, '<li>$1</li>');
            formattedText = formattedText.replace(/(<li>.*?<\/li>)+/g, '<ul>$&</ul>');

            return formattedText;
        }
    var homeUrl = window.DjangoURLs.home;
    $('#scan-search').click(function(){
        $('#error-mess-website').css('display','none');
        var scan_input=$('#scan-input').val();
        if(scan_input == ''){return;}
        var valid=isValidUrl(scan_input);
        if(!valid) {
            $('#error-mess-website').css('display','block');
            $('#error-mess-website').text('Invalid url');
            return;
        }
        $('#website-scan-feature').css('display','none');
        $('#website-scan-result').css('display','none');
        $('#website-scan-loader').css('display','block');
        var csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
        var website_link=$('#scan-input').val();
        var data = new FormData();
        data.append('feature', 'website-scan');
        data.append('website-link',website_link);
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
                        $('#error-mess-website').css('display','block');
                        $('#error-mess-website').text(response['message']);

                        $('#website-scan-feature').css('display','block');
                        $('#website-scan-loader').css('display','none');

                        return;
                    }
                    var tempDiv = $('<div>').html(response.html);

                    // Extract the specific element from the new HTML
                    var newElementContent = tempDiv.find('#website-scan-result').html();
                    $('#website-scan-result').html(newElementContent);
                    const rawDomainSummary = $('#domain-summary-raw').text();
                    const formattedDomainSummary = formatSummary(rawDomainSummary);
                    $('#domain-summary-formatted').html(formattedDomainSummary);
                    $('#domain-summary-formatted-more').html(formattedDomainSummary);
                    var fs_less=formattedDomainSummary.slice(0, 100) + " ... Read More";
                    $('#domain-summary-formatted-less').html(fs_less);

                    const rawSSLSummary = $('#ssl-summary-raw').text();
                    const formattedSSLSummary = formatSummary(rawSSLSummary);
                    $('#ssl-summary-formatted-more').html(formattedSSLSummary);
                    $('#ssl-summary-formatted').html(formattedSSLSummary);
                    var fs_less=formattedSSLSummary.slice(0, 100) + " ... Read More";

                    $('#ssl-summary-formatted-less').html(fs_less);

                    const rawRedirectSummary = $('#redirections-summary-raw').text();
                    const formattedRedirectSummary = formatSummary(rawRedirectSummary);
                    $('#redirections-summary-formatted-more').html(formattedRedirectSummary);
                    $('#redirections-summary-formatted').html(formattedRedirectSummary);
                    var fs_less=formattedRedirectSummary.slice(0, 100) + " ... Read More";

                    $('#redirections-summary-formatted-less').html(fs_less);

                    const rawOverallSummary = $('#overall-summary-raw').text();
                    const formattedOverallSummary = formatSummary(rawOverallSummary);
                    $('#overall-summary-formatted').html(formattedOverallSummary);
                    $('#request-count').text(response['request']);


                    $('#website-scan-result').css('display','block');
                    $('#website-scan-loader').css('display','none');

                },
                error: function(xhr, status, error) {
                    alert('File upload failed.');
                    console.error('Error:', error);
                    $('#error-mess-website').css('display','block');
                    $('#error-mess-website').text('An error occurred try again');
                    $('#website-scan-feature').css('display','block');
                    $('#website-scan-loader').css('display','none');

                }
            });
      });

});

