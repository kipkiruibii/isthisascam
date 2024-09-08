
$(document).ready(function() {
    function isValidUrl(url) {
        // Regular expression to match common URL patterns
        var pattern = /^(https?:\/\/)?(www\.)?([a-zA-Z0-9-]+\.[a-zA-Z]{2,})(\/.*)?$/;
        return pattern.test(url);  // Returns true if the pattern matches, false otherwise
    }

    $('#scan-search').click(function(){
        $('#error-mess-website').css('display','none');
        var scan_input=$('#scan-input').val();
        if(scan_input == ''){return;}
        var valid=isValidUrl(scan_input);
        if(!valid) {
        $('#error-mess-website').css('display','block');
        $('#error-mess-website').text('Invalid url');
        return;}
        $('#website-scan-feature').css('display','none');
        $('#website-scan-loader').css('display','block');
    })


});