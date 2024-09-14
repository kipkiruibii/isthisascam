$(document).ready(function() {
    $('#quick-links li').click(function() {
        // Remove the 'active' class from all li elements
        $('#quick-links li').removeClass('active');
        // Add the 'active' class to the clicked li element
        $(this).addClass('active');
        // Get the target content ID from the data-target attribute
        var target = $(this).data('target');
        // Hide all content sections
        $('.chat-content').hide();
        // Show the corresponding content section
        $(target).show();
    });
    $('#new-conversation-btn-left').click(function() {
        // Remove the 'active' class from all li elements
        $('#quick-links li').removeClass('active');
        //restore default state
        $('#analyse-details').val('');//delete prompt
        $('#analyse-details').val('');//delete prompt
        $('#preview_imgs').empty();//delete prompt and images
        $('#chat-box').css('display','none');//open chat box
        $('#intro-placeholder').css('display','block');//remove default message
        $('#input-container').css('display','block');//hide input field
        $('#new-conversation').css('display','none');//show new conversation button
        $('#screenshot-upload').css('display','block');
        $('#scam_indx').text('')

        $('#analyse-convo').addClass('active');
        // Add the 'active' class to the clicked li element
        var target = $('#analyse-convo').data('target');
        // Hide all content sections
        $('.chat-content').hide();
        // Show the corresponding content section
        $(target).show();
    });
});