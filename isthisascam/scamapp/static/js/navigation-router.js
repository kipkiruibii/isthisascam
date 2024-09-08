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
});