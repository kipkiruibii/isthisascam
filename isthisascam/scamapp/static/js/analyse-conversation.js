
var valideImagesA = [];
var imageContainerA = [];
var imageCount=0;
function triggerFileUpload() {
    $('#fileInput').click();  // Trigger the file input when the icon is clicked
}
function defaultScreen(){
        $('#analyse-details').val('');//delete prompt
        $('#analyse-details').val('');//delete prompt
        $('#preview_imgs').empty();//delete prompt and images
        $('#chat-box').css('display','none');//open chat box
        $('#intro-placeholder').css('display','block');//remove default message
        $('#input-container').css('display','block');//hide input field
        $('#new-conversation').css('display','none');//show new conversation button
        $('#screenshot-upload').css('display','block');
        $('#screenshot-upload').css('display','block');
        $('#scam_indx').text('')

}
function followUpScreen(){
        // Models seeking further information
        $('#analyse-details').val('');//delete prompt
        $('#analyse-details').val('');//delete prompt
        $('#preview_imgs').empty();//delete prompt and images
        $('#chat-box').css('display','flex');//open chat box
        $('#intro-placeholder').css('display','none');//remove default message
        $('#follow-up').css('display','block');//open follow_up
        $('#final-results').css('display','none');//remove default message
        $('#screenshot-upload').css('display','none');


}
function resultsScreen(){
        //Model produced results
        $('#analyse-details').val('');//delete prompt
        $('#preview_imgs').empty();//delete prompt and images
        $('#chat-box').css('display','flex');//open chat box
        $('#follow-up').css('display','none');//open follow_up
        $('#final-results').css('display','block');//remove default message
        $('#intro-placeholder').css('display','none');//remove default message
        $('#input-container').css('display','none');//hide input field
        $('#new-conversation').css('display','block');//show new conversation button

}

$(document).ready(function() {
    var homeUrl = window.DjangoURLs.home;
    $('#new-conversation').click(function(){
        defaultScreen();
    });
   $('#submit-analyse-form').click(function(){
    $('#error-mess-analyse').css('display','none');
    $('#suc-mess-analyse').css('display','none');
    var desc=$('#analyse-details').val();
    var indx=$('#scam_indx').text();
    if(desc == ''){
        toastr.error('Please provide some additional details on the text area!');
        return;
    }
    $('#error-mess-analyse').css('display','none');
    $('#preview_imgs').css('display','none');
    $('#preview').css('display','none');
    $('#loading-state').css('display','block');
    $('#chat-box').css('display','none');
    $('#intro-placeholder').css('display','none');//remove default message
    $('#input-container').css('display','none');//hide input field

    var data = new FormData();
    for (var i = 0; i < valideImagesA.length; i++) {
        var file = valideImagesA[i];
        if (file instanceof File) {
            data.append('files[]', file); // 'files[]' is the key for Django to process the files
        } else {
            console.error('File is not of type File:', file);
        }
    }
    var csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
    data.append('feature', 'analyse-convo');
    data.append('details',desc);
    data.append('id',indx);
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
                        toastr.error(response['message']);
                        $('#loading-state').css('display','none');
                        $('#chat-box').css('display','none');
                        $('#intro-placeholder').css('display','block');//remove default message
                        $('#input-container').css('display','block');//hide input field
                        defaultScreen();

                    return;
                }
                valideImagesA = [];
                imageContainerA = [];
                var tempDiv = $('<div>').html(response.html);

                if(response['page']=='follow_up'){
                    $('#scam_indx').text(response['scam_id'])
                    var newElementContent = tempDiv.find('#follow-up').html();
                    $('#follow-up').html(newElementContent);
                    followUpScreen();
                    $('#loading-state').css('display','none');
                    $('#chat-box').css('display','block');
                    $('#analyse-details').attr('placeholder','Please provide more details that answer the questions above');//hide input field
                    $('#input-container').css('display','block');//show input field

                    return;
                }
                var newElementContent = tempDiv.find('#final-results').html();
                $('#final-results').html(newElementContent);
                resultsScreen();
                $('#loading-state').css('display','none');
                $('#request-count').text(response['request']);
                $('#chat-box').css('display','block');


            },
            error: function(xhr, status, error) {
                toastr.error('Failed! Your request could not be processed. Try again');
                console.error('Error:', error);
                    $('#loading-state').css('display','none');
                    $('#chat-box').css('display','block');

            }
        });
      });


//upvote
});
function isFileInArray(file, fileArray) {
    return fileArray.some(f => f.name === file.name && f.size === file.size && f.type === file.type);
}

function addFileToArray(file, fileArray) {
    if (!isFileInArray(file, fileArray)) {
        fileArray.push(file);
        console.log('File added:', file.name);
    } else {
        console.log('File already in array:', file.name);
    }
}

function FileVerificationA(event) {
    var validatedFilesA = [];

    var errorStatement = "";

    var files = event.target.files;

    var minImageWidth = 400;
    var minImageHeight = 400;

    var nbMaxImages = 5;


    //verification du nombre d<images:
    if ((files.length > nbMaxImages) || (validatedFilesA > 5 ||imageContainerA>5 )) {
        //files.splice(0,5)
        toastr.error("Maximum number of images is 5");
        return;
    }
    imageCount = $('#preview_imgs').children().length;

    if(imageCount > 4 ){
        toastr.error("Maximum number of images is 5");
        return;
    }

    for (var i = 0; i < files.length; i++) {

        //image Informations
        var fileName = files[i].name;
        var fileType = files[i].type;
        var fileSize = files[i].size;
        var ImageHeight;
        var ImageWidth;

        var reader = new FileReader();
        var image = new Image();
        image.src = reader.readAsDataURL(files[i]);
        ImageWidth = image.width;
        ImageHeight = image.height;


        //Verification du format des images
        if ((fileType != "image/png") &&
            (fileType != "image/jpeg") &&
            (fileType != "image/jpg")) {
            errorStatement += "File format not supported";


            //verification de la qualit
        } else if ((ImageHeight < minImageHeight) && (ImageWidth > minImageWidth)) {

            errorStatement += "Resolution too low";

            //verifier le poids de toutes les images
        } else {
            addFileToArray(files[i], imageContainerA);
            validatedFilesA.push(files[i]);

        }

    }

    if (errorStatement != "") {

        toastr.error(errorStatement);

    }

    valideImagesA = imageContainerA;
    FileDisplay(validatedFilesA);
}



function FileDisplay(files) {

  var preview = document.querySelector('#preview_imgs');

  function readAndPreview(file) {

    // Make sure `file.name` matches our extensions criteria
      var reader = new FileReader();
      reader.readAsDataURL(file);

      reader.onloadend = function () {
        imageCount = $('#preview_imgs').children().length;
       $('#intro-placeholder').css('display','none');
        $('#image-delete-instruction').css('display','block');
        var image = new Image();
        image.height = 300;
        image.style.borderRadius = "10px";
        image.style.margin = "10px";
        image.title = file.name;
        image.src = this.result;
        var nImage = $(image).on('click', function(){
            $(this).fadeOut(500, function() {
                // Remove image element from DOM
                $(this).remove();
//                imageContainerA.length-=1;
            // Remove file from the array
            files = files.filter(f => f.name !== file.name);
            imageCount = $('#preview_imgs').children().length;

            // Optional: Hide the delete instruction if there are no images
            if (imageCount == 0) {
                $('#image-delete-instruction').css('display', 'none');
            }
        });
        });
        preview.appendChild(image);
            // Add file to the array if it’s not already there
        if (!files.some(f => f.name === file.name)) {
            files.push(file);
        }

      };
    }

  if (files) {
    [].forEach.call(files, readAndPreview);
  }
}



