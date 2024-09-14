
var valideImages = [];
var imageContainer = [];


$(document).ready(function() {
    var homeUrl = window.DjangoURLs.home;
    $('#submit-report-form').click(function(){
    $('#error-mess-report').css('display','none');
    $('#suc-mess-report').css('display','none');
    var title=$('#report-title').val();
    var desc=$('#report-details').val();
    var loc=$('#report-location').val();
    var type_l=$('#report-type').val();
    var action=$('#report-action').val();
    var action_r=$('#report-action-result').val();
    if(title == '' || desc == ''){
        $('#error-mess-report').text('Please fill all the fields');
        $('#error-mess-report').css('display','block');
        return;
    }
    $('#error-mess-report').css('display','none');

    var data = new FormData();
    for (var i = 0; i < valideImages.length; i++) {
        var file = valideImages[i];
        if (file instanceof File) {
            data.append('files[]', file); // 'files[]' is the key for Django to process the files
        } else {
            console.error('File is not of type File:', file);
        }
    }
    var csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
    data.append('feature', 'report-scam');
    data.append('title',title);
    data.append('description',desc);
    data.append('location',loc);
    data.append('action',action);
    data.append('type',type_l);
    data.append('action_result',action_r);
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
                    $('#error-mess-report').text('Your report could not be submitted. Try again');
                    $('#error-mess-report').css('display','block');

                    return;
                }
                $('#suc-mess-report').text('Your report was submitted successfully! Thank you');
                $('#suc-mess-report').css('display','block');
                $('#image-delete-instruction').css('display','none');
                $('#preview').empty();
                $('#report-title').val('');
                $('#report-details').val('');
                $('#report-type').val('');
                $('#report-location').val('');
                $('#report-action').val('');
                $('#report-action-result').val('');
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

function FileVerification(event) {
    var validatedFiles = [];

    var errorStatement = "";

    var files = event.target.files;

    var minImageWidth = 400;
    var minImageHeight = 400;

    var nbMaxImages = 5;


    //verification du nombre d<images:
    if ((files.length > nbMaxImages) || (validatedFiles > 5 ||imageContainer>5 )) {
        //files.splice(0,5)
        alert("Maximum number of images is 5");

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
            addFileToArray(files[i], imageContainer);
            validatedFiles.push(files[i]);

        }

    }

    if (errorStatement != "") {

        alert(errorStatement);

    }

    valideImages = imageContainer;
//    valideImages = validatedFiles;
    FileDisplayA(validatedFiles);
}



function FileDisplayA(files) {

  var preview = document.querySelector('#preview');

  function readAndPreview(file) {

    // Make sure `file.name` matches our extensions criteria
      var reader = new FileReader();
      reader.readAsDataURL(file);

      reader.onloadend = function () {
        $('#image-delete-instruction').css('display','block');
        var image = new Image();
        image.height = 200;
        image.style.borderRadius = "10px";
        image.style.margin = "10px";
        image.title = file.name;
        image.src = this.result;
        var nImage = $(image).on('click', function(){
            $(this).fadeOut(500, function() {
                // Remove image element from DOM
                $(this).remove();
            // Remove file from the array
            files = files.filter(f => f.name !== file.name);
            var imageCount = $('#preview').children().length;
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


function create_zip(Images) {
    var zip = new JSZip();
    var zipChunk = new JSZip();
    var Count = 0;

    // Loop through all images and add them to zip chunks
    for (var i = 0; i < Images.length; i++) {
        var file = Images[i];

        // Check if the file is a Blob (File)
        if (file instanceof Blob) {
            if ((i % 99) != 0) {
                zipChunk.file(file.name, file);
            } else {
                zip.file("Chunk" + Count, zipChunk);
                zipChunk = new JSZip();  // Reset zipChunk
                Count++;
            }
        } else {
            console.error('Invalid file type:', file);
        }
    }

    // Add any remaining files in zipChunk to the main zip file
    if (zipChunk.files.length > 0) {
        zip.file("Chunk" + Count, zipChunk);
    }

    // Generate the zip file as a Blob (asynchronously)
    return zip.generateAsync({ type: "blob" });
}


