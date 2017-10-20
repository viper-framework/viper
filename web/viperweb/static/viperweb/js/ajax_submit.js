// This file is part of Viper - https://github.com/viper-framework/viper
// See the file 'LICENSE' for copying permission.
//
// ajax_submit.js

var csrftoken = Cookies.get('csrftoken');

function csrfSafeMethod(method) {
    // these HTTP methods do not require CSRF protection
    return (/^(GET|HEAD|OPTIONS|TRACE)$/.test(method));
}
$.ajaxSetup({
    beforeSend: function (xhr, settings) {
        if (!csrfSafeMethod(settings.type) && !this.crossDomain) {
            xhr.setRequestHeader("X-CSRFToken", csrftoken);
        }
    }
});


$("#upload_form").submit(function (event) {
    console.log("upload_form called");
    event.preventDefault();
    var formData = new FormData($(this)[0]);
    $.ajax({
        url: malware_upload_url,
        type: 'POST',
        data: formData,
        contentType: false,
        processData: false,

        success: function (data) {
            console.log("Submit successful");
            console.log(data);

            // TODO(frennkie) this simply redirects to first..?!
            window.location.replace(malware_list_url + data[0].data.sha256);
        },
        error: function(data){
            console.log("Submit failed");
            var obj = jQuery.parseJSON(data["responseText"]);
            var error = obj.error;
            console.log(error);
            console.log(error.message);
        }
    });
    return false;
});


// Tag: add, delete (as function)
$("#add_tag_form").submit(function (event) {
    console.log("add_tag_form called");
    event.preventDefault();
    var formData = new FormData($(this)[0]);

    $.ajax({
        url: malware_tag_list_url,
        type: 'POST',
        data: formData,
        contentType: false,
        processData: false,

        success: function (data) {
            console.log("Submit successful");
            window.location.reload();
        },
        error: function (data) {
            console.log("Submit failed");
            var obj = jQuery.parseJSON(data["responseText"]);
            alert("Tag: " + obj.tag[0]);
        }
    });
    return false;
});


function delTag(tag_id) {
    console.log("del_tag called for: " + tag_id);

    $.ajax({
            url: malware_tag_list_url + tag_id + '/',
            type: "DELETE",
            success: function (data) {
                console.log("deleted");
                $('#display_tag_' + tag_id).hide();
            },
            error: function (data) {
                console.log("error");
                console.log(data);
            }
        }
    )
}


// Note: add, update, delete (as function)
$("#add_note_form").submit(function (event) {
    console.log("add_note_form called");
    event.preventDefault();
    var formData = new FormData($(this)[0]);

    $.ajax({
        url: malware_note_list_url,
        type: 'POST',
        data: formData,
        contentType: false,
        processData: false,

        success: function (data) {
            console.log("Submit successful");
            console.log(data);
            // window.location.replace(file_view_url  + "#notes");
            window.location.reload();
        },
        error: function (data) {
            console.log("Submit failed");
            var obj = jQuery.parseJSON(data["responseText"]);
            console.log(data);
            alert("Note: " + obj.title[0])
        }
    });
    return false;
});


$("#update_note_form").submit(function (event) {
    console.log("update_note_form called");
    event.preventDefault();
    var formData = new FormData($(this)[0]);
    console.log(formData.get("id"));

    $.ajax({
        url: malware_note_list_url + formData.get("id") + '/',
        type: 'PUT',
        data: formData,
        contentType: false,
        processData: false,

        success: function (data) {
            console.log("Submit successful");
            window.location.reload();
        },
        error: function (data) {
            console.log("Submit failed");
            var obj = jQuery.parseJSON(data["responseText"]);
            alert("Note: " + obj.title[0]);
        }
    });
    return false;
});


function delNote(note_id) {
    console.log("del_note called for: " + note_id);

    if (confirm('Are you sure you want to delete this note?')) {
        $.ajax({
                url: malware_note_list_url + note_id + '/',
                type: "DELETE",
                success: function (data) {
                    console.log("deleted");
                    $('#display_note_' + note_id).hide();
                },
                error: function (data) {
                    console.log("error");
                    console.log(data);
                    var obj = jQuery.parseJSON(data["responseText"]);
                    alert("Note: " + obj.title[0]);
                }
            }
        )
    }
}



$('#ajaxsubmit').submit(function (event) {
    $.ajax({
        url: '/module/',
        type: 'post',
        dataType: 'html',
        data: $('#ajaxsubmit').serialize(),
        beforeSend: function () {
            var target = document.getElementById('spin_loader');
            var spinner = new Spinner(opts).spin(target);
            $(target).data('spinner', spinner);
        },
        complete: function () {
            $('#spin_loader').data('spinner').stop();
        },
        success: function (response, textStatus, jqXHR) {
            $('#ajaxresponse').prepend(response);
        },
        error: function (jqXHR, textStatus, errorThrown) {
            console.log('error(s):' + textStatus, errorThrown);
        }
    });
});


$('#hexsubmit').submit(function (event) {
    $.ajax({
        url: '/hex/',
        type: 'post',
        dataType: 'html',
        data: $('#hexsubmit').serialize(),
        beforeSend: function () {
            var target = document.getElementById('spin_loader');
            var spinner = new Spinner(opts).spin(target);
            $(target).data('spinner', spinner);
        },
        complete: function () {
            $('#spin_loader').data('spinner').stop();
            var hex_start = document.getElementById('hex_start');
            hex_start.value = parseInt(hex_start.value, 10) + 256;
        },
        success: function (response, textStatus, jqXHR) {
            $('#hexview').append(response);

        },
        error: function (jqXHR, textStatus, errorThrown) {
            console.log('error(s):' + textStatus, errorThrown);
        }
    });
});


function clear_div() {
    document.getElementById("ajaxresponse").innerHTML = "";
}


var opts = {
  lines: 13, // The number of lines to draw
  length: 20, // The length of each line
  width: 10, // The line thickness
  radius: 30, // The radius of the inner circle
  corners: 1, // Corner roundness (0..1)
  rotate: 0, // The rotation offset
  direction: 1, // 1: clockwise, -1: counterclockwise
  color: '#000', // #rgb or #rrggbb or array of colors
  speed: 0.9, // Rounds per second
  trail: 52, // Afterglow percentage
  shadow: false, // Whether to render a shadow
  hwaccel: false, // Whether to use hardware acceleration
  className: 'spinner', // The CSS class to assign to the spinner
  zIndex: 2e9, // The z-index (defaults to 2000000000)
  top: '400', // Top position relative to parent
  left: '50%' // Left position relative to parent
};
