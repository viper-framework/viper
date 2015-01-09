$('#ajaxsubmit').submit(function(event){
  $.ajax({
    url: '/file/module',
    type: 'post',
    dataType:'html', 
    data: $('#ajaxsubmit').serialize(),
    beforeSend: function() {
        var target = document.getElementById('spin_loader');
        var spinner = new Spinner(opts).spin(target);
        $(target).data('spinner', spinner);
    },
    complete: function() {
        $('#spin_loader').data('spinner').stop();
    },
    success: function(response, textStatus, jqXHR){
        $('#ajaxresponse').prepend(response);      
    },
   error: function(jqXHR, textStatus, errorThrown){
        console.log('error(s):'+textStatus, errorThrown);
   }
 });
 });

 
$('#hexsubmit').submit(function(event){
  $.ajax({
    url: '/hex',
    type: 'post',
    dataType:'html', 
    data: $('#hexsubmit').serialize(),
    beforeSend: function() {
        var target = document.getElementById('spin_loader');
        var spinner = new Spinner(opts).spin(target);
        $(target).data('spinner', spinner);
    },
    complete: function() {
        $('#spin_loader').data('spinner').stop();
        var hex_start = document.getElementById('hex_start');
        hex_start.value = parseInt(hex_start.value, 10) + 256;
    },
    success: function(response, textStatus, jqXHR){
        $('#hexview').append(response);

    },
   error: function(jqXHR, textStatus, errorThrown){
        console.log('error(s):'+textStatus, errorThrown);
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
