$('#ajaxsubmit').submit(function(event){
  $.ajax({
    url: '/file/module',
    type: 'post',
    dataType:'html', 
   data: $('#ajaxsubmit').serialize(),
   success: function(response, textStatus, jqXHR){
      $('#ajaxresponse').prepend(response);   
    },
   error: function(jqXHR, textStatus, errorThrown){
      console.log('error(s):'+textStatus, errorThrown);
   }
 });
 });

function clear_div() {
    document.getElementById("ajaxresponse").innerHTML = "";
}