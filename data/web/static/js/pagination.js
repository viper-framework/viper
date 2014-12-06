// https://gist.github.com/korpirkor/8721979
$('.pagination').each(function(){
  var allLi = $(this).find('li');
  if(allLi.length > 20) {
    var activeId = allLi.filter('.active').index();
    allLi.eq(0)
    .add(allLi.eq(1))
    .add(allLi.eq(2))
    .add(allLi.eq(3))
    .add(allLi.eq(4))
    .add(allLi.eq(-1))
    .add(allLi.eq(-2))
    .add(allLi.eq(-3))
    .add(allLi.eq(-4))
    .add(allLi.eq(activeId))
    .add(allLi.eq(activeId-1))
    .add(allLi.eq(activeId-2))
    .add(allLi.eq(activeId-3))
    .add(allLi.eq(activeId+1))
    .add(allLi.eq(activeId+2))
    .add(allLi.eq(activeId+3))
    .addClass('allow');
    var replacedWithDots = false;
    allLi.each(function() {
      if( $(this).hasClass('allow') ) {
        replacedWithDots = false;
      } else if(!replacedWithDots) {
        replacedWithDots = true;
        $(this).html('<a>...</a>');
      } else {
        $(this).remove();
      }
    })
  }
});