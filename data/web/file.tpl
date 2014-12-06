% include("header.tpl", title=file_info[6])
<ul id="navTabs" class="nav nav-tabs">
    <li class="active"><a href="#static" data-toggle="tab">Static</a></li>
    <li><a href="#notes" data-toggle="tab">Notes</a></li>
    <li><a href="#modules" data-toggle="tab">Modules</a></li>
</ul>
<div class="tab-content">       
    % include("sections/static.tpl")
    % include("sections/notes.tpl")
    % include("sections/modules.tpl")   
</div>
<script type="text/javascript" src="/static/js/ajax_submit.js"></script>

% include("footer.tpl")