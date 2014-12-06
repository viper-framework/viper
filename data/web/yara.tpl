% include("header.tpl", title="Yara Rules")

<h3> Yara Rules <button type="button" class="btn btn-primary btn-xs" data-toggle="modal" data-target="#editRule">Add New Rule</button> </h3>

<div class="row">
    <div class="col-md-6">
        <div class="list-group">
            % for rule in rule_list:
                <a href="/yara?action=display&amp;rule={{rule}}" class="list-group-item">{{rule}}</a>
            % end
        </div>
    </div>    
    <div class="col-md-6">
        % if rule_text:
            <pre>{{rule_text}}</pre>
            <button type="button" class="btn btn-primary" data-toggle="modal" data-target="#editRule">Edit</button>
            <a class="btn btn-primary" href="/yara?action=delete&amp;rulename={{rule_name}}">Delete</a>
        % end
    </div>
</div>

<% 
if not rule_text: 
    rule_text = ''
    rule_name = ''
end
%>

<div class="modal fade" id="editRule" tabindex="-1" role="dialog" aria-labelledby="editLabel" aria-hidden="true">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal"><span aria-hidden="true">&times;</span><span class="sr-only">Close</span></button>
                <h4 class="modal-title" id="editLabel">Editing {{rule_name}}</h4>
            </div>
            <div class="modal-body">
                <form role="form" action="/yara" enctype="multipart/form-data" method="post" onsubmit="window.location.reload();">
                    <input type="text" class="form-control" name="rule_name" value="{{rule_name}}" placeholder="Rule Name"/>
                    <textarea class="form-control" rows="10" name="rule_text" id="ruleText" placeholder="Add your rule here. No Syntax Checking">{{rule_text}}</textarea>
                    <button type="submit" class="btn btn-default" name="new" value="New">Save</button>
                </form>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
            </div>
        </div>
    </div>
</div>

% include("footer.tpl")
