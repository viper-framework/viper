% include("header.tpl", title="Search Results")

% for proj in results.iterkeys():
    % if len(results[proj]) > 0:
        <div class="panel panel-default">
            <div class="panel-heading">
                <h3 class="panel-title">Results for Project {{proj}}</h3>
            </div>
            <div class="panel-body">
                <table class="table table-striped table-bordered">
                    <tr>
                        <th>Name</th>
                        <th>Sha256</th>
                    </tr>
                    % for res in results[proj]:
                        <tr>
                            <td><a href="/file/{{proj}}/{{res[1]}}">{{res[0]}}</a></td>
                            <td>{{res[1]}}</td>
                        </tr>
                    % end      
                </table>
            </div>
        </div>
    % end
% end

% include("footer.tpl")
