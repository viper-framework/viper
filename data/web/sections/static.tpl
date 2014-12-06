<div class="tab-pane active" id="static">
    <div class="panel panel-default">
        <div class="panel-body">
            <table class="table table-striped table-bordered table-hover">
                <tr>
                    <th>File Name</th>
                    <td>{{file_info[0]}}</td>
                </tr>
                <tr>
                    <th>File Size</th>
                    <td>{{file_info[3]}} bytes</td>
                </tr>
                <tr>
                    <th>File Type</th>
                    <td>{{file_info[4]}}</td>
                </tr>
                <tr>
                    <th>File Mime</th>
                    <td>{{file_info[5]}}</td>
                </tr>
                <tr>
                    <th>MD5</th>
                    <td>{{file_info[6]}}</td>
                </tr>
                <tr>
                    <th>SHA1</th>
                    <td>{{file_info[7]}}</td>
                </tr>
                <tr>
                    <th>SHA256</th>
                    <td>{{file_info[8]}}</td>
                </tr>
                <tr>
                    <th>SHA512</th>
                    <td>{{file_info[9]}}</td>
                </tr>
                <tr>
                    <th>CRC32</th>
                    <td>{{file_info[11]}}</td>
                </tr>
                <tr>
                    <th>Ssdeep</th>
                    <td>{{file_info[10]}} | <span><button type="button" class="btn btn-primary btn-xs">Fuzzy Search</button></span></td>
                </tr>
                <tr>
                    <th></th>
                    <td><a class="btn btn-primary btn-small" href="/get/{{project}}/{{file_info[8]}}">Download</a> <a class="btn btn-primary btn-small" onClick="$('#cuckoo').load('/cuckoo/submit?hash={{file_info[8]}}&amp;project={{project}}');">Cuckoo</a> <span id="cuckoo"></span></td>
                </tr>          
            </table>

            <div class="alert alert-success" role="alert">
                Tags: 
                % for tag in file_info[1].split(','):
                    % if len(tag) > 0:
                        % tag = tag.strip()
                        <span><a href="/tags?action=search&amp;value={{tag}}" class="alert-link">{{tag}}</a> <a href="/tags?action=delete&amp;value={{tag}}" class="alert-link"><span class="glyphicon glyphicon-remove"></span></a></span>
                    % end
                % end
                <a href="#newTag"><span class="glyphicon glyphicon-pencil" data-toggle="modal" data-target="#newTag"></span></a>
            </div>
            <div class="modal fade" id="newTag" tabindex="-1" role="dialog" aria-labelledby="newNoteLabel" aria-hidden="true">
                <div class="modal-dialog">
                    <div class="modal-content">
                        <div class="modal-header">
                            <button type="button" class="close" data-dismiss="modal"><span aria-hidden="true">&times;</span><span class="sr-only">Close</span></button>
                            <h4 class="modal-title" id="newNoteLabel">Add New Tag</h4>
                        </div>
                        <div class="modal-body">
                            <form role="form" action="/tags/add" enctype="multipart/form-data" method="post">
                                <input type="text" class="form-control" name="tags" id="tag" placeholder="Tags">
                                <button type="submit" class="btn btn-default" name="new" value="New">Save</button>
                                <input type="hidden" name="sha256" value="{{file_info[8]}}" />
                                <input type="hidden" name="project" value="{{project}}" />
                            </form>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>