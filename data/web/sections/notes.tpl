<div class="tab-pane" id="notes">
    <div class="panel panel-default">
        <div class="panel-body">
            <button class="btn btn-primary btn-small" data-toggle="modal" data-target="#newNote">Add New Note</button>
            <div class="row">
                % for note in notes:
                    <div class="col-md-4">
                        <div class="note-box">
                            <form role="form" action="/file/notes" enctype="multipart/form-data" method="post" onsubmit="window.location.reload();">
                                <input type="text" class="form-control" name="noteTitle" value="{{note[0]}}">
                                <textarea class="form-control" rows="5" name="noteBody">{{note[1]}}</textarea>
                                <input type="hidden" name="id" value="{{note[2]}}" />
                                <input type="hidden" name="sha256" value="{{file_info[8]}}" />
                                <input type="hidden" name="project" value="{{project}}" />
                                <button type="submit" class="btn btn-default" name="update" value="Update">Update</button>
                                <button type="submit" class="btn btn-default btn-danger" name="delete" value="Delete" onclick="return confirm('Are you sure you want to delete this note?')">Delete</button>
                            </form>
                        </div>
                    </div>
                % end
            </div>

            <div class="modal fade" id="newNote" tabindex="-1" role="dialog" aria-labelledby="newTagLabel" aria-hidden="true">
                <div class="modal-dialog">
                    <div class="modal-content">
                        <div class="modal-header">
                            <button type="button" class="close" data-dismiss="modal"><span aria-hidden="true">&times;</span><span class="sr-only">Close</span></button>
                            <h4 class="modal-title" id="newTagLabel">Add New Note</h4>
                        </div>
                        <div class="modal-body">
                            <form role="form" action="/file/notes" enctype="multipart/form-data" method="post" onsubmit="window.location.reload();">
                                <input type="text" class="form-control" name="noteTitle" id="noteTitle" placeholder="Title">
                                <textarea class="form-control" rows="3" name="noteBody" id="noteBody" placeholder="Note Text"></textarea>
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