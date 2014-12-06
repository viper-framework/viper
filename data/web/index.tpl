% include("header.tpl", title="Viper Web Interface")

<!-- File Uploader -->
<script type="text/javascript">
$(document).on('change', '.btn-file :file', function() {
  var input = $(this),
      numFiles = input.get(0).files ? input.get(0).files.length : 1,
      label = input.val().replace(/\\/g, '/').replace(/.*\//, '');
  input.trigger('fileselect', [numFiles, label]);
});

$(document).ready( function() {
    $('.btn-file :file').on('fileselect', function(event, numFiles, label) {
        
        var input = $(this).parents('.input-group').find(':text'),
            log = numFiles > 1 ? numFiles + ' files selected' : label;
        
        if( input.length ) {
            input.val(log);
        } else {
            if( log ) alert(log);
        }
        
    });
});
</script>

<div class="panel panel-default">
    <div class="panel-heading">
        <h3 class="panel-title">Upload Sample</h3>
    </div>
    <div class="panel-body">
        <form class="form-inline" role="form" action="/add" enctype="multipart/form-data" method="post" name="submit">
            <div class="form-group">
                    <div class="input-group">
                        <span class="input-group-btn">
                            <span class="btn btn-default btn-file">
                                Browse&hellip; <input type="file" name="file" multiple>
                            </span>
                        </span>
                        <input type="text" class="form-control" readonly>
                    </div>
            </div>

            <div class="checkbox">
                <label>
                <input type="checkbox" name="unzip" value="unzip"> UnZip
                </label>
            </div>

            <div class="form-group">
                <label class="sr-only" for="zip_pass">Zip Pass</label>
                <input type="password" class="form-control" name="zip_pass" id="zip_pass" placeholder="Zip Password">
            </div>


            <div class="form-group">
                <label for="tag_list">Tags</label>
                <input type="text" class="form-control" name="tag_list" id="tag_list" placeholder="List of Tags">
            </div>
            
            <input type="hidden" name="project" value="{{p}}" />
            <button type="submit" class="btn btn-default">Upload</button>
        </form>
    </div>
</div>

<!-- Download from URL -->
<div class="panel panel-default">
    <div class="panel-heading">
        <h3 class="panel-title">URL Download</h3>
    </div>
    <div class="panel-body">
        <form class="form-inline" role="form" action="/URLDownload" enctype="multipart/form-data" method="post" name="submit">
            <div class="form-group">
                <label class="sr-only" for="URL">URL</label>
                <input type="search" class="form-control" name="url" id="url" placeholder="URL">
            </div>

            <div class="checkbox">
                <label><input type="checkbox" name="tor" value="tor"> Use Tor</label>
            </div>

            <div class="form-group">
                <label for="tag_list">Tags</label>
                <input type="text" class="form-control" name="tag_list" id="tag_list" placeholder="List of Tags">
            </div>

            <button type="submit" class="btn btn-default">Run</button>
        </form>
    </div>
</div>

<!-- Search -->
<div class="panel panel-default">
    <div class="panel-heading">
        <h3 class="panel-title">Search Samples</h3>
    </div>
    <div class="panel-body">
<form class="form-inline" role="form" action="/search" enctype="multipart/form-data" method="post" name="search" target="_self">
  <div class="form-group">
      <select class="form-control" name="key">
        <option value="name">Name</option>
        <option value="type">Type</option>
        <option value="mime">Mime</option>
        <option value="md5">MD5</option>
        <option value="sha256">SHA256</option>
        <option value="tag">Tag</option>
        <option value="note">Note</option>
    </select>
  </div>


  <div class="form-group">
    <label class="sr-only" for="term">Search Term</label>
    <input type="text" class="form-control" name="term" id="term" placeholder="Search Term">
  </div>


  <div class="checkbox">
    <label>
      <input type="checkbox" name="project" value="project"> All Projects
    </label>
  </div>
  <input type="hidden" name="curr_project" value="{{p}}" />
  <button type="submit" class="btn btn-default">Search</button>
</form>
</div>
</div>

<!-- List Submissions -->

<div class="panel panel-default">
    <div class="panel-heading">
        <h3 class="panel-title">Project <span class="text-success"><strong>{{p}}</strong></span> contains: <span class="text-success"><strong>{{count}}</strong></span> Files</h3>
    </div>

        <table class="table table-striped table-bordered table-hover">
            <tr>
                <th>#</th>
                <th>Name</th>
                <th>SHA256</th>
                <th>Tags</th>
            </tr>
            % for row in latest:
            <tr>
                <td>{{row.id}}</td>
                <td><a href="/file/{{p}}/{{row.sha256}}">{{row.name}}</a></td>
                <td><span class="mono">{{row.sha256}}</span></td>
                <td>
                % for tags in row.tag:
                {{tags.tag}},
                % end
                </td>
            </tr>
            % end      
        </table>

</div>

<%
# number of pages
num_pages = count / 25
if num_pages % 25 > 0:
    num_pages += 1
end
cur_page = int(act_page)
%>

% if num_pages > 0:
    <!-- pagination -->
    <div class="text-center">
        <ul class="pagination">
            
          <li><a href="/project/{{p}}?page={{cur_page-1}}">&laquo;</a></li>
          % for i in range(num_pages):
          <li
          % if act_page: 
          % if i == cur_page: 
          class="active" 
          % end
          % end
          >
          
          <a href="/project/{{p}}?page={{i}}">{{i}}</a></li>
          % end
          <li><a href="/project/{{p}}?page={{cur_page+1}}">&raquo;</a></li>
        </ul>
    </div>

    <script type="text/javascript" src="/static/js/pagination.js"></script>
% end
% include("footer.tpl")
