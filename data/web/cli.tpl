% include("header.tpl", title="Viper Web Interface")
    <div class="panel panel-default">
        <div class="panel-body">
            <p>You can enter commands here as if you were at the console. </p>
            <form class="form-inline" role="form" id="ajaxsubmit" onsubmit="return false" name="modules">
                        <label for="cmdString">Viper Command</label>
                        <input type="text" class="form-control" name="cmdline" placeholder="Enter CLI Commands">
                        <input type="text" class="form-control" name="file_hash" placeholder="Optional Sha256"/>
                <button type="submit" class="btn btn-default" name="submit" >Run</button>
                
            </form>
            <hr/>
                    <div class="panel panel-default">
                        <div class="panel-heading">
                            <h3 class="panel-title">Module Output</h3>
                            </div>
                            <button class="btn btn-default btn-xs btn-warning" onclick="clear_div()">Clear</button>
                            <div class="panel-body">
                            <div id="ajaxresponse">
                            </div>
                        </div>
                    </div>

        </div>
    </div>
% include("footer.tpl")