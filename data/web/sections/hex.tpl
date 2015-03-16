<div class="tab-pane" id="hex">
    <form class="form-inline" role="form" id="hexsubmit" onsubmit="return false" name="hexsubmit">
        <button type="submit" class="btn btn-default" name="submit" >Load More</button>
        <input type="hidden" name="file_hash" value="{{file_info[8]}}"/>
        <input type="hidden" id="hex_start" name="hex_start" value="0"/>
        <input type="hidden" id="hex_end" name="hex_end" value="32"/>
    </form>
    <hr/>
    <div class="panel panel-default">
        <div class="panel-heading">
            <h3 class="panel-title">Hex Viewer</h3>
            </div>
            <div class="panel-body">
            <div class="text-center" id="hexview">
            </div>
        </div>
    </div>
</div>