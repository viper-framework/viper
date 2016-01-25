<div class="tab-pane" id="script">
  <form class="form-inlne" role="form" id="scriptsubmit" onsubmit="return false" name="scriptsubmit">
    <button type="submit" class="btn btn-default" name="submit" >Load file</button>
    <input type="hidden" name="file_hash" value="{{file_info[8]}}"/>
  </form>
  <hr/>
  <div class="panel panel-default">
    <div class="panel-heading">
      <h3 class="panel-title">Script Viewer</h3>
    </div>
    <div class="panel-body">
      <div class="text-left" id="scriptview">
    </div>
  </div>
</div>
