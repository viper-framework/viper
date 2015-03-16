<div class="tab-pane" id="modules">
    <p>Select a module or run a command</p>
    <form class="form-inline" role="form" id="ajaxsubmit" onsubmit="return false" name="modules">
                <label for="cmdString">Viper Command</label>
                <select class="form-control" name="module" onchange="setOptions(document.modules.module.options[document.modules.module.selectedIndex].value);">
                  <option value="module">Module</option>
                  <option value="apk">APK - Parse Android APKs</option>
                  <option value="clamav">ClamaAV - Scan file from local ClamAV daemon</option>
                  <option value="debup">Debup - Parse McAfee BUP Files</option>
                  <option value="editdistance">Edit Distance - Filename Edit Distance</option>
                  <option value="elf">ELF - Extract information from ELF headers</option>
                  <option value="email">Email - Parse eml and msg Files</option>
                  <option value="exif">Exif - Extract MetaData</option>
                  <option value="fuzzy">Fuzzy - SSdeep CTPH Scan</option>
                  <option value="html">HTML - Parse HTML Data</option>
                  <option value="idx">IDX - Parse Java IDX Files</option>
                  <option value="image">Image - Perfom analysis on images</option>
                  <option value="jar">JAR - Parse Java archives</option>
                  <option value="office">Office - Office document parser</option>
                  <option value="pdf">PDF - PDF document parser</option>
                  <option value="pe">PE - Parse PE32 files</option>
                  <option value="rat">RAT - Extract config from common rats</option>
                  <option value="reports">Reports - Online sandbox reports</option>
                  <option value="shellcode">ShellCode - Identify shellCode patterns</option>
                  <option value="strings">Strings - Extract strings</option>
                  <option value="swf">SWF - Parse SWF files</option>
                  <option value="virustotal">VirusTotal</option>
                  <option value="xor">XOR - Encoded strings</option>
                  <option value="yara">Yara - Scan with Yara rules</option>

                </select>
                <select class="form-control" name="command">
                    <option value=" ">Select a module first</option>
                </select>
                <input type="text" class="form-control" name="cmdline" placeholder="Enter CLI Commands">
        <button type="submit" class="btn btn-default" name="submit" >Run</button>
        <input type="hidden" name="file_hash" value="{{file_info[8]}}"/>
    </form>
    <hr/>
    <div class="panel panel-default">
        <div class="panel-heading">
            <div class="row">
                <div class="col-md-8"><h3 class="panel-title">Module Output</h3></div>
                <div class="col-md-4" style="text-align: right;"><button class="btn btn-default btn-xs btn-primary" onclick="clear_div()">Clear</button></div>
            </div>
        </div>
        <div class="panel-body">
            <div id="ajaxresponse"></div>
        </div>
    </div>
</div>
