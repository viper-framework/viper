<div class="tab-pane" id="modules">
    <div class="panel panel-default">
        <div class="panel-body">
            <p>Select A Module then a Command</p>
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
                          <option value="image">Image - Perfome Analysis On Images</option>
                          <option value="jar">JAR - Parse Java Archives</option>
                          <option value="office">Office - Office Document Parser</option>
                          <option value="pdf">PDF - PDF Document Parser</option>
                          <option value="pe">PE - Parse PE32 Files</option>
                          <option value="rat">RAT - Extract Config From Common Rats</option>
                          <option value="reports">Reports - Online Sandbox Reports</option>
                          <option value="shellcode">ShellCode - Identify ShellCode Patterns</option>
                          <option value="strings">Strings - Extract Strings</option>
                          <option value="swf">SWF - Parse SWF Files</option>
                          <option value="virustotal">VirusTotal</option>
                          <option value="xor">XOR - Encoded Strings</option>
                          <option value="yara">Yara - Scan With Yara Rules</option>

                        </select>
                        <select class="form-control" name="command">
                            <option value=" ">Select a Module First</option>
                        </select>
                        <input type="text" class="form-control" name="cmdline" placeholder="Enter CLI Commands">
                <button type="submit" class="btn btn-default" name="submit" >Run</button>
                <input type="hidden" name="file_hash" value="{{file_info[8]}}"/>
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
</div>
