<div class="tab-pane" id="modules">
    <div class="panel panel-default">
        <div class="panel-body">
            <p>Enter any command you would expect to run from the Viper Console</p>
            <form role="form" id="ajaxsubmit" onsubmit="return false">
                <div class="row">
                    <div class="form-group col-xs-2">
                        <label for="cmdString">Viper Command</label>
                        <input type="text" class="form-control" name="command_string" id="cmdString" placeholder="virustotal -s">
                    </div>
                </div>
                <button type="submit" class="btn btn-default" name="submit" >Run</button>
                <input type="hidden" name="file_hash" value="{{file_info[8]}}"/>
            </form>
            <hr/>
            <div class="row">
                <div class="col-md-8">
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
                <div class="col-md-4">
                    <div class="panel panel-default">
                        <div class="panel-heading">Module help</div>
                        <div class="panel-body">
                            <p>A list of Available Commands</p>
                            <p>Running most commands with '-h' or 'help' will display their usage</p>
                            <p>options to export or dump will be coming soon</p>
                        </div>

                        <table class="table">
                            <thead>
                                <tr>
                                    <th>Module</th>
                                    <th>Description</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr>
                                    <td>apk</td>
                                    <td>Parse Android Applications </td>
                                </tr>
                                <tr>
                                    <td>clamav</td>
                                    <td>Scan file from local ClamAV daemon</td>
                                </tr>
                                <tr>
                                    <td>cuckoo</td>
                                    <td>Submit the file to Cuckoo Sandbox</td>
                                </tr>
                                <tr>
                                    <td>debup</td>
                                    <td>Parse McAfee BUP Files</td>
                                </tr>
                                <tr>
                                    <td>editdistance</td>
                                    <td>Edit distance on the filenames</td>
                                </tr>
                                <tr>
                                    <td>elf</td>
                                    <td>Extract information from ELF headers</td>
                                </tr>
                                <tr>
                                    <td>email</td>
                                    <td>Parse eml and msg email files</td>
                                </tr>
                                <tr>
                                    <td>exif</td>
                                    <td>Extract Exif MetaData</td>
                                </tr>
                                <tr>
                                    <td>fuzzy</td>
                                    <td>Search for similar files through fuzzy hashing</td>
                                </tr>
                                <tr>
                                    <td>html</td>
                                    <td>Parse html files and extract content</td>
                                </tr>
                                <tr>
                                    <td>ida</td>
                                    <td>Start IDA Pro</td>
                                </tr>
                                <tr>
                                    <td>idx</td>
                                    <td>Parse Java idx files</td>
                                </tr>
                                <tr>
                                    <td>image</td>
                                    <td>Perform analysis on images</td>
                                </tr>
                                <tr>
                                    <td>jar</td>
                                    <td>Parse Java JAR archives</td>
                                </tr>
                                <tr>
                                    <td>office</td>
                                    <td>Office Document Parser</td>
                                </tr>
                                <tr>
                                    <td>pdf</td>
                                    <td>Parse and analyze PDF documents </td>
                                </tr>
                                <tr>
                                    <td>pe</td>
                                    <td>Extract information from PE32 headers</td>
                                </tr>
                                <tr>
                                    <td>rat</td>
                                    <td>Extract information from known RAT families</td>
                                </tr>
                                <tr>
                                    <td>reports</td>
                                    <td>Online Sandboxes Reports</td>
                                </tr>
                                <tr>
                                    <td>shellcode</td>
                                    <td>Search for known shellcode patterns</td>
                                </tr>
                                <tr>
                                    <td>strings</td>
                                    <td>Extract strings from file</td>
                                </tr>
                                <tr>
                                    <td>swf</td>
                                    <td>Parse and analyze Flash objects</td>
                                </tr>
                                <tr>
                                    <td>virustotal</td>
                                    <td>Lookup the file on VirusTotal</td>
                                </tr>
                                <tr>
                                    <td>xor</td>
                                    <td>Search for xor Strings</td>
                                </tr>
                                <tr>
                                    <td>yara</td>
                                    <td>Run Yara Scan</td>
                                </tr> 
                            </tbody>
                        </table>
                    </div>
                </div>

            </div>
        </div>
    </div>
</div>