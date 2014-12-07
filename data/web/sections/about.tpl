<div class="modal fade" id="aboutModal" tabindex="-1" role="dialog" aria-labelledby="aboutLabel" aria-hidden="true">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal"><span aria-hidden="true">&times;</span><span class="sr-only">Close</span></button>
                <h4 class="modal-title" id="aboutLabel">Viper Web Interface</h4>
            </div>
            <div class="modal-body">
                <p>The Web interface replicates the most common functions of Viper. It is project aware and most search functions are capable of spanning all projects.</p>
                <p>It does not allow for <strong>ALL</strong> the functionality of the Command Line Console</p>
                <p>The Web and CLI are not independent, Files stored in one are visible to the other.</p>
                <div class="alert alert-warning">
                    <h4>ToDo</h4>
                    <ul>
                        <li>AutoPopulate More Tabs</li>
                        <ul>
                            <li>Strings</li>
                            <li>Hex</li>
                            <li>Yara</li>
                            <li>VirusTotal</li>
                        </ul>
                        <li>Add From URL</li>
                        <li>Module Export Functions</li>
                    </ul>
                </div>
                <div class="alert alert-danger">
                    <h4>Warning</h4>
                    <p>Viper is designed to read and in some cases export files to your environment. The modules interface does not prevent this kind of action</p>
                    <p>Avoid unauthenticated access to the web interface</p>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
            </div>
        </div>
    </div>
</div>