<%
# This gets a list of Projects for the nav bar
import os
from viper.core.project import __project__
projects_path = __project__.get_projects_path()
projects = ['default']
if os.path.exists(projects_path):
    for project in sorted(os.listdir(projects_path)):
        project_path = os.path.join(projects_path, project)
        if os.path.isdir(project_path):
            projects.append(project)
        end
    end
end
%>

<!DOCTYPE html>
<html lang="en">
<head>
    <title>{{title}}</title>
    <meta charset="UTF-8">
    <meta name="description" content="Viper Web Interface">
    <meta name="keywords" content="viper,malware,analysis">
    <link href="/static/css/bootstrap.css" rel="stylesheet">
    <link href="/static/css/style.css" rel="stylesheet">
</head>
<body>

<!-- Nav Bar -->

<nav class="navbar navbar-inverse navbar-static-top" role="navigation">
    <div class="container-fluid">
        <div class="navbar-header">
            <button type="button" class="navbar-toggle collapsed" data-toggle="collapse" data-target="#bs-example-navbar-collapse-1">
                <span class="sr-only">Toggle navigation</span>
                <span class="icon-bar"></span>
                <span class="icon-bar"></span>
                <span class="icon-bar"></span>
            </button>
            <a class="navbar-brand">Viper</a>
        </div>
        <div class="collapse navbar-collapse" id="bs-example-navbar-collapse-1">
            <ul class="nav navbar-nav">
                <li class="active"><a href="/"><i class="glyphicon glyphicon-home"></i></a></li>
                <li class="dropdown">
                <a href="#" class="dropdown-toggle" data-toggle="dropdown">Projects <span class="caret"></span></a>
                <ul class="dropdown-menu" role="menu">
                    % for project in projects:
                        <li><a href="/project/{{project}}">{{project}}</a></li>
                    % end
                </ul>
                </li>
                <li ><a href="/yara?action=list">Yara Rules</a></li>
                <li ><a href="/cli">CLI</a></li>
            </ul>

            <ul class="nav navbar-nav navbar-right">
                <li>
                <form class="navbar-form navbar-left" role="form" action="/create" enctype="multipart/form-data" method="post">
                    <input type="text" name="project" class="form-control" placeholder="New_Project">
                    <button type="submit" class="btn btn-default">Create</button>
                </form>
                </li>
                <li class="dropdown">
                    <a href="#" class="dropdown-toggle" data-toggle="dropdown">Help <span class="caret"></span></a>
                    <ul class="dropdown-menu" role="menu">
                        <li><a href="http://viper-framework.readthedocs.org/en/latest/" target="_blank">Docs</a></li>
                        <li><a href="https://github.com/viper-framework/viper/issues" target="_blank">Issues</a></li>
                        <li class="divider"></li>
                        <li><a href="#" data-toggle="modal" data-target="#aboutModal">About</a></li>
                    </ul>
                </li>
            </ul>
            % include("sections/about.tpl")
        </div>
    </div>
</nav>
<div class="container-fluid">
<p style="margin-bottom: 25px;"><img src="/static/images/viper.png" width="250" height="60" alt="Viper Malware"/></p>
