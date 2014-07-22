API
========

Viper provides a set of core command API:

  test
	file/add
	file/get/<file_hash>
	file/find
	/tags/list
	


Running API
--------

To start the API:

	user@system:~/scripts/viper$ python api.py -H 127.0.0.1 -p 8080
	Bottle server starting up (using WSGIRefServer())...
	Listening on http://127.0.0.1:8080/
	Hit Ctrl-C to quit.

API Console:

	localhost - - [22/Jul/2014 17:44:27] "GET /tags/list HTTP/1.1" 200 142
	localhost - - [22/Jul/2014 17:44:30] "POST /file/find HTTP/1.1" 200 637
	localhost - - [22/Jul/2014 17:44:32] "POST /file/find HTTP/1.1" 200 637

Following are details for all the currently available commands.
Result will be JSON


Test
--------

To test the API:

URL

	/test

Method

	GET

URL Params

	None

Success Response
	
	Code: 200
	Content:
		{
    		"message": "test"
		}

Example

	user@system:~/scripts/viper$ curl -X GET 127.0.0.1:8080/test
	{
    	"message": "test"
	}

Notes

	none


/file/add
--------

To add a file to viper:

URL

	/file/add

Method

	POST

URL Params

	tags=[alphanumeric]
	file=@FILE

Success Response
	
	Code: 200
	Content:
		{
    		"message": "added"
		}
	Code: 500 

Example

	user@system:~/scripts/viper$curl -F file=@FILE -F tags='foo bar' -X POST 127.0.0.1:8080/file/add
	{
    	"message": "added"
	}

	user@system:~/scripts/viper$ curl -F file=@FILE -F tags='foo bar'    -X POST --noproxy 127.0.0.1 127.0.0.1:8080/file/add

    	<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
    	<html>
        	<head>
		    <title>Error 500: Internal Server Error</title>
		    <style type="text/css">
		      html {background-color: #eee; font-family: sans;}
		      body {background-color: #fff; border: 1px solid #ddd;
		            padding: 15px; margin: 15px;}
		      pre {background-color: #eee; border: 1px solid #ddd; padding: 5px;}
		    </style>
		</head>
		<body>
		    <h1>Error 500: Internal Server Error</h1>
		    <p>Sorry, the requested URL <tt>&#039;http://127.0.0.1:8080/file/add&#039;</tt>
		       caused an error:</p>
		    <pre>Unable to store file</pre>
		</body>
	    </html>

Notes

	none


/file/get
--------

To receive a file from viper

URL

	/file/get/<file_hash>

Method

	GET

URL Params

	file_hash

Success Response
	
	Code: 200

Example

	user@system:~/scripts/viper$ curl -X GET 127.0.0.1:8080/file/get/9ce49435b67d531bbd966186920c90ecf0752e88b79af246886b077c8ec9b649

Notes

	file_hash is not a POST var - it is a get Param


/file/find
--------

Find a file in viper

URL

	/file/find/

Method

	POST

URL Params

	md5
	sha256
	ssdeep
	tag
	name
	all

Success Response
	
	Code: 200

Example

	user@system:~/scripts/viper$ curl -F sha256=9ce49435b67d531bbd966186920c90ecf0752e88b79af246886b077c8ec9b649 -X POST 127.0.0.1:8080/file/find
	[
	    {
		"sha1": "ac911c52b344764f733caa1ebcfabf7bd29b024b", 
		"name": "AUTHORS", 
		"tags": [
		    "foo", 
		    "bar"
		], 
		"sha512": "8368d1a806fbcae2134e69b17674388755ffec99831d1f63de54d6771f1e23141f281e679d7c6a2f8407a7129f70ddfbbde0041961b01f7779cd0ec2944804f0", 
		"created_at": "2014-07-22 14:53:15.130966", 
		"crc32": "64362766", 
		"ssdeep": "", 
		"sha256": "9ce49435b67d531bbd966186920c90ecf0752e88b79af246886b077c8ec9b649", 
		"type": "ASCII text", 
		"id": 8, 
		"md5": "8c4768f0066d50fa02a2128d2beb10e6", 
		"size": 178
	    }
	]

Notes

	None


/tags/list
--------

list all tags

URL

	/tags/list

Method

	GET

URL Params

	-

Success Response
	
	Code: 200

Example

	user@system:~/scripts/viper$ curl -X GET 127.0.0.1:8080/tags/list
	[
	    "asd", 
	    "asdasd", 
	    "asdas2d", 
	    "asdas2d3", 
	    "foo", 
	    "bar"
	]

Notes

	None
