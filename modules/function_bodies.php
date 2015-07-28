<?php

//Store the file path and read the file
$path = $argv[1];
$source = file_get_contents($path);

//Break script into tokens
$tokens = token_get_all($source);

// Variables for keeping track of the function body
$foundFunc = false;
$foundFirst = false;
$count = 0;
$body = "";

foreach($tokens as $token)
{
	// If the token isn't a normal string
    if (!is_string($token)) 
    {
        list($id, $text, $line) = $token;
		// And we have found the first curly bracket
        if($foundFirst) 
        {
            $body = $body.$text;
        }
        // And we haven't found the first curly bracket, and it's a function
        else if($id == T_FUNCTION)
        {
            $foundFunc = true;         
        }
    }
    else
    {
        // If we have found a function (but not the starting bracket) and we find an opening bracket
        if($foundFunc && !$foundFirst && $token == "{") 
        {
            $foundFirst = true; 
            $count = 1;
            $body = $body.$token;
        }
        // If we have found a function and the starting bracket and we find another opening bracket
        else if($foundFunc && $foundFirst && $token == "{") 
        {
            $count++; 
            $body = $body.$token;
        }
        // If we have found a function and the starting bracket and we find a closing bracket
        else if($foundFunc && $foundFirst && $token == "}")
        {
            $count--; 
            $body = $body.$token;
        }
        // If we have found a function and the starting bracket and a string other than "{" or "}"
        else if($foundFirst)
        {
            $body = $body.$token;
        }
        
        // If we are at the end of the function body, echo the body and reset it as well as all tracking variables
        if($foundFirst && $count == 0)
        {
            print($body."\n####BREAK####\n");
            
            $body = "";
            $foundFunc = false;
            $foundFirst = false;
            $count = 0;                      
        }        
    }
}

?>
