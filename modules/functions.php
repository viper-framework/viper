<?php

//Store the file path and read the file
$path = $argv[1];
$source = file_get_contents($path);

//Break script into tokens
$tokens = token_get_all($source);

$flag = false;

foreach($tokens as $token)
{
    if (!is_string($token)) 
    {
        list($id, $text, $line) = $token;

        switch ($id) 
        {
            case T_FUNCTION:
                $flag = true;
                break;
            case T_STRING:
                if($flag)
                {
                    echo $text, "\n";
                    $flag = false;
                }
                break;                
       }
   } 
}

?>
