<?php

// Link parser and set nesting level 
require "parser/lib/bootstrap.php";
ini_set('xdebug.max_nesting_level', 3000);

// Initialise parser and pretty printer
$parser = new PhpParser\Parser(new PhpParser\Lexer\Emulative);
$prettyPrinter = new PhpParser\PrettyPrinter\Standard;

// Store the file path and read the file
$path = $argv[1];
$decoded = file_get_contents($path);

// Stats
$depth = 0;
$time = 0;
$numEvals = 0;
$numPregReplaces = 0;
$functionArrays = new ArrayObject();

$start = microtime(true);

decode();

$end = microtime(true);

$time = $end - $start;

print $decoded;

function decode()
{
    global $decoded, $depth;
		
	// While there are still evals or preg_replaces in the script		
	while((strpos($decoded, "eval(") !== false) || (strpos($decoded, "preg_replace(") !== false))
	{
		// Increment the obfuscation depth
		$depth++;

		// Remove the evals
		processEvals();
	
		// Remove the preg_replaces
		processPregReplace();
	}
	
	normalise();
	fix_tags();
}

function processEvals()
{
    global $decoded, $numEvals, $functionArrays;

    $currentPos = 0;	
    
	// While there are still evals in the script  
    while(strpos($decoded, "eval(", $currentPos) !== false)
	{
		// Extract the eval
		$startEval = strpos($decoded, "eval(", $currentPos);
		$currentPos = $startEval + 1;
		$endEval = strpos($decoded, ";", $currentPos);
		$eval = substr($decoded, $startEval + 5, $endEval - $startEval - 6);	

		// Count the number of functions used in the eval
		$count = substr_count($eval, "(");

		// Extract the text and populate the array of functions to be applied to it
		$functions = array();
		$functionPos = 0;
		$text = "";
		for($i = 0; $i < $count; $i++)
		{	
			$nextBracket = strpos($eval, "(", $functionPos);
			$functions[$i] = substr($eval, $functionPos, $nextBracket - $functionPos);
			$functionPos = $nextBracket + 1;
			
			if($i == $count - 1)
			{
				$startText = $nextBracket;
				$endText = strpos($eval, ")", $functionPos);
				$text = substr($eval, $startText + 1, $endText - $startText - 1);
			}
		}	 
		
		// Check if eval contains variables, and if so, abandon the replacement process
		$pattern = '/\$([a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*)/';
		if(preg_match($pattern, $text) != 0)
		{
			break;
		}
		
		// Increment the eval count
		$numEvals++;
		
		// Remove the eval and determine the code to be inserted in its place
		$decoded = str_replace("eval(".$eval.");", "", $decoded);
		$functions = array_reverse($functions);
		$functionArrays->append($functions);
		for($i = 0; $i < $count; $i++)
		{
			switch($functions[$i])
			{
				case "base64_decode":
					$text = base64_decode($text);
					break;

				case "gzinflate":
					$text = gzinflate($text);
					break;

				case "gzuncompress":
					$text = gzuncompress($text);
					break;

				case "str_rot13":
					$text = str_rot13($text);
					break;

				case "strrev":
					$text = strrev($text);
					break;

				case "rawurldecode":
					$text = rawurldecode($text);
					break;

				case "stripslashes":
					$text = stripslashes($text);
					break;

				case "trim":
					$text = trim($text);
					break;
			
				default:
					$text = $text;
					break;
			}
		}
		// Place the code back into the script
		$decoded = substr_replace($decoded, $text, $startEval, 0);
		$currentPos += strlen($text) - 1;	
	}
}

function processPregReplace()
{
    global $decoded, $numPregReplaces;

	$currentPos = 0;	
    
	// While there are still preg_replace functions in the script  
    while(strpos($decoded, "preg_replace(", $currentPos) !== false)
    {
		// Increment the preg_replace count
		$numPregReplaces++;
		
		// Extract the preg_replace
		$startPreg = strpos($decoded, "preg_replace(", $currentPos);
		$currentPos = $startPreg + 1;
		$endPreg = strpos($decoded, ";", $currentPos);
		$preg = substr($decoded, $startPreg + 13, $endPreg - $startPreg - 14);

		// Remove the preg_replace from the script
		$decoded = str_replace("preg_replace(".$preg.");", "", $decoded);
		
		// Determine the code to be inserted in the preg_replace's place
		$parts = array();
		$partPos = 1;
		for($i = 0; $i < 3; $i++)
		{	
			$nextQuote = strpos($preg, "\"", $partPos);
			$parts[$i] = (string)substr($preg, $partPos, $nextQuote - $partPos);
			$partPos = $nextQuote + 3;
		}	    
		$text = preg_replace($parts[0], "\"".$parts[1]."\"", $parts[2]);
		$decoded = substr_replace($decoded, $text, $startPreg, 0);
		$currentPos += strlen($text) - 1;
	}
}

function normalise()
{	
	global $decoded, $parser, $prettyPrinter;
	
	try 
	{
		// Parse
		$stmts = $parser->parse($decoded);

		// Pretty print
		$decoded = $prettyPrinter->prettyPrint($stmts);
	} 
	catch (PhpParser\Error $e) 
	{

	}
}

function fix_tags()
{
    global $decoded;
    
    $original = $decoded;    
    while(True)
    {
		$decoded = trim($decoded);
		$decoded = trim($decoded, "<?");
		$decoded = trim($decoded, "php");
		$decoded = trim($decoded, "PHP");
		$decoded = trim($decoded, "?>");
		
		if(strcmp($original, $decoded) == 0)
			break;
		
		$original = $decoded;
	}	
	$decoded = "<?php\n".$decoded."\n?>";			
}

?>
