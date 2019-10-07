<?php

//Converts the input password to sha1
$sha1pwd = (string) sha1(/*Input Password Here*/);

//takes the first 5 characters of the sha1 hash
$head = (string) substr($sha1pwd, 0, 5);

//takes the last 5 characters of the sha1 hash and makes them uppercase
$tail = strtoupper((string) substr($sha1pwd, -5));

//Performs the http request to the pwnd api
$url = 'https://api.pwnedpasswords.com/range/' . $head;
$res = (string) file_get_contents($url);

//Parses the results of the http request breaking it up into an array of seperate hashes
$res = preg_split('/\s+/', $res, -1, PREG_SPLIT_NO_EMPTY);

//Goes through all the hashes
foreach($res as $v)
{

    //Splits the hashes from the count
    $c = explode(':', $v);
    
    //Checks if any of the hashes' last 5 characters matches the tail variable
    if(strpos($c[0], $tail) !== false)
    {

        //Returns the amount of times the password appears in the pwnd api
        $count = $c[1];
        return $count;

    }

}

?>