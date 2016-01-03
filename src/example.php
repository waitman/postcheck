<?php

define('MAX_POST_SIZE',4*1024);				/* 4k post limit, adjust as needed. */
define('MAX_CSRF_AGE',10*60);				/* 10 minutes */
define('CSRF_BYTE_SIZE',32);				/* number of random bytes to generate */
define('CSRF_SECRET_FILE','/secret/csrf-secret');	/* location of secret storage */
define('CSRF_SECRET_FILE_MAX_LIFE',24*60*60);		/* regenerate after 24 hours */
define('CSRF_TOKEN_FIELD_NAME','csrftoken');		/* field name used in form */

require_once('PostCheck/PostCheck.php');
use PostCheck\PostCheck;

$res = array(
	0 => ' Oh No! There was an error. ',
	1 => ' Everything was OK. '
);


$test = new PostCheck;
if (!$test->is_error())
{
	switch($_GET['page'])
	{
		case 'post':

echo '<!doctype html>
<html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title></title>
</head>

<body>
<p>Post Check Result</p>
'.$res[$test->check()].'
<p>'.$test->error().'</p>

<p>Post Data</p>
<pre>
'.print_r($_POST,true).'
</pre>

<p>Get Data</p>
<pre>
'.print_r($_GET,true).'
</pre>

<p>Secret File Time</p>
<p>'.date('m/d/Y g:i:s a',$test->secrettime()).'</p>


<p><a href="'.$_SERVER['PHP_SELF'].'">Go Back</a></p>
</body>
</html>
';
			break;

		default: 

			$test->nocache();		/* send http headers */

			$csrftoken = $test->gencsrf();

echo '<!doctype html>
<html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title></title>
<script>
var crsftoken = "'.$csrftoken.'";
</script>
</head>

<body>
<p>Form with file field</p>
<form method="post" action="'.$_SERVER['PHP_SELF'].'?page=post" enctype="multipart/form-data" autocomplete="off">
<input type="text" style="display:none" />
<input type="password" style="display:none" />
<input type="hidden" name="'.CSRF_TOKEN_FIELD_NAME.'" value="'.$csrftoken.'" />
<input type="text" name="boo">
<br />
<input type="file" name="files" />
<br />
<input type="submit" name="woo" value="Submit" />
</form>
<p>Form without file field</p>
<form method="post" action="'.$_SERVER['PHP_SELF'].'?page=post" autocomplete="off">
<input type="text" style="display:none" />
<input type="password" style="display:none" />
<input type="hidden" name="'.CSRF_TOKEN_FIELD_NAME.'" value="'.$csrftoken.'" />
<input type="text" name="boo">
<br /> 
<input type="submit" name="woo" value="Submit" />
</form>
</body>
</html>
';
			break;
	}

} else {
	echo 'Error: '.$test;
}


