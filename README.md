
PostCheck / PHP

This program provides a PHP class which validates POST requests.


# PostCheck

1) Request made over HTTPS

2) Request made using POST

3) Valid Content-Type (application/x-www-form-urlencoded or multipart/form-data)

4) HTTP Connection type must be keep-alive (ie, not 'close')

5) Referrer must match host

6) Content Length data payload must not exceed defined limit (if no files uploaded)

7) CSRF Token check



# Simple example

```
<?php

define('MAX_POST_SIZE',4*1024);                         /* 4k post limit, adjust as needed. */
define('MAX_CSRF_AGE',10*60);                           /* 10 minutes */
define('CSRF_BYTE_SIZE',32);                            /* number of random bytes to generate */
define('CSRF_SECRET_FILE','/secret/csrf-secret');       /* location of secret storage */
define('CSRF_SECRET_FILE_MAX_LIFE',24*60*60);           /* regenerate after 24 hours */
define('CSRF_TOKEN_FIELD_NAME','csrftoken');            /* field name used in form */

require_once('vendor/autoload.php'); //composer

use PostCheck\PostCheck;

$test = new PostCheck;
if (!$test->is_error())
{
	
	if (!$test->check()) 			/* check form post */
		echo $test->error(); 
	
	echo $test->secrettime();	/* when secret was generated */
	
	$test->nocache();               /* send http headers */

    $csrftoken = $test->gencsrf();  /* generate CSRF token */
}

```

Note: see src/example.php

# Notes

CSRF Token may be stored in $_SESSION, however pay special attention to 
CSRF_SECRET_FILE_MAX_LIFE and MAX_CSRF_AGE



# LICENSE

Copyright (c) 2016 Waitman Gobble <ns@waitman.net>.
All rights reserved.

Redistribution and use in source and binary forms are permitted
provided that the above copyright notice and this paragraph are
duplicated in all such forms and that any documentation,
advertising materials, and other materials related to such
distribution and use acknowledge that the software was developed
by Waitman Gobble. The name of Waitman Gobble may not be used to 
endorse or promote products derived from this software without 
specific prior written permission. THIS SOFTWARE IS PROVIDED ``AS IS'' 
AND WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, WITHOUT 
LIMITATION, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS 
FOR A PARTICULAR PURPOSE.


# INSTALLING IT WITH composer

edit composer.json in your project directory:
```
{
        "minimum-stability": "dev",
        "require": {
                "waitman/postcheck": "dev-master"
        }
}
```

```
# composer update
```

