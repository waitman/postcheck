<?php

/*
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
*/

namespace PostCheck;

class PostCheck {

    private $is_error;
    private $error_string;
    private $csrftoken;
    public $response;

    public function __construct()
    {
		$this->is_error = false;
		$err=array();
		if (!defined('MAX_POST_SIZE')) $err[]='MAX_POST_SIZE not defined.';
		if (!defined('MAX_CSRF_AGE')) $err[]='MAX_CSRF_AGE not defined.';
		if (!defined('CSRF_SECRET_FILE')) $err[]='CSRF_SECRET_FILE not defined';
		if (!defined('CSRF_SECRET_FILE_MAX_LIFE')) $err[]='CSRF_SECRET_FILE_MAX_LIFE not defined';
		if (!defined('CSRF_TOKEN_FIELD_NAME')) $err[]='CSRF_TOKEN_FIELD_NAME not defined';
		if (!defined('CSRF_BYTE_SIZE')) $err[]='CSRF_BYE_SIZE not defined';
		if (count($err)>0)
		{
			$this->response = join("\n",$err);
			$this->is_error = true;
			$this->error_string = $this->response;
		} else {
			$this->response = 'OK';
			$this->is_error = false;
			$this->error_string = '';
		}
     }

     public function secrettime()
     {
	if (file_exists(CSRF_SECRET_FILE))
        {
		return (filemtime(CSRF_SECRET_FILE));
	} else {
		return (0);
	}
     }

     public function gencsrf()
     {
			$t = time();

			$regen_secret = true;

			if (file_exists(CSRF_SECRET_FILE))
			{
				$s = unserialize(file_get_contents(CSRF_SECRET_FILE));
				if (array_key_exists('secret',$s)) $secret = $s['secret'];
				if (strlen($secret)===(CSRF_BYTE_SIZE*2)) $regen_secret = false;
				if (filemtime(CSRF_SECRET_FILE)<($t-CSRF_SECRET_FILE_MAX_LIFE)) $regen_secret = true;
			} else {
				$s=array();
			}

			if ($regen_secret)
			{
				$bytes = openssl_random_pseudo_bytes(CSRF_BYTE_SIZE);
				$hex   = bin2hex($bytes);
				/* 
					save previous secret to avoid problems with overlap
					when new key is generated but some users are still 
					using old key
				*/
				if (is_array($s) && array_key_exists('secret',$s))
				{
					$s['old-secret']=$s['secret'];
					$s['secret']=$hex;
				} else {
					$s = array(
						'secret'=>$hex
					);
				}
				$fp = fopen(CSRF_SECRET_FILE,'w');
				fwrite($fp,serialize($s));
				fclose($fp);
				$secret = $hex;
				if (!is_writable(CSRF_SECRET_FILE)) exit('could not write to csrf secrets file');
			}
		
			$bytes = openssl_random_pseudo_bytes(CSRF_BYTE_SIZE);
			$hex   = bin2hex($bytes);

			if (session_id() == "")
				session_start();

			$seal = password_hash($t.$hex.$secret.session_id(),PASSWORD_DEFAULT);
			$a=array(
				't'=>$t,
				'p'=>$hex,
				'seal'=>$seal
			);
			$this->csrftoken = base64_encode(serialize($a));
			$this->response = $this->csrftoken;
			return ($this->csrftoken);
	}
	
	public function check()
	{
		$valid = true;
		$err=array();
		if (is_array($_SERVER))
		{
			/* must be post over HTTPS */
			if (!(array_key_exists('HTTPS',$_SERVER) 
					&& ($_SERVER['HTTPS']==='on'))) 
			{
				$err[] = 'Request not made over HTTPS';
			}

			if (!(array_key_exists('REQUEST_METHOD',$_SERVER) 
					&& ($_SERVER['REQUEST_METHOD']==='POST'))) 
			{
				$err[] = 'Request not made using POST';
			}
			
			/* must have valid content type */
			if (!(array_key_exists('HTTP_CONTENT_TYPE',$_SERVER) 
					&& (($_SERVER['HTTP_CONTENT_TYPE']==='application/x-www-form-urlencoded') 
					|| (substr($_SERVER['HTTP_CONTENT_TYPE'],0,19)==='multipart/form-data')))) 
			{
				$err[] = 'Invalid Content-Type';
			}
	
			/* must be keep-alive, not close */
			if (!(array_key_exists('HTTP_CONNECTION',$_SERVER) && 
					($_SERVER['HTTP_CONNECTION']==='keep-alive')))
			{
				$err[] = 'Invalid Connection Type';
			}
	
			/* referrer must match host */
			if (!(array_key_exists('HTTP_REFERER',$_SERVER) && 
					array_key_exists('HTTP_HOST',$_SERVER) && 
					(substr($_SERVER['HTTP_REFERER'],8,strlen($_SERVER['HTTP_HOST']))===$_SERVER['HTTP_HOST'])))
			{
				$err[] = 'Invalid Referrer';
			}
	
			/* if not uploading file(s) then limit post data size to MAX_POST_SIZE, otherwise fall back to php.ini setting for max */
			$check_size = true;
			if (is_array($_FILES) && 
					(count($_FILES)>0)) $check_size = false;
			if ($check_size && 
					(array_key_exists('HTTP_CONTENT_LENGTH',$_SERVER) && 
					intval($_SERVER['HTTP_CONTENT_LENGTH'])>MAX_POST_SIZE))
			{
				$err[] = 'Content data payload too large '.$_SERVER['HTTP_CONTENT_LENGTH'].' > '.MAX_POST_SIZE;
			}

			/* check csrf token */
			if (session_id() == "")
				session_start();

			$csrf_valid = false;
			if (is_array($_POST) && 
				array_key_exists(CSRF_TOKEN_FIELD_NAME,$_POST))
			{
				$a = unserialize(base64_decode($_POST[CSRF_TOKEN_FIELD_NAME]));
				if (is_array($a) && array_key_exists('t',$a) && array_key_exists('seal',$a) && array_key_exists('p',$a))
				{
					if ((time()-MAX_CSRF_AGE)<$a['t'])
					{
						if (file_exists(CSRF_SECRET_FILE))
						{
							$s = unserialize(file_get_contents(CSRF_SECRET_FILE));
							if (is_array($s) && array_key_exists('secret',$s)) $secret = $s['secret'];
							if (strlen($secret)===(CSRF_BYTE_SIZE*2))
							{
								if (password_verify($a['t'].$a['p'].$secret.session_id(),$a['seal']))
								{
									$csrf_valid = true;
								} else {
									/* check old secret in case user got the key right before regen */
									if (array_key_exists('old-secret',$s)) $secret = $s['old-secret'];
									if (strlen($secret)===(CSRF_BYTE_SIZE*2))
									{
										if (password_verify($a['t'].$a['p'].$secret.session_id(),$a['seal']))
										{
											$csrf_valid=true;
										}
									}
								}
							}
						}
					}
				}
			}
			if (!$csrf_valid)
			{
				$err[]='Invalid or expired CSRF Token';
			}
		} else {
			$err[] = 'Invalid Request';
		}
		
		if (count($err)>0)
		{
			http_response_code(500);
			$valid = false;
			$this->response = join("\n",$err);
			$this->is_error = true;
			$this->error_string = $this->response;
		} else {
			$valid =true;
			$this->is_error = false;
			$this->response = 'OK';
			$this->error_string = '';
		}
		return ($valid);
	}

	public function __toString()
	{
		return $this->response;
	}
	
	public function error()
	{
		return $this->error_string;
	}

	public function nocache()
	{
		Header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
		Header("Cache-Control: post-check=0, pre-check=0", false);
		Header("Pragma: no-cache");
	}

	public function is_error()
	{
		return $this->is_error;
	}
}

