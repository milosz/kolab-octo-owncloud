<?php

/*
  Requires the following options in ownCloud config:

  'kolaburl' => 'https://<kolab-host>/<webclient-url>',
  'kolabsecret' => '<a secret key, the same as in Roundcube owncloud plugin>',

*/


// check for kolab auth token
if (!OC_User::isLoggedIn() && !empty($_GET['kolab_auth'])) {
	OCP\Util::writeLog('kolab_auth', 'got kolab auth token', OCP\Util::INFO);

	// decode auth data from Roundcube
	parse_str(oc_kolab_decode($_GET['kolab_auth']), $request);

	// send back as POST request with session cookie
	$postdata = http_build_query($request, '', '&');

	// add request signature using secret key
	$postdata .= '&hmac=' . hash_hmac('sha256', $postdata, OC_Config::getValue('kolabsecret', '<da-sso-secret-key>'));

	$context = stream_context_create(array(
		'http' => array(
			'method' => 'POST',
				'header'=> "Content-type: application/x-www-form-urlencoded\r\n"
	 				. "Content-Length: " . strlen($postdata) . "\r\n"
					. "Cookie: " . $request['cname'] . '=' . $request['session'] . "\r\n",
				'content' => $postdata,
			)
		)
	);

	$url = !empty($_SERVER['HTTP_REFERER']) ? dirname($_SERVER['HTTP_REFERER']) . '/' : OC_Config::getValue('kolaburl', '');
	$auth = @json_decode(file_get_contents($url . '?_action=owncloudsso', false, $context), true);

	OC_App::loadApps(array('authentication'));
        if (OC_User::login($auth['user'], $auth['pass'])) {
                OC_Log::write('core',"User \"" . $auth['user'] . "\" logged in with Kolab SSO Authentication", OC_Log::DEBUG);
        }

}

function oc_kolab_decode($str)
{
	// TODO: chose a more sophisticated encryption method
	return base64_decode(str_pad(strrev($str), strlen($str) % 4, '=', STR_PAD_RIGHT));
}

