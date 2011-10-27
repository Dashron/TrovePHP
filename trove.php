<?php
/**
 * The MIT License (MIT)

 * Copyright (c) 2011 Aaron hedges

 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

 * The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

 */

/**
 * 
 * @author Aaron Hedges <aaron@dashron.com>
 * @version 
 */
class Trove {
	
	private $consumerKey;
	private $consumerSecret;
	private $token;
	private $tokenSecret;
	private $sigMethod = 'HMAC-SHA1';
	
	private static $rootUrl = 'https://api.yourtrove.com/v2/';
	private static $requestUrl = '/v2/oauth/request_token/';
	private static $authorizeUrl = '/v2/oauth/authorize/';
	const VERSION = '1.0';
	
	/**
	 * Getter for the token
	 * @return string
	 */
	public function token() {
		return $this->token;
	}
	
	/**
	 * Getter for the token secret
	 * @return string
	 */
	public function tokenSecret() {
		return $this->tokenSecret;
	}
	
	/**
	 * Consumer Key and Consumer Secret are required here. These are your oauth credentials
	 * 
	 * @param string $consumerKey Required, contains the oauth consumer key
	 * @param string $consumerSecret Required, contains the oauth consumer secret
	 * @param string $token Optional, if you have already retrieved a token you can provide it here
	 * @param string $tokenSecret Optional, if you have already retrieved a token secret you can provide it here
	 */
	public function __construct($consumerKey, $consumerSecret, $token = null, $tokenSecret = null) {
		$this->consumerKey = $consumerKey;
		$this->consumerSecret = $consumerSecret;
		$this->token = $token;
		$this->tokenSecret = $tokenSecret;
	}
	
	/**
	 * First step of oauth, contact the service provider and get an unauthorized request token.
	 * No redirections are handled here, the result is the final url string.
	 * 
	 * Once called, you MUST pull out the token secret using $trove->tokenSecret(). It will be set
	 * with an unauthorized token secret, and is required for the next step: acceptToken
	 * 
	 * @return string Url that the user should be redirected to.
	 */
	public function buildAuthURL() {
		//I believe callback is set in admin for trove
		//Build post request with any additional parameters
		//if(!isset($requestParams['oauth_callback'])) {
		//	 $requestParams['oauth_callback'] = $this->callback;
		//}
		
		//Build the signed request
		$params = $this->buildRequest('POST', self::$requestUrl); 

		//Perform the signed request to retrieve an unauthorized token
		$data = HttpUtil::httpRequest('POST', self::$requestUrl, $params);
		
		//The standard response is a query string, parse it into an array
		$data = self::parseQuery($data);
		
		//Retrieve the oauth_token, this is used in the final authorization url
		$this->token = $data['oauth_token'];
		
		//From the array we pull the token secret. This is used in authorizing a token (step 2)
		$this->tokenSecret = $data['oauth_token_secret'];
		
		//The final url is returned here, containing the configured authroizeTokenUrl and the newly
		//generated authorization token.
		return self::$authorizeUrl . "?oauth_token={$requestToken}";
		
	}
	
	/**
	 * This is step two, it must be called from the auth callback page.
	 * it must be provided with the token secret you received while building the auth url
	 * 
	 * @param string tokenSecret the secret provided upon building the authurl
	 * @param array $params
	 * @return boolean true if the token and token secret has been located, false otherwise
	 */
	public function acceptToken($tokenSecret, $params = array()) {
		
		//First we retrieve all the data we can to build the request
		//From the GET variable we pull the verifier string (for oauth 1.0a) and the token
		//From the session we pull the token secret, retrieved in step one.
		
		//verifier was added in oauth 1.0a
		if(isset($_GET['oauth_verifier']) && !isset($params['oauth_verifier'])) {
			$params['oauth_verifier'] = $_GET['oauth_verifier'];
		}
		
		$this->token = $_GET['oauth_token'];
		$this->tokenSecret = $tokenSecret;
		/*if(isset($_GET['oauth_token_secret'])) $this->tokenSecret($_GET['oauth_token_secret']);
		  else {
			$this->tokenSecret = $tokenSecret;
		  }
		*/	
		 
		//build the request from the provided parameters
		$params = $this->buildRequest('POST', $this->accessTokenUrl, $params);
		
		//request an access token using the built request
		$data = CurlUtil::post($this->accessTokenUrl, $params, array(CURLOPT_SSL_VERIFYPEER=>false));
		
		//the response is similar to the query section of a url, this parses it into an array
		$data = CurlUtil::parseQuery($data);
		
		//assign the token information to the currently logged in user
		$this->token = $data['oauth_token'];
		$this->tokenSecret = $data['oauth_token_secret'];;
		
		return !empty($this->token) && !empty($this->tokenSecret);
	}
	
	/**
	 * performs an http post request along with the necessary oauth information, and signature
	 * 
	 * @param string $url
	 * @param array $params
	 * @return the body of the http response
	 */
	function post($url, $params = array()) {
		$url = self::$rootUrl . $url;
		$params = $this->buildRequest("POST", $url, $params);
		return HttpUtil::httpRequest("POST", $url, $params);
	}
	
	/**
	 * performs an http get request along with the necessary oauth information, and signature
	 *  
	 * @param string $url
	 * @param arrray $params
	 * @return the body of the http response
	 */
	function get($url, $params = array()) {
		$url = self::$rootUrl . $url;
		$params = $this->buildRequest("GET", $url, $params);
		return HttpUtil::httpRequest("GET", $url, $params);
	}
	
	/**
	 * Builds the oauth request parameters and adds the signature.
	 *
	 * @param string $method HTTP method, GET, POST, DELETE etc.
	 * @param string $url destination url
	 * @param array $params any additional parameters that are needed
	 * @return array $params with the oauth data injected
	 */
	protected function buildRequest($method, $url, $params = array()) {
		
		$params['oauth_consumer_key'] = $this->consumerKey;
		if(isset($this->token)) {
			$params['oauth_token'] = $this->token;
		}

		//cheap and easy nonce
		//TODO: investigate more whether this is safe
		//TODO: seed mt_rand?
		$params['oauth_nonce'] = sha1(mt_rand() . microtime());
		$params['oauth_timestamp'] = time();
		$params['oauth_signature_method'] = $this->sigMethod;
		$params['oauth_version'] = self::VERSION;
		//$params['realm'] = 'photos';
		$params['oauth_signature'] = $this->buildSignature($method, $url, $params);
		return $params;
	}
	
	/**
	 * Builds the signature hash
	 *
	 * @param string $type http request type
	 * @param string $url http request url
	 * @param array $params http request parameters
	 * @return the signature for the provided request type, url and params
	 */
	protected function buildSignature($type, $url, $params) {
		ksort($params);
		$query = http_build_query($params);

		//build un-hashed signature
		$signature = self::clean($type) . "&" . self::clean($url) . "&" . $this->clean($query); //eg. GET&http%3A%2F%2Fphotos.example.net%2F

		if($params['oauth_signature_method'] == 'HMAC-SHA1') {
			$hmac_key = self::clean($this->consumerSecret) . "&";
			if(isset($this->tokenSecret)) $hmac_key .= self::clean($this->tokenSecret);
			
			return base64_encode(hash_hmac('sha1', $signature, $hmac_key, true));			
		}
		else throw new Exception('Currently unsupported signature method');
	}
	
	/**
	 * OAuth uses a different url encode scheme than php, so this function ensures compliance
	 *
	 * @param string $data
	 * @return string the cleaned data
	 */
	protected static function clean($data) {
		$data = utf8_encode($data);
		$data = rawurlencode($data);
		//cheating and un-doing the non-rfc compliant encoding
		//TODO: Do this the right way?
		return str_replace('+',' ', str_replace('%7E', '~', $data));
	}
}

/**
 * A simple utility to make curl get/post easier, and to decouple the code from curl if 
 * I want to add alternate support
 * 
 * @author Aaron Hedges <aaron@dashron.com>
 */
class HttpUtil {
	/**
	 * Posts the parameters to the provided url
	 * 
	 * @todo: remove verifypeer false
	 * @param string $url url to post the params to
	 * @param array $params List of key=>value parameters to post to the url
	 * @return string the body of the http response.
	 */
	public static function httpRequest($method, $url, $params) {
		var_dump($method, $url, $params);
		$curl = curl_init();
		curl_setopt($curl, CURLOPT_URL, $url);
		curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
		
		if($method == "GET") {
			if(isset($params)) {
				if(strstr($url, '?')) {
					$url .= '&' . http_build_query($params);
				}
				else {
					$url .= '?' . http_build_query($params);
				}
			}
		} 
		elseif ($method == "POST") {
			$params = http_build_query($params);
			curl_setopt($curl, CURLOPT_POST, 1);
			curl_setopt($curl, CURLOPT_POSTFIELDS, $params);
		}
		
		//TODO: Remove this, unsafe
		curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
		
		$data = curl_exec($curl);
		if(curl_errno($curl)) {
			$err = curl_error($curl);
			curl_close($curl);
			throw new Exception($err);
		}
		$page = curl_getinfo($curl);

		if($page['http_code']!=200) {	 
			throw new CurlException($page, $data);
		}
		curl_close($curl);
		
		return $data;
	}
	
	/**
	 * Builds an array out of the query string of a url
	 * name=john&id=5 becomes array('name'=>'john', 'id'=>'5')
	 * 
	 * @param string $query
	 * @return array an array representation of query
	 */
	public static function parseQuery($query) {
		$query = rawurldecode($query);
		$params = explode('&', $query);

		$paramArray = array();
		
		foreach($params as $param) {
			$split = explode('=', $param);
			$paramArray[$split[0]] = $split[1];
		}
		return $paramArray;
	}
}