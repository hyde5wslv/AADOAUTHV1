<?php
require_once	'Zend/Controller/Plugin/Abstract.php';

/**
 * Implement the privilege controller.
 */
class Common_Plugin_MyAuth	extends	Zend_Controller_Plugin_Abstract 
{
	/**
	 * An instance of Zend_Auth
	 * @var Zend_Auth
	 */
	private $_auth;
	
	/**
	 * An instance of Custom_Acl
	 * @var Custom_Acl
	 */
	private $_acl;
	
	/**
	 * Redirect to a new controller when the user has a invalid indentity.
	 * @var array
	 */
	private $_noauth=array(	'module'=>'default',
							'controller'=>'index',
							'action'=>'singelogin');
	/**
	 * Redirect to 'error' controller when the user has a vailid identity 
	 * but no privileges
	 * @var array
	 */
	private $_nopriv=array(	'module'=>'default',
							'controller'=>'error',
							'action'=>'nopriv');
							
	private $_licenserestrict=array(	'module'=>'default',
							'controller'=>'error',
							'action'=>'licenserestrict');
							
	private $_notfound=array(	'module'=>'default',
							'controller'=>'error',
							'action'=>'notfound');
							
	private $_error=array(	'module'=>'default',
							'controller'=>'error',
							'action'=>'error');
	private $_ajaxnoauth=array(	'module'=>'default',
								'controller'=>'error',
								'action'=>'ajaxnoauth');
	
	/**
	 * Constructor.
	 * @return void
	 */
	
	public function	__construct($auth,$acl)
	{
		$this->_auth = $auth;
		$this->_acl = $acl;
	}
	
	/**
	 * Track user privileges.
	 * @param Zend_Controller_Request_Abstract $request
	 * @return void
	 */
	public function	preDispatch(Zend_Controller_Request_Abstract $request)
	{
		$role = 'guest';
		$backend_ip = Zend_Registry::get("backend_ip");
		$backend_port = Zend_Registry::get("backend_port");
		$personConsoleNamespace = new Zend_Session_Namespace('person_console');
		
		$module = $request->module;
		$controller = $request->controller;
		$action = $request->action;
		$csrf = new CSRFHandler();
		
		$coremail_sso = false;
		$sid = null;
		if (Zend_Registry::get('coremail_ext_sso') == 1) {
			$coremail_sso = true;
			$sid = $request->get ( 'sid' );
		}		
		$cur_lang = Zend_Registry::get ('default_lang');
		$cur_skin = "classic";
		$pskin = $request->get('skin');
		if ($pskin == "outlook" || $pskin == "classic") {
			$cur_skin = $pskin;
		} else if (isset($_COOKIE['skin'])) {
			if ($_COOKIE['skin'] == "outlook" || $_COOKIE['skin'] == "classic") {
				$cur_skin = $_COOKIE['skin'];
			}
		}
		setcookie("skin", $cur_skin, 0, '/');
		Zend_Registry::set ( 'cur_skin', $cur_skin );

		if (isset($_SERVER['HTTP_ACCEPT_LANGUAGE'])) {
			if (strpos($_SERVER['HTTP_ACCEPT_LANGUAGE'], 'en') === 0) {
				$cur_lang = 'en';
			} else if (strpos($_SERVER['HTTP_ACCEPT_LANGUAGE'], 'zh') === 0) {
				$cur_lang = 'zh';
			}		
		}
		if (isset($_COOKIE['locale'])) {
			if ($_COOKIE['locale'] == "zh" || $_COOKIE['locale'] == "en") {
				$cur_lang = $_COOKIE['locale'];
			}
		} else {
			setcookie("locale", $cur_lang, 0, '/');
		}
		 if ($cur_lang == "zh" || $cur_lang == "en") {
            Zend_Registry::set ( 'cur_locale', $cur_lang );
        } else {
            Zend_Registry::set ( 'cur_locale', "zh" );
        }
	if(isset($personConsoleNamespace->expires_in) && (time() > $personConsoleNamespace->expires_in)){
	    $module = 'default';
            $controller = 'index';
            $action = 'refreshtoken';
            $request->setModuleName($module);
            $request->setControllerName($controller);
            $request->setActionName($action);
            return;
        }
        if(isset($_GET['code']) && !empty($_GET['code']) && $controller == 'index' && $action == 'singecallback'){
            $request->setModuleName($module);
            $request->setControllerName($controller);
            $request->setActionName($action);
            return;
        }

		if (!$coremail_sso) {
			if (isset($_SERVER['HTTP_REFERER']) && !empty($_SERVER['HTTP_REFERER'])) {
				$referer = strtolower($_SERVER['HTTP_REFERER']);
				$server_addr = strtolower($_SERVER['SERVER_ADDR']);
				$http_host = strtolower($_SERVER['HTTP_HOST']);
				$server_name = strtolower($_SERVER['SERVER_NAME']);
				$refererParse = parse_url($referer);
				if ($refererParse['host'] != $server_addr && $refererParse['host'] != $server_name && strpos($http_host, $refererParse['host']) !== 0) {
					/*$module = $this->_nopriv['module'];
					$controller = $this->_nopriv['controller'];
					$action = $this->_nopriv['action'];*/
					$request->setModuleName($module);
					$request->setControllerName($controller);
					$request->setActionName($action);
					//return;
				}
			}
		}
		
		/*if ($cur_lang == "zh" || $cur_lang == "en") {
			Zend_Registry::set ( 'cur_locale', $cur_lang );
		} else {
			Zend_Registry::set ( 'cur_locale', "zh" );
		}*/
		
		$resource = "$module:$controller";
		if(!$this->_acl->has($resource)){
			$module = $this->_notfound['module'];
			$controller = $this->_notfound['controller'];
			$action = $this->_notfound['action'];
			$request->setModuleName($module);
			$request->setControllerName($controller);
			$request->setActionName($action);
			return;
		}
		
		if ($_SERVER['REQUEST_METHOD'] == 'POST' && !($controller == 'index' && $action == 'login')) {
			if (!$csrf->isTokenValid($_POST['longger'])) {
				$module = $this->_nopriv['module'];
				$controller = $this->_nopriv['controller'];
				$action = $this->_nopriv['action'];
				$request->setModuleName($module);
				$request->setControllerName($controller);
				$request->setActionName($action);
				return;
			}
		}
		if (!empty($_GET['longger']) || !empty($_GET['lang'])) {
			// Zend_Session::expireSessionCookie();
			// Zend_Session::regenerateId();
			$module = $this->_nopriv['module'];
			$controller = $this->_nopriv['controller'];
			$action = $this->_nopriv['action'];
			$request->setModuleName($module);
			$request->setControllerName($controller);
			$request->setActionName($action);
			return;
		}
		if (isset($personConsoleNamespace->login_user)) {
		   	$login_user = $personConsoleNamespace->login_user;
		   	if ($login_user != null)
				$role = $login_user['role'];  
     	}
		if (!(($controller == 'index' && $action == 'logout') || ($controller == 'index' && $action == 'kl') || ($controller == 'index' && $action == 'captcha') || ($controller == 'index' && $action == 'login'))) {		
			$licenseinfo = $personConsoleNamespace->licenseinfo;
			if ($licenseinfo == NULL) {
				$licenseinfo = SnifferAPI::GetLicenseInfo($backend_ip, $backend_port);
				$personConsoleNamespace->licenseinfo = $licenseinfo;
			}
			if ($licenseinfo == NULL) {
				$module = $this->_licenserestrict['module'];
				$controller = $this->_licenserestrict['controller'];
				$action = $this->_licenserestrict['action'];
				$request->setModuleName($module);
				$request->setControllerName($controller);
				$request->setActionName($action);
				return;
			} else {
				$endyear = $licenseinfo["end_year"];
				$endmonth = $licenseinfo["end_month"];
				$enddate = $licenseinfo["end_date"];
				$end_time = mktime(23,59,59,$endmonth,$enddate,$endyear);
				$current_time = time();
				$invalid_license = true;
				if ($current_time > $end_time) {
					$invalid_license = false;
				}
				if (!$invalid_license) {
					$module = $this->_licenserestrict['module'];
					$controller = $this->_licenserestrict['controller'];
					$action = $this->_licenserestrict['action'];
					$request->setModuleName($module);
					$request->setControllerName($controller);
					$request->setActionName($action);
					return;
				}
			}
		}
		// download msg
		if ($controller == "download" && $action == "downloadmsg") {
			$request->setModuleName($module);
			$request->setControllerName($controller);
			$request->setActionName($action);
			return;
		}

		if ($controller == 'index' && $action == 'captcha') {
			$request->setModuleName($module);
			$request->setControllerName($controller);
			$request->setActionName($action);
			return;
		}
		
		if ($role=='admin') {		
			$module = $this->_noauth['module'];
			$controller = $this->_noauth['controller'];
			$action = $this->_noauth['action'];
			$request->setModuleName($module);
			$request->setControllerName($controller);
			$request->setActionName($action);
			return;
		}
		if(!$this->_acl->isAllowed($role,$resource,$action)){
			if($role=='guest'){
				$get_auth = false;
				if ($coremail_sso && $sid != null) {
					$server_addr = Zend_Registry::get('coremail_ext_address');
					$server_port = Zend_Registry::get('coremail_ext_port');
					$ssocmd = "sudo java -jar /opt/bin/coremail_ext.jar ".$server_addr." ".$server_port." ".$sid." 0 0";
					@exec($ssocmd, $return_array, $status);
					$uid = null;
					if (count($return_array)>0) {
						$uid = $return_array[0];
					}
					if ($uid != null && strpos ($uid, "@") !== false) {
						$data = array();
						$data['username'] = $uid;
						$data['role'] = 'person';
						$data['displayname'] = "";
						$personConsoleNamespace = new Zend_Session_Namespace('person_console');
						$personConsoleNamespace->cur_user_mailbox = $uid;

						$auth_array = CommonUtil::judgeUserPrivilege(strtolower($uid));

						if ($auth_array['login'] === false) {
							$module = $this->_noauth['module'];
							$controller = $this->_noauth['controller'];
							$action = $this->_noauth['action'];
							$request->setModuleName($module);
							$request->setControllerName($controller);
							$request->setActionName($action);
							return;
						}

						$personConsoleNamespace->utype = $auth_array['utype'];
						$personConsoleNamespace->worktime = $auth_array['worktime'];
						$personConsoleNamespace->worktime_end = $auth_array['worktime_end'];

						$userDn = trim(SolrUtil::getDnFromUserMapsByUbox($uid), '"');
						$personConsoleNamespace->is_self_dn = $userDn;
		
						$use_multiple_domain = Zend_Registry::get ( 'use_multiple_domain' );
						if ($use_multiple_domain == 1) {
							$multipleMails = Zend_Registry::get ( 'multipleMails' );
							$personConsoleNamespace->multipleMails = $multipleMails;
						} else {
							$multipleMails = array();
							$personConsoleNamespace->multipleMails = array();
						}

						$is_self_array = CommonUtil::getUnPrincipalName(strtolower($userDn));
						if ($use_multiple_domain == 1) {
							$is_self_array = array_merge($is_self_array, $multipleMails);
						}
						$personConsoleNamespace->is_self_array = $is_self_array;

						$get_auth = true;
						$personConsoleNamespace->login_user = $data;
						if (isset ( $personConsoleNamespace->mytasks )) {
							unset($personConsoleNamespace->mytasks);
						}
					}
				}
				if (!$get_auth) {
					$headers = getallheaders();
					if(isset($headers['X-Requested-With']) && $headers['X-Requested-With'] == 'XMLHttpRequest'){
						$module = $this->_ajaxnoauth['module'];
						$controller = $this->_ajaxnoauth['controller'];
						$action = $this->_ajaxnoauth['action'];
					}else{
						$module = $this->_noauth['module'];
						$controller = $this->_noauth['controller'];
						$action = $this->_noauth['action'];
					}
				}
			}else{
				$module = $this->_nopriv['module'];
				$controller = $this->_nopriv['controller'];
				$action = $this->_nopriv['action'];
			}
		}
		
		$request->setModuleName($module);
		$request->setControllerName($controller);
		$request->setActionName($action);
	}
    
}
