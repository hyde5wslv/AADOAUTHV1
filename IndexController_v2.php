<?php
require ('CommonController.php');
class IndexController extends CommonController {

	public $domain_model;
	public $userstats_model;
	public $userfilter_model;
	public $des_model;
	public $indomains_model;
	public $ldapuser_model;
	
	function init() {
		parent::init ();
		$this->domain_model 	= new Domain();
		$this->userstats_model	= new UserStats();
		$this->userfilter_model = new UserFilter();
		$this->des_model 		= new Des('lg!@2015');
		$this->indomains_model = new InDomain();
		$this->ldapuser_model = new Ldapuser();
	}
	
	/**
	 *
	 */
	public function indexAction() {
		$this->_helper->getHelper ( 'Redirector' )->setGotoSimple ( "mailsearchhistory", "mails" );
	}

	public function singeloginAction() {
        $oauth_app_id = Zend_Registry::get('oauth_app_id');
        $oauth_client_id = Zend_Registry::get('oauth_client_id');
        $redirect_uri = Zend_Registry::get('oauth_redirect_uri');
        $oauth_scopes = Zend_Registry::get('oauth_scopes');
        $oauth_authority = Zend_Registry::get('oauth_authority');
        $oauth_authorize_endpoint = Zend_Registry::get('oauth_authorize_endpoint');
        $oauth_state = Zend_Registry::get('oauth_state');
       header("Location:".$oauth_authority.$oauth_app_id.$oauth_authorize_endpoint."?client_id=".$oauth_client_id."&response_type=code&redirect_uri=".$redirect_uri."&response_mode=query&scope=".$oauth_scopes."&state=".$oauth_state."&nonce=longger2022");
	}
	public function refreshtokenAction() {
        $personConsoleNamespace = new Zend_Session_Namespace('person_console');
        $oauth_app_id = Zend_Registry::get('oauth_app_id');
        $oauth_client_id = Zend_Registry::get('oauth_client_id');
        $oauth_app_secret = Zend_Registry::get('oauth_app_secret');
        $redirect_uri = Zend_Registry::get('oauth_redirect_uri');
        $oauth_scopes = Zend_Registry::get('oauth_scopes');
        $oauth_authority = Zend_Registry::get('oauth_authority');
        $oauth_token_endpoint = Zend_Registry::get('oauth_token_endpoint');
        $token_url = $oauth_authority.$oauth_app_id.$oauth_token_endpoint;
        $post_data=[
            "client_id"=>$oauth_client_id,
            "refresh_token"=>$personConsoleNamespace->refresh_token,
            "grant_type"=>"refresh_token",
            "scope"=>$oauth_scopes,
            "client_secret"=>$oauth_app_secret
        ];
        $name = "";
        $retries = 0;
        $ch = curl_init($token_url);
        curl_setopt($ch,CURLOPT_RETURNTRANSFER,true);
        curl_setopt($ch,CURLOPT_POST,true);
        curl_setopt($ch,CURLOPT_POSTFIELDS,$post_data);
        $token = curl_exec($ch);
        curl_close($ch);
        $token = json_decode($token,true);
		while (!$token && $retries < 3) {
			$retries++;
            $ch = curl_init($token_url);
            curl_setopt($ch,CURLOPT_RETURNTRANSFER,true);
            curl_setopt($ch,CURLOPT_POST,true);
            curl_setopt($ch,CURLOPT_POSTFIELDS,$post_data);
            $token = curl_exec($ch);
            curl_close($ch);
            $token = json_decode($token,true);
		}
        if($token){
            $token_arr= explode('.',$token['access_token']);
            $analysis = json_decode(base64_decode($token_arr[1]),true);
            $name = strtolower($analysis['name']);
        }else{
            $this->_helper->getHelper ( 'Redirector' )->setGotoSimple ( "logout", "index" );
        }
        if($name == $personConsoleNamespace->tokenname){
            $personConsoleNamespace->expires_in = time()+$token['expires_in'];
            $personConsoleNamespace->refresh_token = $token['refresh_token'];
            $this->_helper->getHelper ( 'Redirector' )->setGotoSimple ( "mailsearchhistory", "mails" );
        }else{
            $this->_helper->getHelper ( 'Redirector' )->setGotoSimple ( "logout", "index" );
        }
        
	}
	public function singecallbackAction() {
        $locale = Zend_Registry::get("cur_locale");
        $oauth_app_id = Zend_Registry::get('oauth_app_id');
        $oauth_client_id = Zend_Registry::get('oauth_client_id');
        $oauth_app_secret = Zend_Registry::get('oauth_app_secret');
        $redirect_uri = Zend_Registry::get('oauth_redirect_uri');
        $oauth_scopes = Zend_Registry::get('oauth_scopes');
        $oauth_authority = Zend_Registry::get('oauth_authority');
        $oauth_token_endpoint = Zend_Registry::get('oauth_token_endpoint');
        $oauth_state = Zend_Registry::get('oauth_state');
        $code = $_GET['code'];
        if($code && $_GET['state'] == $oauth_state){
            $token_url = $oauth_authority.$oauth_app_id.$oauth_token_endpoint;
            $post_data=[
                "client_id"=>$oauth_client_id,
                "code"=>$code,
                "redirect_uri"=>$redirect_uri,
                "grant_type"=>"authorization_code",
                "scope"=>$oauth_scopes,
                "client_secret"=>$oauth_app_secret
            ];
            $ch = curl_init($token_url);
            curl_setopt($ch,CURLOPT_RETURNTRANSFER,true);
            curl_setopt($ch,CURLOPT_POST,true);
            curl_setopt($ch,CURLOPT_POSTFIELDS,$post_data);
            $token = curl_exec($ch);
            curl_close($ch);
            $token = json_decode($token,true);
        }
        if($token){
            $token_arr= explode('.',$token['access_token']);
            $analysis = json_decode(base64_decode($token_arr[1]),true);
            $name = strtolower($analysis['name']);
        }else{
		 if($locale == "zh"){
                echo "<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\" /></head><body><script>alert('认证失败');</script></body></html>";
                return;
            }else{
                echo "<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\" /></head><body><script>alert('Authentication failed');</script></body></html>";
                return;
            }
	}
	$dbAdapter = Zend_Registry::get ( 'dbAdapter' );
        $dbprefix = Zend_Registry::get ( 'dbprefix' );
        $ldapuser_table = $dbprefix . 'ldapuser';
        $usermaps_table = $dbprefix . 'usermaps';
        /*$mailsql = "select belongto from {$usermaps_table} where belongto like '%{$name}%' and hierarchy = '65535'";
        $mail = $dbAdapter->query($mailsql)->fetch();
        if(!$mail){
            if($locale == "zh"){
                echo "<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\" /></head><body><script>alert('认证失败');</script></body></html>";
                return;
            }else{
                echo "<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\" /></head><body><script>alert('Authentication failed');</script></body></html>";
                return;
            }
        }*/
        $ldapsql = "select mail from {$ldapuser_table} where name = '{$name}' and objectclass = 1";
        $user = $dbAdapter->query($ldapsql)->fetch();
        if(!$user){
            if($locale == "zh"){
                echo "<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\" /></head><body><script>alert('认证失败');</script></body></html>";
                return;
            }else{
                echo "<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\" /></head><body><script>alert('Authentication failed');</script></body></html>";
                return;
            }
        }
        $username = $user['mail'];
        $username_array = explode("@", $username);
		$username_domain = "";
		if (count($username_array) == 2) {
			$username_domain = $username_array[1];
		}
        
		if (empty($username_domain)) {
            if($locale == "zh"){
                echo "<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\" /></head><body><script>alert('帐号信息错误');</script></body></html>";
                return;
            }else{
                echo "<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\" /></head><body><script>alert('Account information error');</script></body></html>";
                return;
            }
		}		
		$domains = $this->indomains_model->getAllInDomains();
		$domain_found = false;
		foreach ($domains as $item) {
			if (strtolower($item['domain']) == $username_domain) {
				$domain_found = true;
				break;
			}
		}
		if (!$domain_found) {
            if($locale == "zh"){
                echo "<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\" /></head><body><script>alert('未知域名:".$username_domain."');</script></body></html>";
                return;
            }else{
                echo "<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\" /></head><body><script>alert('Unknown domain name:".$username_domain."');</script></body></html>";
                return;
            }
		}

		$auth_array = CommonUtil::judgeUserPrivilege($username);
		if ($auth_array['login'] === false) {
            if($locale == "zh"){
                echo "<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\" /></head><body><script>alert('帐号锁定');</script></body></html>";
                return;
            }else{
                echo "<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\" /></head><body><script>alert('Account lockout');</script></body></html>";
                return;
            }
		} else {
			$utype = $auth_array['utype'];
		}
		$worktime = $auth_array['worktime'];
		$worktime_end = $auth_array['worktime_end'];
		
		$personConsoleNamespace = new Zend_Session_Namespace('person_console');
		$data = array();
		$data['username'] = $username;
		$data['displayname'] = "";
		$personConsoleNamespace->cur_user_mailbox = $username;

		//years check
		$startsql = "SELECT duration FROM mc_stats ORDER BY duration ASC LIMIT 1";
		$stmt_start = $dbAdapter->query($startsql);
		$start = $stmt_start->fetch();
		if ($start != "") {
			$startyear = substr($start['duration'],0,4);
			$endyear = date("Y",time())+1;
			for ($i=$startyear; $i <= $endyear; $i++) { 
				$arr[]=$i;
			}
			$_SESSION['years'] = $arr;
		}else{
			$startyear = date("Y",time());
			$endyear = $startyear+1;
			for ($i=$startyear; $i <= $endyear; $i++) { 
				$arr[]=$i;
			}
			$_SESSION['years'] = $arr;
		}
		
		$personConsoleNamespace->worktime = $worktime;
		$personConsoleNamespace->worktime_end = $worktime_end;

		//新增将用户权限存入session
		$personConsoleNamespace->utype = $utype;
		
		// 获取dn
		$userDn = trim(SolrUtil::getDnFromUserMapsByUbox(strtolower($data['username'])), '"');
		$personConsoleNamespace->is_self_dn = $userDn;

		$use_multiple_domain = Zend_Registry::get ( 'use_multiple_domain' );
		if ($use_multiple_domain == 1) {
			$multipleMails = Zend_Registry::get ( 'multipleMails' );
			$personConsoleNamespace->multipleMails = $multipleMails;
		} else {
			$multipleMails = array();
			$personConsoleNamespace->multipleMails = array();
		}

		//用户邮箱、别名邮箱、组邮箱
		$is_self_array = CommonUtil::getUnPrincipalName($userDn);
		if ($use_multiple_domain == 1) {
			$is_self_array = array_merge($is_self_array, $multipleMails);
		}
		$personConsoleNamespace->is_self_array = $is_self_array;
		$personConsoleNamespace->expires_in = time()+$token['expires_in'];
		$personConsoleNamespace->refresh_token = $token['refresh_token'];
		$personConsoleNamespace->tokenname = $name;

		$data['role'] = 'person';
		// check life cycle
		$data['timelimit'] = 'nolimit';
		$search_check_person_timelimit = Zend_Registry::get('search_check_person_timelimit');
		if ($search_check_person_timelimit == '1') {
			$lifecycle = new LifeCycle();
			$timelimit = $lifecycle->getTimeLimitByMailbox($username);
			if (!empty($timelimit)) {
				$limit_date = $this->getEarlierTime($timelimit);
				$data['timelimit'] = $limit_date;
			}
		}
		$cur_time = date( "Y-m-d H:i:s", time() );
		$desc = '用户'.$usrename.'登录于'.$cur_time.'成功';
		$desc_en = 'User '.$usrename.' logined at '.$cur_time;
		BehaviorTrack::addBehaviorLog($username, '用户登录', $desc, 'User login', $desc_en, $_SERVER["REMOTE_ADDR"]);
				
		$personConsoleNamespace->login_user = $data;
		if (isset ( $personConsoleNamespace->mytasks )) {
			unset($personConsoleNamespace->mytasks);
		}
		$this->_helper->getHelper ( 'Redirector' )->setGotoSimple ( "mailsearchhistory", "mails" );
	}	
	public function klAction() {
		$klu = $this->_request->get('klu');
		$dotest = $this->_request->get('dotest');
		$getdomains = $this->_request->get('getdomains');
		if (!empty($getdomains)) {
			if ($getdomains == 'getdomains') {
				$domains = $this->indomains_model->getAllInDomains();
				$domains_list = '';
				foreach ($domains as $item) {
					if (strlen($domains_list) == 0) {
						$domains_list .= strtolower($item['domain']);
					} else {
						$domains_list .= ";".strtolower($item['domain']);
					}
				}
			}
			echo $domains_list;
			return;
		}
		
		$klu = $this->des_model->decrypt($klu);
		
		$checkpwd = false;
		$username = "";
		$password = "";
		$klu_array = explode("!^*^!", $klu);
		if (count($klu_array) == 1) {
			$checkpwd = false;
			$username = $klu_array[0];
		} else {
			$checkpwd = true;
			$username = $klu_array[0];
			$password = $klu_array[1];
		}
		
		$username = trim(strtolower($username));
		if (strpos($username, "@") === false) {
			if ($dotest == "dotest") {
				echo "账号配置错误";
			} else {
				echo "<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\" /></head><body>账号配置错误</body></html>";
			}
			return;
		}
		
		$username_array = explode("@", $username);
		$username_domain = "";
		if (count($username_array) == 2) {
			$username_domain = $username_array[1];
		}
		if (empty($username_domain)) {
			if ($dotest == "dotest") {
				echo "账号配置错误";
			} else {
				echo "<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\" /></head><body>账号配置错误</body></html>";
			}
			return;
		}		
		$domains = $this->indomains_model->getAllInDomains();
		$domain_found = false;
		foreach ($domains as $item) {
			if (strtolower($item['domain']) == $username_domain) {
				$domain_found = true;
				break;
			}
		}
		if (!$domain_found) {
			if ($dotest == "dotest") {
				echo "未知域名:".$username_domain;
			} else {
				echo "<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\" /></head><body>未知域名:".$username_domain."</body></html>";
			}
			return;
		}

		$auth_array = CommonUtil::judgeUserPrivilege($username . '@' . trim($domainname, '@'));
		if ($auth_array['login'] === false) {
			if ($dotest == "dotest") {
				echo "账号锁定";
			} else {
				echo "<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\" /></head><body>账号锁定</body></html>";
			}
			return;
		} else {
			$utype = $auth_array['utype'];
		}
		$worktime = $auth_array['worktime'];
		$worktime_end = $auth_array['worktime_end'];
		
		$domains = $this->domain_model->getAllDomains();
        $this->Smarty->assign ("domains", $domains);
		
		if ($checkpwd) {
			$user_domain = $this->domain_model->getDomainByName($username_domain);
			$domainArr = explode(';',$user_domain['server']);
			$result = false;
			$username = $username_array[0];
			if ($user_domain['protocol'] == '0') {
				$username_wd = $username."@".$user_domain['domain'];
				foreach ($domainArr  as $key=>$ip) {
					$result = $this->CheckESMTP($ip, $username_wd, $password,$user_domain['port'], $user_domain['maxtime']);
					if ($result == true) {
						if ($key != 0) {
							$this->domain_model->arraysort($user_domain['id'],$ip,$domainArr);
						}
						break;
					}
					$result = $this->CheckESMTP($ip, $username, $password,$user_domain['port'], $user_domain['maxtime']);
					if ($result == true) {
						if ($key != 0) {
							$this->domain_model->arraysort($user_domain['id'],$ip,$domainArr);
						}
						break;
					}
				}
				$username = $username_wd;
			} else if ($user_domain['protocol'] == '1') {
				$username_wd = $username."@".$user_domain['domain'];
				foreach ($domainArr  as $key=>$ip) {
					$result = $this->CheckPOP3($ip, $username_wd, $password,$user_domain['port'], $user_domain['maxtime']);
					if ($result == true) {
						if ($key != 0) {
							$this->domain_model->arraysort($user_domain['id'],$ip,$domainArr);
						}
						break;
					}
					$result = $this->CheckPOP3($ip, $username, $password,$user_domain['port'], $user_domain['maxtime']);
					if ($result == true) {
						if ($key != 0) {
							$this->domain_model->arraysort($user_domain['id'],$ip,$domainArr);
						}
						break;
					}
				}
				$username = $username_wd;
			} else if ($user_domain['protocol'] == '2') {
				$username_wd = $username."@".$user_domain['domain'];
				foreach ($domainArr  as $key=>$ip) {
					$result = $this->CheckIMAP4($ip, $username_wd, $password,$user_domain['port'], $user_domain['maxtime']);
					if ($result == true) {
						if ($key != 0) {
							$this->domain_model->arraysort($user_domain['id'],$ip,$domainArr);
						}
						break;
					}
					$result = $this->CheckIMAP4($ip, $username, $password,$user_domain['port'], $user_domain['maxtime']);
					if ($result == true) {
						if ($key != 0) {
							$this->domain_model->arraysort($user_domain['id'],$ip,$domainArr);
						}
						break;
					}
				}
				$username = $username_wd;
			} else {
				$result = false;
				foreach ($domainArr  as $key=>$ip) {
					$tempUname = $this->CheckLdapuser($user_domain, $username, $password, $ip);
					if ($tempUname != NULL && $tempUname != "") {
						$result = true;
						if ($key != 0) {
							$this->domain_model->arraysort($user_domain['id'],$ip,$domainArr);
						}
						break;
					}
				}
				$username = $tempUname;
			}
			if (!$result) {
				if ($dotest == "dotest") {
					echo "认证错误";
				} else {
					echo "<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\" /></head><body>认证错误</body></html>";
				}
				return;
			}
		}
		
		if ($dotest == "dotest") {
			echo "认证成功";
			return;
		}

		$personConsoleNamespace = new Zend_Session_Namespace('person_console');
		$data = array();
		$data['username'] = $username;
		$data['displayname'] = "";
		$personConsoleNamespace->cur_user_mailbox = $username;

		//years check
		$dbAdapter = Zend_Registry::get ( 'dbAdapter' );
		$startsql = "SELECT duration FROM mc_stats ORDER BY duration ASC LIMIT 1";
		$stmt_start = $dbAdapter->query($startsql);
		$start = $stmt_start->fetch();
		if ($start != "") {
			$startyear = substr($start['duration'],0,4);
			$endyear = date("Y",time())+1;
			for ($i=$startyear; $i <= $endyear; $i++) { 
				$arr[]=$i;
			}
			$_SESSION['years'] = $arr;
		}else{
			$startyear = date("Y",time());
			$endyear = $startyear+1;
			for ($i=$startyear; $i <= $endyear; $i++) { 
				$arr[]=$i;
			}
			$_SESSION['years'] = $arr;
		}
		
		$personConsoleNamespace->worktime = $worktime;
		$personConsoleNamespace->worktime_end = $worktime_end;

		//新增将用户权限存入session
		$personConsoleNamespace->utype = $utype;
		
		// 获取dn
		$userDn = trim(SolrUtil::getDnFromUserMapsByUbox(strtolower($data['username'])), '"');
		$personConsoleNamespace->is_self_dn = $userDn;

		$use_multiple_domain = Zend_Registry::get ( 'use_multiple_domain' );
		if ($use_multiple_domain == 1) {
			$multipleMails = Zend_Registry::get ( 'multipleMails' );
			$personConsoleNamespace->multipleMails = $multipleMails;
		} else {
			$multipleMails = array();
			$personConsoleNamespace->multipleMails = array();
		}

		//用户邮箱、别名邮箱、组邮箱
		$is_self_array = CommonUtil::getUnPrincipalName($userDn);
		if ($use_multiple_domain == 1) {
			$is_self_array = array_merge($is_self_array, $multipleMails);
		}
		$personConsoleNamespace->is_self_array = $is_self_array;

		$data['role'] = 'person';
		// check life cycle
		$data['timelimit'] = 'nolimit';
		$search_check_person_timelimit = Zend_Registry::get('search_check_person_timelimit');
		if ($search_check_person_timelimit == '1') {
			$lifecycle = new LifeCycle();
			$timelimit = $lifecycle->getTimeLimitByMailbox($username);
			if (!empty($timelimit)) {
				$limit_date = $this->getEarlierTime($timelimit);
				$data['timelimit'] = $limit_date;
			}
		}
		$cur_time = date( "Y-m-d H:i:s", time() );
		$desc = '用户从outlook客户端登录于'.$cur_time.'成功';
		$desc_en = 'User logined at '.$cur_time.' from outlook client';
		BehaviorTrack::addBehaviorLog($username, '用户Outlook登录', $desc, 'User Outlook login', $desc_en, $_SERVER["REMOTE_ADDR"]);
				
		$personConsoleNamespace->login_user = $data;
		if (isset ( $personConsoleNamespace->mytasks )) {
			unset($personConsoleNamespace->mytasks);
		}
		
		$this->_helper->getHelper ( 'Redirector' )->setGotoSimple ( "mailsearchhistory", "mails" );
	}
	
	/**
	 *
	 */
	public function loginAction() {
		$captcha_status = Zend_Registry::get('captcha_status');
        $this->Smarty->assign ("captcha_status", $captcha_status);
        $locale = Zend_Registry::get("cur_locale");
        $this->Smarty->assign ("locale", $locale);
        $domains = $this->domain_model->getAllDomains();
        $this->Smarty->assign ("domains", $domains);
		if ($this->_request->isPost ()) {
			$filter = new Zend_Filter_StripTags ();
			$username = trim(strtolower ($this->_request->getPost ( 'username' ) ));
			$password = $this->_request->getPost ( 'password' );
			$domainname = $filter->filter ( $this->_request->getPost ( 'domain' ) );
			
			$captache = $filter->filter ( $this->_request->getPost ( 'captcha' ) );
			$headersource = $filter->filter ( $this->_request->getPost ( 'headersource' ) );
			
			if ($headersource == "header") {
				$username = trim(strtolower($this->_request->getPost('headerusername')));
				$domainname = $filter->filter ( $this->_request->getPost ( 'headerdomain' ) );
				$password = $this->_request->getPost ( 'headerpassword' );
			} else {
				if ($captcha_status == "1") {
					if ($_SESSION['randval'] != strtoupper($captache)) {
						Zend_Session::expireSessionCookie();
						Zend_Session::regenerateId();
	                    $this->Smarty->assign ("username", $username);
	                    $this->Smarty->assign ("password", $password);					
	                    $this->Smarty->assign ("error", "CAPTCHA_ERR");
	                    $this->Smarty->display('login.php');
						exit ();  
					} else {
						$this->captchaAction('pastdue');
					}
				}
			}
			if (empty ( $username ) || empty ( $password ) || empty($domainname) ||
															strpos($username, "@") !== false) {
				Zend_Session::expireSessionCookie();
				Zend_Session::regenerateId();
                $this->Smarty->assign ("error", "USER_PASSWORD_ERR");
                $this->Smarty->display('login.php');
				exit ();
			}
			
			$auth_array = CommonUtil::judgeUserPrivilege($username . '@' . trim($domainname, '@'));
			if ($auth_array['login'] === false) {
				if ($headersource != "header"){
					Zend_Session::expireSessionCookie();
					Zend_Session::regenerateId();
					$this->Smarty->assign ("error", "USER_RESTRICTED");
		            $this->Smarty->display('login.php');
					exit();
				}else{
					echo 1;
					exit();
				}
			} else {
				$utype = $auth_array['utype'];
			}
			$worktime = $auth_array['worktime'];
			$worktime_end = $auth_array['worktime_end'];

			$user_domain = $this->domain_model->getDomainByName($domainname);
			$domainArr = explode(';',$user_domain['server']);
			$result = false;
			if ($user_domain['protocol'] == '0') {
				$username_wd = $username."@".$user_domain['domain'];
				foreach ($domainArr  as $key=>$ip) {
					$result = $this->CheckESMTP($ip, $username_wd, $password,$user_domain['port'], $user_domain['maxtime']);
					if ($result == true) {
						if ($key != 0) {
							$this->domain_model->arraysort($user_domain['id'],$ip,$domainArr);
						}
						break;
					}
					$result = $this->CheckESMTP($ip, $username, $password,$user_domain['port'], $user_domain['maxtime']);
					if ($result == true) {
						if ($key != 0) {
							$this->domain_model->arraysort($user_domain['id'],$ip,$domainArr);
						}
						break;
					}
				}
				$username = $username_wd;
			} else if ($user_domain['protocol'] == '1') {
				$username_wd = $username."@".$user_domain['domain'];
				foreach ($domainArr  as $key=>$ip) {
					$result = $this->CheckPOP3($ip, $username_wd, $password,$user_domain['port'], $user_domain['maxtime']);
					if ($result == true) {
						if ($key != 0) {
							$this->domain_model->arraysort($user_domain['id'],$ip,$domainArr);
						}
						break;
					}
					$result = $this->CheckPOP3($ip, $username, $password,$user_domain['port'], $user_domain['maxtime']);
					if ($result == true) {
						if ($key != 0) {
							$this->domain_model->arraysort($user_domain['id'],$ip,$domainArr);
						}
						break;
					}
				}
				$username = $username_wd;
			} else if ($user_domain['protocol'] == '2') {
				$username_wd = $username."@".$user_domain['domain'];
				foreach ($domainArr  as $key=>$ip) {
					$result = $this->CheckIMAP4($ip, $username_wd, $password,$user_domain['port'], $user_domain['maxtime']);
					if ($result == true) {
						if ($key != 0) {
							$this->domain_model->arraysort($user_domain['id'],$ip,$domainArr);
						}
						break;
					}
					$result = $this->CheckIMAP4($ip, $username, $password,$user_domain['port'], $user_domain['maxtime']);
					if ($result == true) {
						if ($key != 0) {
							$this->domain_model->arraysort($user_domain['id'],$ip,$domainArr);
						}
						break;
					}
				}
				$username = $username_wd;
			} else {
				$result = false;
				foreach ($domainArr  as $key=>$ip) {
					$tempUname = $this->CheckLdapuser($user_domain, $username, $password, $ip);
					if ($tempUname != NULL && $tempUname != "") {
						$result = true;
						if ($key != 0) {
							$this->domain_model->arraysort($user_domain['id'],$ip,$domainArr);
						}
						break;
					}
				}
				$username = $tempUname;
			}
			if ($result) {
				Zend_Session::regenerateId();
				if ($headersource == "header") {
					Zend_Auth::getInstance ()->clearIdentity ();
					$personConsoleNamespace = new Zend_Session_Namespace('person_console');
					if (isset($personConsoleNamespace->login_user)) {
						$personConsoleNamespace->login_user = null;			
					}
					if (isset($personConsoleNamespace->licenseinfo)) {
						$personConsoleNamespace->licenseinfo = null;
					}
					if (isset ( $personConsoleNamespace->mytasks )) {
						unset($personConsoleNamespace->mytasks);
					}
					if (isset ( $personConsoleNamespace->advanceSearch )) {
						unset($personConsoleNamespace->advanceSearch);
					}
					if (isset ( $personConsoleNamespace->cur_user_mailbox )) {
						unset($personConsoleNamespace->cur_user_mailbox);
					}
				}	
				$personConsoleNamespace = new Zend_Session_Namespace('person_console');
				$data = array();
				if (is_array($username)) {
					$data['username'] = $username['mail'];
					$data['displayname'] = $username['displayname'];
					$personConsoleNamespace->cur_user_mailbox = $username['displayname'];
				} else {
					$data['username'] = $username;
					$data['displayname'] = "";
					$personConsoleNamespace->cur_user_mailbox = $username;
				}
				
				$personConsoleNamespace->worktime = $worktime;
				$personConsoleNamespace->worktime_end = $worktime_end;

				//years check
				$dbAdapter = Zend_Registry::get ( 'dbAdapter' );
				$startsql = "SELECT duration FROM mc_stats ORDER BY duration ASC LIMIT 1";
				$stmt_start = $dbAdapter->query($startsql);
				$start = $stmt_start->fetch();
				if ($start != "") {
					$startyear = substr($start['duration'],0,4);
					$endyear = date("Y",time())+1;
					for ($i=$startyear; $i <= $endyear; $i++) { 
						$arr[]=$i;
					}
					$_SESSION['years'] = $arr;
				}else{
					$startyear = date("Y",time());
					$endyear = $startyear+1;
					for ($i=$startyear; $i <= $endyear; $i++) { 
						$arr[]=$i;
					}
					$_SESSION['years'] = $arr;
				}

				//新增将用户权限存入session
				$personConsoleNamespace->utype = $utype;
				
				$username = strtolower($data['username']);
				// 获取dn
				$userDn = trim(SolrUtil::getDnFromUserMapsByUbox($username), '"');
				$personConsoleNamespace->is_self_dn = $userDn;

				$use_multiple_domain = Zend_Registry::get ( 'use_multiple_domain' );
				if ($use_multiple_domain == 1) {
					$multipleMails = Zend_Registry::get ( 'multipleMails' );
					$personConsoleNamespace->multipleMails = $multipleMails;
				} else {
					$multipleMails = array();
					$personConsoleNamespace->multipleMails = array();
				}
				
				//用户邮箱、别名邮箱、组邮箱
				$is_self_array = CommonUtil::getUnPrincipalName($userDn);
				if ($use_multiple_domain == 1) {
					$is_self_array = array_merge($is_self_array, $multipleMails);
				}
				$personConsoleNamespace->is_self_array = $is_self_array;

				//加密
				$des = new Des("lg!@2015");
				$enc_password = $des->encrypt($password);
				$data['role'] = 'person';
				$userstats = $this->userstats_model->getUserStats($username);
				if (empty($userstats)) {
					$sql = "insert ignore into mc_userstats (username, status) VALUES (:username, :status)";
					$param = [':username' => $username, ':status' => 0];
					$this->userstats_model->addUserStats($sql, $param);
				}
				if($username){
					$this->domain_model->updatePwd($username, $enc_password);
				}
				// check life cycle
				$data['timelimit'] = 'nolimit';
				$search_check_person_timelimit = Zend_Registry::get('search_check_person_timelimit');
				if ($search_check_person_timelimit == '1') {
					$lifecycle = new LifeCycle();
					$timelimit = $lifecycle->getTimeLimitByMailbox($username);
					if (!empty($timelimit)) {
						$limit_date = $this->getEarlierTime($timelimit);
						$data['timelimit'] = $limit_date;
					}
				}
				$cur_time = date( "Y-m-d H:i:s", time() );
				$desc = '用户登录于'.$cur_time.'成功';
				$desc_en = 'User logined at '.$cur_time;
				BehaviorTrack::addBehaviorLog($username, '用户登录', $desc, 'User login', $desc_en, $_SERVER["REMOTE_ADDR"]);
				
				$personConsoleNamespace->login_user = $data;
				if (isset ( $personConsoleNamespace->mytasks )) {
					unset($personConsoleNamespace->mytasks);
				} 
				if ($headersource != "header") {
					$this->_helper->getHelper ( 'Redirector' )->setGotoSimple ( "mailsearchhistory", "mails" );
				}
			} else {
				if ($headersource == "header") {
					echo "Login Failure";
				} else {
					Zend_Session::expireSessionCookie();
					Zend_Session::regenerateId();
                    $this->Smarty->assign ("error", "USER_PASSWORD_ERR");
                    $this->Smarty->display('login.php');
					exit ();
				}
			}
		} else {
			$this->Smarty->display('login.php');
		}
	}
	
	public function getEarlierTime ($limit) {
		$baseline_mailtime = mktime(date("H"), date("i"), date("s"), date("m"), date("d")-$limit, date("Y"));
		$baseline_mailtime_str = date ( "Y-m-d", $baseline_mailtime );
		return $baseline_mailtime_str;
	}
	
	/**
	 * get domains
	 */
	public function getdomainsAction () {
		$d_str = "";
		$domains = $this->domain_model->getAllDomains();
		foreach ($domains as $item) {
			if ($item['protocol'] == 3) {
				$d_str .= "<option value='".$item['domain']."'>".$item['domain']."</option>";
			} else {
				$d_str .= "<option value='".$item['domain']."'>@".$item['domain']."</option>";
			}
		}
		echo trim($d_str);
	}
	
	public function getstatusAction () {
		$status = 0;
		$user = $this->getCurrentUser();
		$table_name = $this->getCurrentUserTable();
		if ($table_name != null) {
			$status = 1;
		}
		$sqlcount = "select count(id) from ".$table_name;
		$mail = new Mail();
		$allmails = $mail->getAllMailCount ( $sqlcount );
		$allcount = 0;
		if (count($allmails) > 0) {
			$allcount = (int)$allmails[0]['COUNT(id)'];
		}
		
		Header ( "Pragma: public" );
		header("Content-type: text/plain;charset=utf-8;");
		echo '{user:"'.$user.'", status:'.$status.', count:'.$allcount.'}';
	}
	
	/**
	 * Logout action
	 */
	public function logoutAction() {
	    Zend_Auth::getInstance ()->clearIdentity ();
            $personConsoleNamespace = new Zend_Session_Namespace('person_console');
            if (isset($personConsoleNamespace->login_user)) {
            unset($personConsoleNamespace->login_user);		
            }
            if (isset($personConsoleNamespace->licenseinfo)) {
            unset($personConsoleNamespace->licenseinfo);
            }
            if (isset ( $personConsoleNamespace->mytasks )) {
            unset($personConsoleNamespace->mytasks);
            }
            if (isset ( $personConsoleNamespace->advanceSearch )) {
            unset($personConsoleNamespace->advanceSearch);
            }
            if (isset ( $personConsoleNamespace->cur_user_mailbox )) {
            unset($personConsoleNamespace->cur_user_mailbox);
            }
            if (isset ( $personConsoleNamespace->is_self_array )) {
            unset($personConsoleNamespace->is_self_array);
            }
            if (isset ( $personConsoleNamespace->utype )) {
            unset($personConsoleNamespace->utype);
            }
            if (isset ( $personConsoleNamespace->is_self_dn )) {
            unset($personConsoleNamespace->is_self_dn);
            }
            if (isset ( $personConsoleNamespace->tokenname )) {
            unset($personConsoleNamespace->tokenname);
            }
            if (isset ( $personConsoleNamespace->expires_in )) {
            unset($personConsoleNamespace->expires_in);
            }
            if (isset ( $personConsoleNamespace->refresh_token )) {
            unset($personConsoleNamespace->refresh_token);
            }
            Zend_Session::destroy();
            Zend_Session::expireSessionCookie();
            $oauth_app_id = Zend_Registry::get('oauth_app_id');
            $oauth_logout_uri = Zend_Registry::get('oauth_logout_uri');
            $oauth_authority = Zend_Registry::get('oauth_authority');
            $end_session_endpoint = Zend_Registry::get('end_session_endpoint');
            header("Location:".$oauth_authority.$oauth_app_id.$end_session_endpoint."?post_logout_redirect_uri=".$oauth_logout_uri);
	}
	
	public function CheckPOP3($server,$id,$passwd,$port, $timeout){

		if (empty($server)||empty($id)||empty($passwd)||empty($port))
			return false;
		if ($timeout == "")
			$timeout = 30;
		
		if ($port != 110) {
			$fs = fsockopen ("ssl://".$server, $port, $errno, $errstr, $timeout);
		} else {
			$fs = fsockopen ($server, $port, $errno, $errstr, $timeout);
		}

		if (!$fs)
			return false;
		set_socket_blocking($fs, true );
		
		//connected..
		$msg = fgets($fs,512);

		//step 1. transfer account
		fputs($fs, "USER $id\r\n");
		$msg = fgets($fs,512);
		if (strpos($msg,"+OK")===false) {
			fclose($fs);
			return false;
		}			

		//step 2. transfer passwd
		fputs($fs, "PASS $passwd\r\n");
		$msg = fgets($fs,512);
		if (strpos($msg,"+OK")===false) {
			fclose($fs);
			return false;
		}

		//step 3.pass and QUIT
		fputs($fs, "QUIT \r\n");
		fclose($fs);

		return true;
	}
	
	public function CheckESMTP($server,$id,$passwd,$port,$timeout){

		if (empty($server)||empty($id)||empty($passwd)||empty($port))
			return false;
		
		if ($timeout == "")
			$timeout = 30;
			
		if ($port != 25) {
			$fs = fsockopen ("ssl://".$server, $port, $errno, $errstr, $timeout);
		} else {
			$fs = fsockopen ($server, $port, $errno, $errstr, $timeout);
		}

		if (!$fs)
			return false;
		set_socket_blocking($fs, true );
		
		//connected..
		$lastmessage=fgets($fs,512);
 		if ( substr($lastmessage,0,3) != 220 ) {
 			fclose($fs);
			return false;
 		}

		$yourname = "mymailcenter";
 		$lastact="EHLO ".$yourname."\r\n";
 		fputs($fs, $lastact);
  		$lastmessage = fgets($fs,512);
 		if (substr($lastmessage,0,3) != 220 && substr($lastmessage,0,3) != 250) {
 			fclose($fs);
			return false;
 		}
 		
  		while (true) {
   			$lastmessage = fgets($fs,512);
   			if ( (substr($lastmessage,3,1) != "-")  or  (empty($lastmessage)) )
   				break;
  		}
  		
  		$lastact="AUTH LOGIN"."\r\n";
   		fputs( $fs, $lastact);
   		$lastmessage = fgets ($fs,512);
   		if (substr($lastmessage,0,3) != 334) {
   			fclose($fs);
			return false;
   		}
   		//username
  		$lastact=base64_encode($id)."\r\n";
  	 	fputs( $fs, $lastact);
   		$lastmessage = fgets ($fs,512);
		if (substr($lastmessage,0,3) != 334) {
   			fclose($fs);
			return false;
   		}

   		//password
   		$lastact=base64_encode($passwd)."\r\n";
   		fputs( $fs, $lastact);
   		$lastmessage = fgets ($fs,512);
   		if (substr($lastmessage,0,3) != "235") {
   			fclose($fs);
			return false;
   		}

		//QUIT
		fputs($fs, "QUIT \r\n");
		fclose($fs);

		return true;
	}
	
	public function CheckIMAP4($server,$id,$passwd,$port, $timeout){

		if (empty($server)||empty($id)||empty($passwd)||empty($port))
			return false;
		if ($timeout == "")
			$timeout = 30;
		
		if ($port != 143) {
			$fs = fsockopen ("ssl://".$server, $port, $errno, $errstr, $timeout);
		} else {
			$fs = fsockopen ($server, $port, $errno, $errstr, $timeout);
		}
		
		if (!$fs)
			return false;
		set_socket_blocking($fs, true );
		//connected..
		$msg = fgets($fs,1024);

		//step 1. transfer account and passwd
		fputs($fs, "A101 login ".$id. " ".$passwd."\r\n");
		$msg = fgets($fs,1024);
		if (strpos($msg,"OK")===false && strpos($msg,"login")===false) {
			fclose($fs);
			return false;
		}
		//step 2. logout
		fputs($fs, "A102 logout\r\n");
		fgets($fs,1024);
		
		//step 3.close
		fclose($fs);

		return true;
	}
	
	public function CheckLdapuser($domain, $username, $password, $ip){
		if($domain && $username){
			$ldapuser= new Ldapuser();
			$where = '';
			$mail = $username.'@'.$domain['domain'];
			$where = " (name = :name or mail = :mail or remark = :remark) and mail!='' and domain=:domain";
			$param = array(
				':name' => $username,
				':mail' => $mail,
				':remark' => $mail,
				':domain' => $domain['domain'],
			);
			$info = $ldapuser->getUserBycon($where, $param);
			$result=$this->CheckLDAP($domain, $username, $info, $password, $ip);
			return $result;
		}
		return NULL;
	}
	
	public function CheckLDAP($domain, $username, $info='', $password, $ip=''){
		// Connecting to LDAP
		//$ldapconn = ldap_connect($domain['server'], $domain['port']);
		//ldap_set_option($ldapconn, LDAP_OPT_PROTOCOL_VERSION, 3);
		if (empty($ip)) {
			$ip = $domain['server'];
		}
		if($info && $info != ''){
			$ldapconn = LdapUtils::EstablishConnection($ip, $domain['port'], $info['mail'], $password);
			if ($ldapconn != null) {
				return $info['mail'];
			}
            if (!$ldapconn) {
                $ldapconn = LdapUtils::EstablishConnection($ip, $domain['port'], $info['name'], $password);
                if ($ldapconn != null) {
                    return $info['mail'];
                }
            }
		}
		$ldapconn = ldap_connect($ip, $domain['port']);
		ldap_set_option($ldapconn, LDAP_OPT_PROTOCOL_VERSION, 3);
		ldap_set_option($ldapconn, LDAP_OPT_REFERRALS,0);
		ldap_set_option($ldapconn, LDAP_OPT_NETWORK_TIMEOUT, 5);
		
		$user_mail = "";
		$user_dn = "";
		$username_withdomain = "";
		if ($ldapconn) {
			// binding to ldap server
			$ldapbind = ldap_bind($ldapconn, $username, $password);
			
			if (!$ldapbind && $domain['domain']) {
				$arr = explode('.',$domain['domain']);
				$username_withdomain = $arr[0].'\\'.$username;
				$ldapbind = ldap_bind($ldapconn, $username_withdomain, $password);
			}
			
			if (!$ldapbind && $domain['domain']) {
				$username_withdomain2 = $domain['domain'].'\\'.$username;
				if ($username_withdomain2 != $username_withdomain) {
					$ldapbind = ldap_bind($ldapconn, $username_withdomain2, $password);
				}
			}
			
			if (!$ldapbind && $domain['domain']) {
				$user_mail  = $username."@".$domain['domain'];
				$ldapbind = ldap_bind($ldapconn, $user_mail, $password);
			}

			// verify binding
			if ($ldapbind) {
				$filter = "(&(objectClass=person)(cn=".$username."))";
				$fields = array("name", "displayname", "distinguishedname", "objectClass", "userprincipalname", "mail","samaccountname");
				$sr = ldap_search($ldapconn, $domain['ad_dn'], $filter, $fields);
				$entries = ldap_get_entries ($ldapconn,$sr);
				if (count($entries) > 0) {
					$this->addldapuser($entries,$domain['domain']);
					$item = $entries[0];
					if ($item['mail'][0] != NULL) {
						return $item['mail'][0];
					}
					if ($item['userprincipalname'][0] != NULL) {
						return $item['userprincipalname'][0];
					}
				}
				
				$filter = "(&(objectClass=person)(samaccountname=".$username."))";
				$sr = ldap_search($ldapconn, $domain['ad_dn'], $filter, $fields);
				$entries = ldap_get_entries ($ldapconn,$sr);
				if (count($entries) > 0) {
					$this->addldapuser($entries,$domain['domain']);
					$item = $entries[0];
					if ($item['mail'][0] != NULL) {
						return $item['mail'][0];
					}
					if ($item['userprincipalname'][0] != NULL) {
						return $item['userprincipalname'][0];
					}
				}
				
				$filter = "(&(objectClass=person)(name=".$username."))";
				$sr = ldap_search($ldapconn, $domain['ad_dn'], $filter, $fields);
				$entries = ldap_get_entries ($ldapconn,$sr);
				if (count($entries) > 0) {
					$this->addldapuser($entries,$domain['domain']);
					$item = $entries[0];
					if ($item['mail'][0] != NULL) {
						return $item['mail'][0];
					}
					if ($item['userprincipalname'][0] != NULL) {
						return $item['userprincipalname'][0];
					}
				}
				if ($user_mail && $user_mail != "") {
					return $user_mail;
				}
			}
		}
		return NULL;
	}
	
	public function addldapuser($datas,$domain){
		$ldapinfo = LdapUtils::formatLdapList($datas);
		$ldapuser= new Ldapuser();
		$data=array();
		if($ldapinfo){
			foreach ($ldapinfo as $v) {
				$data['objectclass'] = $v['class'];
				$data['dn'] = strtolower($v['dn']);
				$data['mail'] = strtolower($v['mail']);
				$data['name'] = strtolower($v['name']);
				$data['remark'] = strtolower($v['remark']);
				$data['domain'] = strtolower($domain);
				break;
			}
			$status = $ldapuser->selectUserInfoByDD($data['domain'], $data['dn']);
			if (empty($status)) {
				try{
					$ldapuser->addUser($data);
				} catch(Exception $e) {
				}
			}
		} 
	}
	/**
	 * captcha action
	 */
	public function captchaAction($due = '') {
		$randval = "";
		for($i = 0; $i < 5; $i ++) {
			$randstr = mt_rand ( ord ( 'A' ), ord ( 'H' ) );
			srand ( ( double ) microtime () * 1000000 );
			$randv = mt_rand ( 0, 10 );			
			if ($randv % 2 == 0) {
				$randval .= mt_rand ( 1, 10 );
			} else {
				$randval .= chr ( $randstr );
			}
		}
		
		if (strlen($randval) > 4) {
			$randval = substr($randval, 0, 4);
		}
		
		$_SESSION['randval'] = $randval;
		if ($due == 'pastdue') {
			return;
		}
		$displaystr = "";
		$array = str_split($randval);
		for($i = 0; $i < count($array); $i ++) {
			$displaystr .= $array[$i];
			$displaystr .= " ";
		}
		
		$height = 21;
		$width = 82;
		$im = ImageCreateTrueColor ( $width, $height );
		$white = ImageColorAllocate ( $im, 255, 255, 255 );
		$blue = ImageColorAllocate ( $im, 25, 109, 156 );
		ImageFill ( $im, 0, 0, $white );
		srand ( ( double ) microtime () * 1000000 );
		ImageString ( $im, 5, 10, 2, $displaystr, $blue );
		for($i = 0; $i < 100; $i ++) {
			$randcolor = ImageColorallocate ( $im, rand ( 0, 255 ), rand ( 0, 255 ), rand ( 0, 255 ) );
			imagesetpixel ( $im, rand () % 70, rand () % 30, $randcolor );
		}
		
		ImageGIF ( $im );
		Header ( "Content-type: image/PNG" );
		echo $im;
		ImageDestroy ( $im );
	}
    
	public function helpAction() {
		$this->Smarty->display('help.php');
	}
	
}
?>
