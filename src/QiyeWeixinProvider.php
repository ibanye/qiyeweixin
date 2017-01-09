<?php

namespace YitianProviders\Weixin;

use App\WeixinUser;
use Illuminate\Support\Facades\Cookie;
use Jenssegers\Agent\Facades\Agent;
use Laravel\Socialite\Two\ProviderInterface;
use SocialiteProviders\Manager\Contracts\ConfigInterface;
use SocialiteProviders\Manager\OAuth2\AbstractProvider;
use Symfony\Component\HttpFoundation\RedirectResponse;
use GuzzleHttp\ClientInterface;

class QiyeWeixin extends AbstractProvider implements ProviderInterface
{
    /**
     * Provider标识
     */
    const IDENTIFIER = 'QIYEWEIXIN';
    const USER_COOKIE_NAME = 'UCN';

    //应用的openid
    protected $openId;
    //是否为无状态请求，默认改为true，因为用cookie验证state，而不是session
    protected $stateless = true;
    //定义授权作用域，默认值改成snsapi_login
    protected $scopes = ['snsapi_login'];
    //代理授权回调的地址
    protected $proxy_url = '';
    //PC端还是移动端
    protected $device = '';
    //授权地址
    protected $auth_url = '';
    //授权state的cookie名称
    protected $state_cookie_name = 'wx_state_cookie';
    //授权state的cookie有效时长
    protected $state_cookie_time = 5 * 60;
    protected $wxUser;
    protected $callback_token = "";
    protected $encodingAesKey = "";
    protected $corpId = "";
    protected $access_token = '';
    protected $corpSecret = '';
    protected $source = 'wx';

    /**
     * @return WeixinUser
     */
    public function user()
    {
        if ($this->hasInvalidState()) {
            throw new InvalidStateException();
        }
        if (!$this->check()) {
            return $this->redirect();
        }
        $user = $this->request->cookie(self::USER_COOKIE_NAME);
        if ($user instanceof WeixinUser) {
            return $user;
        }
    }

    /**
     * 重定向并将state参数写到cookie里面去，而不是采用session
     * @return string
     */
    public function redirect()
    {
        $state = $this->getState();
        $this->redirectUrl = url('/wx/login/callback');
        //根据访问浏览器类型设置跳转地址
        if (strpos(Agent::getUserAgent(), 'MicroMessenger') === false) {
            return redirect()->guest('redirect?url=' . urlencode($this->getAuthUrl($state)));
        } else {
            $response = new RedirectResponse($this->getAuthUrl($state), 302, [
                'Set-Cookie' => implode('', [
                    $this->state_cookie_name,
                    '=',
                    $this->getEncryptState($state),
                    "; path=/; domain=",
                    $_SERVER['HTTP_HOST'],
                    "; expires=" . gmstrftime("%A, %d-%b-%Y %H:%M:%S GMT", time() + $this->state_cookie_time),
                    "; Max-Age=" . $this->state_cookie_time,
                    "; httponly"
                ])
            ]);
            session()->put('url.intended', request()->fullUrl());
            return $response;
        }
    }

    public function PcCallback()
    {
        // TODO: 网页扫码登录回调。
        //回调格式：redirect_url?auth_code=xxx&expires_in=600
        $this->source = 'pc';
        //1.取得access_token
        $this->getAccessTokenResponse();
        //2.取得auth_code
        $auth_code = $this->request->input('auth_code');
        //3.向微信服务器取得用户信息
        $this->getUserByToken($auth_code);

        //4.处理用户信息
        //5.存入cookie
        //6.返回原页面
        return redirect()->intended('/');

    }

    public function WxCallback()
    {
        // TODO: 微信验证回调函数
        $code = $this->getCode();
        logger("开始取TOKEN，CODE：" . $code);
        $this->getAccessTokenResponse('');
        logger("取TOKEN结束");
        if ($this->mapUserToObject($this->getUserByToken($code)) == 0) {
            logger('存储用户COOKIE');
            Cookie::queue(self::USER_COOKIE_NAME, $this->wxUser, 300);
            logger('存储结束，准备跳转原始访问页面');
            return redirect()->intended('/');

        };
        return "ERROR";
    }

    /**
     * 将微信返回的userinfo转成Auth/User对象
     * @param array $user
     * @return $this
     */
    protected function mapUserToObject(array $user)
    {
        /*    参数	说明
                  errcode	返回码
                  errmsg	对返回码的文本描述内容
                  userid	成员UserID。对应管理端的帐号
                  name	成员名称
                  department	成员所属部门id列表
                  position	职位信息
                  mobile	手机号码
                  gender	性别。0表示未定义，1表示男性，2表示女性
                  email	邮箱
                  weixinid	微信号
                  avatar	头像url。注：如果要获取小图将url最后的"/0"改成"/64"即可
                  status	关注状态: 1=已关注，2=已禁用，4=未关注
                  extattr	扩展属性*/
        $errCode = $user['errcode']??999999;
        if ($errCode == 0) {
            $this->wxUser = new WeixinUser();
            $this->wxUser->map([
                'userid' => $user['userid'],
                'department' => $user['department'],
                'name' => $user['name'],
                'weixinid' => $user['weixinid'],
                'avatar' => $user['avatar']??null,
                'name' => $user['nickname']??'',
                'email' => $user['email']??'',
                'token' => $this->access_token,
            ]);

        }
        return $errCode;
    }


    /**
     * 用token获取userinfo
     * @param string $token
     * @return mixed
     */
    protected function getUserByToken($code)
    {
        if ($this->source === 'wx') {
            $response = $this->getHttpClient()->get('https://qyapi.weixin.qq.com/cgi-bin/user/getuserinfo', [
                'query' => [
                    'access_token' => $this->access_token,
                    'code' => $code,
                ],
            ]);
            $userBase = json_decode($response->getBody(), true);
            $userId = $userBase['UserId']??'';
        } elseif ($this->source === 'pc') {
            /*        接口调用请求说明
            https请求方式: POST
            https://qyapi.weixin.qq.com/cgi-bin/service/get_login_info?access_token=ACCESS_TOKEN
            POST数据示例
            {    "auth_code":"xxxxx"}*/

            $response = $this->getHttpClient()->post('https://qyapi.weixin.qq.com/cgi-bin/service/get_login_info', [
                'headers' => ['Accept' => 'application/json'],
                'query' => ['access_token' => $this->access_token],
                'json' => ['auth_code' => $code],
            ]);
            /*返回格式  {
            "usertype": 5,
            "user_info":{"userid":"xxxx","name":"xxxx","avatar":"xxxx"},
            "corp_info":{   "corpid":"wx6c698d13f7a409a4",}
            }*/
            $userBase = json_decode($response->getBody(), true);
            $userId = $userBase['user_info']['userid']??'';

        }
        if ($userId <> '') {
            logger("PC回调获取用户Code为：$code,ID为：$userId");

            $response = $this->getHttpClient()->get('https://qyapi.weixin.qq.com/cgi-bin/user/get', [
                'query' => [
                    'access_token' => $this->access_token,
                    'userid' => $userId,
                ],
            ]);
            return json_decode($response->getBody(), true);
        }
        return '';
    }

    public function check()
    {
        $request = request();
        $value = $request->cookie(self::USER_COOKIE_NAME)??null;
        if ($value == null) return false;
        return true;

    }

    /**
     * 拼接授权链接地址
     * @param string $url
     * @param string $state
     * @return string
     */
    protected function buildAuthUrlFromBase($url, $state)
    {
        $query = http_build_query($this->getCodeFields($state), '', '&', $this->encodingType);
        return $url . '?' . $query . ($this->source === 'wx' ? '#wechat_redirect' : '');
    }

    /**
     * 获取access token的api地址
     * @return string
     */
    protected function getTokenUrl()
    {
        return 'https://qyapi.weixin.qq.com/cgi-bin/gettoken';
    }

    /**
     * 获取调用access token api时的参数
     * @param string $code
     * @return array
     */
    protected function getTokenFields($code)
    {
        return [
            'corpid' => $this->corpId,
            'corpsecret' => $this->corpSecret,
        ];
    }

    protected function getCode()
    {
        if (strpos(Agent::getUserAgent(), 'MicroMessenger') === false) {
            $this->source = 'pc';
            return $this->request->input('auth_code');
        } else {
            $this->source = 'wx';
            return $this->request->input('code');
        }

    }

    /**
     * 生成state参数
     * @return string
     */
    protected function getState()
    {
        return uniqid() . rand(1000, 9999);
    }

    /**
     * 用于校验state
     * 返回true表示state无效，返回false表示state校验正确
     * @return bool
     */
    protected function hasInvalidState()
    {
        if (isset($_COOKIE[$this->state_cookie_name]) &&
            $_COOKIE[$this->state_cookie_name] ==
            self::getEncryptState($this->request->input('state'))
        ) {
            return false;
        }

        return true;
    }

    /**
     * 对$state做加密处理
     * @param $state
     * @return string
     */
    protected function getEncryptState($state)
    {
        return md5($state);
    }

    /**
     * 获取授权链接
     * @param string $state
     * @return string
     */
    protected function getAuthUrl($state)
    {
        /*2、企业或服务商网站引导用户进入登录授权页
         企业或服务商可以在自己的网站首页中放置“微信企业号登录”的入口，引导用户（指企业号管理员或成员）进入登录授权页。
        网址为:  https://qy.weixin.qq.com/cgi-bin/loginpage?corp_id=xxxx&redirect_uri=xxxxx&state=xxxx&usertype=member
        企业或服务商需要提供corp_id，跳转uri和state参数，
        其中uri需要经过一次urlencode作为参数，state用于企业或服务商自行校验session，防止跨域攻击。*/
        if (empty($this->proxy_url)) {
            if (strpos(Agent::getUserAgent(), 'MicroMessenger') === false) {
                $this->auth_url = 'https://qy.weixin.qq.com/cgi-bin/loginpage';
                $this->source = 'pc';
            } else {
                $this->auth_url = 'https://open.weixin.qq.com/connect/oauth2/authorize';
                $this->source = 'wx';
            }
        } else {
            $this->auth_url = $this->proxy_url;
        }
        return $this->buildAuthUrlFromBase($this->auth_url, $state);
    }

    /**
     * 获取授权地址中要传递的参数
     * 如果采用代理授权地址，则添加device的标识
     * @param null $state
     * @return array
     */
    protected function getCodeFields($state = null)
    {
        //https://qy.weixin.qq.com/cgi-bin/loginpage?
        if ($this->source === 'wx') {
            //corp_id=xxxx&redirect_uri=xxxxx&state=xxxx&usertype=member
            $options = [
                'appid' => $this->clientId,
                'redirect_uri' => $this->redirectUrl,
                'response_type' => 'code',
                'scope' => $this->formatScopes($this->scopes, $this->scopeSeparator),
                'state' => $state,
            ];
        } elseif ($this->source === 'pc') {
            $options = [
                'corp_id' => $this->corpId,
                'redirect_uri' => $this->redirectUrl,
                'usertype' => 'all',
                'state' => $state,
            ];
        }
        if (!empty($this->proxy_url)) {
            $options['device'] = $this->device;
        }

        return $options;
    }

    /**
     * 获取access token
     * @param string $code
     * @return mixed
     */
    public function getAccessTokenResponse($code)
    {
        if ($this->check()) {
            //如果检测到有cookie
            $user = $this->request->cookie(self::USER_COOKIE_NAME);
            $this->access_token = $user->token;
            if ($this->access_token <> '') return;
        }
        $query = $this->getTokenFields($code);
        logger("TOKEN查询字串  time:" . time() . request()->fullUrl() . ':', $query);
        $response = $this->getHttpClient()->get($this->getTokenUrl(), [
            'query' => $query,
        ]);
        $this->credentialsResponseBody = json_decode($response->getBody(), true);
        logger('TOKEN查询回调数据' . time() . request()->fullUrl() . '：', $this->credentialsResponseBody);
        $this->access_token = $this->credentialsResponseBody['access_token'];
        /*        {
                    "access_token": "accesstoken000001",
           "expires_in": 7200
        }*/
        return $this->credentialsResponseBody;
    }

    /**
     * 测试方法：校验state参数
     * @return bool
     */
    public function stateInvalid()
    {
        return $this->hasInvalidState();
    }

    /**
     * 定义需要额外解析的参数名
     * @return array
     */
    public static function additionalConfigKeys()
    {
        return ['corpid', 'proxy_url', 'device', 'state_cookie_name', 'state_cookie_time'];
    }

    /**
     * 提供给外部定义scope
     * @param array $scopes
     * @return $this
     */
    public function scopes(array $scopes)
    {
        $this->scopes = array_unique($scopes);

        return $this;
    }

    /**
     * 重写setConfig方法，在原有的基础上，增加对
     * 'proxy_url', 'device', 'state_cookie_name', 'state_cookie_time'
     * 这四个参数的解析
     * @param ConfigInterface $config
     * @return $this
     */
    public function setConfig(ConfigInterface $config)
    {
        $config = $config->get();

        $this->config = $config;
        $this->clientId = $config['client_id'];
        $this->clientSecret = $config['client_secret'];
        $this->redirectUrl = $config['redirect'];
        $this->proxy_url = $config['proxy_url'];
        $this->callback_token = $config['callback_token'];
        $this->encodingAesKey = $config['encodingAesKey'];
        $this->corpId = $config['corpId'];
        $this->corpSecret = $config['corpSecret'];
        if (isset($config['proxy_url'])) {
            $this->proxy_url = $config['proxy_url'];
        }
        if (isset($config['device'])) {
            $this->device = $config['device'];
        }
        if (isset($config['state_cookie_name'])) {
            $this->state_cookie_name = $config['state_cookie_name'];
        }
        if (isset($config['state_cookie_time'])) {
            $this->state_cookie_time = $config['state_cookie_time'];
        }

        return $this;
    }

    public function getOpenId()
    {
        return $this->openId;
    }

    public function setOpenId($openId)
    {
        $this->openId = $openId;
        return $this;
    }

    public function getScopes()
    {
        return $this->scopes;
    }

    public function setScopes($scopes)
    {
        $this->scopes = $scopes;
        return $this;
    }

    public function getProxyUrl()
    {
        return $this->proxy_url;
    }

    public function setProxyUrl($proxy_url)
    {
        $this->proxy_url = $proxy_url;
        return $this;
    }

    public function getDevice()
    {
        return $this->device;
    }

    public function setDevice($device)
    {
        $this->device = $device;
        return $this;
    }

    public function getStateCookieName()
    {
        return $this->state_cookie_name;
    }

    public function setStateCookieName($state_cookie_name)
    {
        $this->state_cookie_name = $state_cookie_name;
        return $this;
    }

    public function getStateCookieTime()
    {
        return $this->state_cookie_time;
    }

    public function setStateCookieTime($state_cookie_time)
    {
        $this->state_cookie_time = $state_cookie_time;
        return $this;
    }

    public function getClientId()
    {
        return $this->clientId;
    }

    public function setClientId($clientId)
    {
        $this->clientId = $clientId;
        return $this;
    }

    public function getClientSecret()
    {
        return $this->clientSecret;
    }

    public function setClientSecret($clientSecret)
    {
        $this->clientSecret = $clientSecret;
        return $this;
    }

    public function getRedirectUrl()
    {
        return $this->redirectUrl;
    }

    public function setRedirectUrl($redirectUrl)
    {
        $this->redirectUrl = $redirectUrl;
        return $this;
    }
}
