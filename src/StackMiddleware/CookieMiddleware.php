<?php

namespace Drupal\drupal_seamless_cilogon\StackMiddleware;

use Drupal\Core\Routing\TrustedRedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\HttpFoundation\Cookie;

/**
 * Provides a HTTP middleware.
 */
class CookieMiddleware implements HttpKernelInterface {

  /**
   * The wrapped HTTP kernel.
   *
   * @var \Symfony\Component\HttpKernel\HttpKernelInterface
   */
  protected $httpKernel;

  /**
   * Constructs a CookieMiddleware object.
   *
   * @param \Symfony\Component\HttpKernel\HttpKernelInterface $kernel
   *   The decorated kernel.
   * @param mixed $optional_argument
   *   (optional) An optional argument.
   */
  public function __construct(HttpKernelInterface $http_kernel) {
    $this->httpKernel = $http_kernel;
  }

  /**
   * {@inheritdoc}
   */
  public function handle(Request $request, $type = self::MASTER_REQUEST, $catch = TRUE) {
    if (!$type) {
      \Drupal::logger('drupal_seamless_login')->notice('type');
      return $this->httpKernel->handle($request, $type, $catch);
    }

    if (!$this->verify_domain_is_asp()) {
      \Drupal::logger('drupal_seamless_login')->notice('domain');
      return $this->httpKernel->handle($request, $type, $catch);
    }

    $seamless_login_enabled = \Drupal::state()->get('drupal_seamless_cilogon.seamless_login_enabled', TRUE);
    if (!$seamless_login_enabled) {
      \Drupal::logger('drupal_seamless_login')->notice('seamless');
      return $this->httpKernel->handle($request, $type, $catch);
    }

    // Don't attempt to redirect if the cilogon_auth module is not installed.
    $moduleHandler = \Drupal::service('module_handler');
    if (!$moduleHandler->moduleExists('cilogon_auth')) {
      \Drupal::logger('drupal_seamless_login')->notice('cilogin_auth');
      return $this->httpKernel->handle($request, $type, $catch);
    }

    $user_is_authenticated = \Drupal::currentUser()->isAuthenticated();
    $path = $_SERVER['REQUEST_URI'];
    $arg = explode('/', $path);
    $cookie_name = $_COOKIE['SESSaccesscisso'];
    $cookie_exists = NULL !== $cookie_name;
    $seamless_debug = \Drupal::state()->get('drupal_seamless_cilogon.seamless_cookie_debug', FALSE);

    if ($seamless_debug) {
      $msg = __FUNCTION__ . "() ------- route_name = $route_name"
        . ", user_is_authenticated = " . ($user_is_authenticated ? "TRUE" : "FALSE")
        . ", \$_COOKIE[$cookie_name] "
        . ($cookie_exists ? ('*exists* (with value ' . print_r($_COOKIE[$cookie_name], TRUE) . ')') : ' <not set>')
        . ' -- ' . basename(__FILE__) . ':' . __LINE__;
      \Drupal::messenger()->addStatus($msg);
      error_log('seamless: ' . $msg);
    }

    // If coming back from cilogon, set the cookie.
    if ($arg[1] === 'cilogon-auth') {
      \Drupal::logger('drupal_seamless_login')->notice('cilogin');
      if (!$cookie_exists) {
        $this->doSetCookie($uri, $seamless_debug, $cookie_name);
      }
      return $this->httpKernel->handle($request, $type, $catch);
    }

    // If logging out, delete the cookie.
    if ($route_name === 'user.logout') {
      if ($cookie_exists) {
        $this->doDeleteCookie($uri, $seamless_debug, $cookie_name);
      }
      return $this->httpKernel->handle($request, $type, $catch);
    }

    // If the user is authenticated, no need to redirect to CILogon, unless cookie doesn't exist, in
    // which case, logout.
    if ($user_is_authenticated) {
      // Unless cookie doesn't exist. In this case, logout.
      if (
        !$cookie_exists &&
        $route_name !== 'user.logout' &&
        $route_name !== 'user.login'
      ) {
        $destination = "/user/logout/";
        $redir = new TrustedRedirectResponse($destination, '302');
        $redir->headers->set('Cache-Control', 'public, max-age=0');
        $redir->addCacheableDependency($destination);
        // $event->setResponse($redir);
      }
      return $this->httpKernel->handle($request, $type, $catch);
    }

    // If here -- user is unauthenticated.  If cookie exists, redirect to cilogon.
    if ($cookie_exists) {
      \Drupal::logger('drupal_seamless_login')->notice('bing');
      $this->doRedirectToCilogon($request, $seamless_debug);
    }

    return $this->httpKernel->handle($request, $type, $catch);

  }

  /**
   * Add the cookie, via a redirect.
   *
   * @param \Symfony\Component\HttpKernel\Event\RequestEvent $event
   *   Response event.   *.
   */
  protected function doSetCookie($uri, $seamless_debug, $cookie_name) {
    $event = new RequestEvent();

    $site_name = \Drupal::config('system.site')->get('name');
    $cookie_value = \Drupal::state()->get('drupal_seamless_cilogon.seamless_cookie_value', $site_name);
    $cookie_expiration = \Drupal::state()->get('drupal_seamless_cilogon.seamless_cookie_expiration', '+18 hours');
    // Use value from form.
    $cookie_expiration = strtotime($cookie_expiration);
    $cookie_domain = \Drupal::state()->get('drupal_seamless_cilogon.seamless_cookie_domain', '.access-ci.org');
    $cookie = new Cookie($cookie_name, $cookie_value, $cookie_expiration, '/', $cookie_domain);

    $destination = $uri;

    // @todo consider following
    // "MUST use service to turn of Internal Page Cache,
    // or else anonymous users will not ever be able to reach source page."
    // $this->killSwitch->trigger();
    // from https://www.drupal.org/project/adv_varnish/issues/3127566:
    // Another documented way is to call the killSwitch in your code:
    //
    // commenting this out to see unnecessary
    // \Drupal::service('page_cache_kill_switch')->trigger();
    $redir = new TrustedRedirectResponse($destination, '302');
    $redir->headers->setCookie($cookie);
    $redir->headers->set('Cache-Control', 'public, max-age=0');
    $redir->addCacheableDependency($destination);
    $redir->addCacheableDependency($cookie);

    $event->setResponse($redir);

    if ($seamless_debug) {
      $msg = __FUNCTION__ . "() - destination = $destination ---- set cookie:  name = $cookie_name, value = $cookie_value, expiration = $cookie_expiration "
        . " = " . date("Y-m-d H:i:s", $cookie_expiration) . ", domain = $cookie_domain"
        . ' -- ' . basename(__FILE__) . ':' . __LINE__;
      \Drupal::messenger()->addStatus($msg);
    }
  }

  /**
   * Redirect to Cilogon.
   *
   * @param \Symfony\Component\HttpKernel\Event\RequestEvent $event
   *   Response event.   *.
   */
  protected function doRedirectToCilogon(Request $request, $seamless_debug) {

    // \Drupal::service('page_cache_kill_switch')->trigger();
    // Setup redirect to CILogon flow.
    // @todo move some of the following to a constructor for this class?
    $container = \Drupal::getContainer();
    $client_name = 'cilogon';
    $config_name = 'cilogon_auth.settings.' . $client_name;
    $configuration = $container->get('config.factory')->get($config_name)->get('settings');
    $pluginManager = $container->get('plugin.manager.cilogon_auth_client.processor');
    $claims = $container->get('cilogon_auth.claims');
    $client = $pluginManager->createInstance($client_name, $configuration);
    $scopes = $claims->getScopes();
    $destination = $request->getRequestUri();
    $query = $request->getQueryString();
    $_SESSION['cilogon_auth_op'] = 'login';
    $_SESSION['cilogon_auth_destination'] = [$destination, ['query' => $query]];

    $response = $client->authorize($scopes);
    $response->headers->set('Cache-Control', 'public, max-age=0');

    new TrustedRedirectResponse($response->getTargetUrl(), 301);
    return $this->httpKernel->handle($request, $type, $catch);

    // $event->setResponse($response);
    if ($seamless_debug) {
      $msg = __FUNCTION__ . "() - destination = $destination ---- "
        . ' -- ' . basename(__FILE__) . ':' . __LINE__;
      \Drupal::messenger()->addStatus($msg);
    }
  }

  /**
   * The ACCESS support portal uses the domain access module.  If this module
   * is in use, we only want to set cookies for the 'access-support'
   * module.
   *
   * This function checks if the domain access module is in use, and
   * if so, returns FALSE if the current domain name is not 'access-support'.
   *
   * Otherwise it returns true.
   *
   * @return bool whether to proceed with the cookie logic in invoking code
   */
  protected function verify_domain_is_asp() {
    // Verify the domain module is installed.  If not installed,
    // return true to proceed to CILogon.
    $moduleHandler = \Drupal::service('module_handler');
    if (!$moduleHandler->moduleExists('domain')) {
      return TRUE;
    }

    $domain_storage = \Drupal::entityTypeManager()->getStorage('domain');
    $current_domain_name = $domain_storage->loadDefaultId();

    $domain_verified = $current_domain_name === 'amp_cyberinfrastructure_org';

    $seamless_debug = \Drupal::state()->get('drupal_seamless_cilogon.seamless_cookie_debug', FALSE);
    if ($seamless_debug) {
      $msg = __FUNCTION__ . "() - current_domain_name = [" . $current_domain_name
        . '] so verify_domain_is_asp() returns ' . ($domain_verified ? 'TRUE' : 'FALSE')
        . ' -- ' . basename(__FILE__) . ':' . __LINE__;
      \Drupal::messenger()->addStatus($msg);
    }

    // Return true if the current domain is 'access-support'.
    return $domain_verified;
  }

}
