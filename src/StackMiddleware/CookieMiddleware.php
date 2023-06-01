<?php

namespace Drupal\drupal_seamless_cilogon\StackMiddleware;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\HttpKernelInterface;

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
   * Constructs a MyModule object.
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
    if (!$event->isMasterRequest()) {
      return;
    }

    if (!$this->verify_domain_is_asp()) {
      return;
    }

    $seamless_login_enabled = \Drupal::state()->get('drupal_seamless_cilogon.seamless_login_enabled', TRUE);
    if (!$seamless_login_enabled) {
      return;
    }

    // Don't attempt to redirect if the cilogon_auth module is not installed.
    $moduleHandler = \Drupal::service('module_handler');
    if (!$moduleHandler->moduleExists('cilogon_auth')) {
      return;
    }

    $user_is_authenticated = \Drupal::currentUser()->isAuthenticated();
    $route_name = \Drupal::routeMatch()->getRouteName();
    $cookie_name = self::SEAMLESSCOOKIENAME;
    $cookie_exists = NULL !== \Drupal::service('request_stack')->getCurrentRequest()->cookies->get($cookie_name);
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
    if ($route_name === 'cilogon_auth.redirect_controller_redirect') {
      if (!$cookie_exists) {
        $this->doSetCookie($event, $seamless_debug, $cookie_name);
      }
      return;
    }

    // If logging out, delete the cookie.
    if ($route_name === 'user.logout') {
      if ($cookie_exists) {
        $this->doDeleteCookie($event, $seamless_debug, $cookie_name);
      }
      return;
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
        $event->setResponse($redir);
      }
      return;
    }

    // If here -- user is unauthenticated.  If cookie exists, redirect to cilogon.
    if ($cookie_exists) {
      $this->doRedirectToCilogon($event, $seamless_debug);
    }
  }

  /**
   * Redirect to Cilogon.
   *
   * @param \Symfony\Component\HttpKernel\Event\RequestEvent $event
   *   Response event.   *.
   */
  protected function doRedirectToCilogon(RequestEvent $event, $seamless_debug) {
    $request = $event->getRequest();

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

    $event->setResponse($response);

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

    $token = \Drupal::token();
    $domainName = t("[domain:name]");
    $current_domain_name = Html::getClass($token->replace($domainName));

    $domain_verified = $current_domain_name === 'access-support';

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
