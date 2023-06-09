<?php

namespace Drupal\drupal_seamless_cilogon\StackMiddleware;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;

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
   * Constructs a drupal_seamless_cilogin object.
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

    $user_is_authenticated = FALSE;
    foreach ($_COOKIE as $cookie_key => $cookie) {
      if (str_starts_with($cookie_key, 'SSESS')) {
        $user_is_authenticated = TRUE;
      }
    }
    $path = $request->getRequestUri();
    $arg = explode('/', $path);
    $cookie_name = isset($_COOKIE['SESSaccesscisso']) ? $_COOKIE['SESSaccesscisso'] : NULL;
    $cookie_exists = NULL !== $cookie_name;

    if (str_starts_with($arg[1], 'user')) {
      return $this->httpKernel->handle($request, $type, $catch);
    }

    // If coming back from cilogon, set the cookie.
    if ($arg[1] === 'cilogon-auth') {
      \Drupal::logger('drupal_seamless_login')->notice('cilogin');
      return $this->httpKernel->handle($request, $type, $catch);
    }

    // If the user is authenticated, no need to redirect to CILogon, unless cookie doesn't exist, in
    // which case, logout
    if ($user_is_authenticated) {
      // Unless cookie doesn't exist. In this case, logout.
      if (
        !$cookie_exists &&
        str_starts_with($arg[1], 'user')
      ) {
        return new RedirectResponse($request->getBasePath() . "/user/logout", 302, ['Cache-Control' => 'no-cache']);
      }
      return $this->httpKernel->handle($request, $type, $catch);
    }

    // If here -- user is unauthenticated.  If cookie exists, redirect to cilogon.
    if ($cookie_exists) {
      \Drupal::logger('drupal_seamless_login')->notice('bing');
      $from = $request->getRequestUri();
      return new RedirectResponse($request->getBasePath() . "/user?redirect=$from", 302, ['Cache-Control' => 'no-cache']);
    }

    return $this->httpKernel->handle($request, $type, $catch);
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

    // Return true if the current domain is 'access-support'.
    return $domain_verified;
  }

}
