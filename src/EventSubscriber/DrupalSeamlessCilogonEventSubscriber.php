<?php

namespace Drupal\drupal_seamless_cilogon\EventSubscriber;

use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Cookie;
use Drupal\Core\PageCache\ResponsePolicy\KillSwitch;
use Drupal\Core\Routing\TrustedRedirectResponse;
use Drupal\Core\Routing\CurrentRouteMatch;
use Drupal\Core\Config\ConfigFactoryInterface;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Drupal\Core\Url;

/**
 * Event Subscriber DrupalSeamlessCilogonEventSubscriber.
 */
class DrupalSeamlessCilogonEventSubscriber implements EventSubscriberInterface {

  // const SEAMLESSCOOKIENAME = 'access_ci_sso';
  const SEAMLESSCOOKIENAME = '  SESSaccesscisso';

  // /**
  //  * Drupal\Core\Config\ConfigFactoryInterface definition.
  //  *
  //  * @var Drupal\Core\Config\ConfigFactoryInterface
  //  */
  // protected $configFactory;

  // /**
  //  * The current route match.
  //  *
  //  * @var \Drupal\Core\Routing\CurrentRouteMatch
  //  */
  // protected $currentRouteMatch;

  // /**
  //  * The page cache kill switch.
  //  *
  //  * @var Drupal\Core\PageCache\ResponsePolicy\KillSwitch
  //  */
  // protected $killSwitch;

  // /**
  //  * {@inheritdoc}
  //  */
  // public function __construct(ConfigFactoryInterface $config_factory, CurrentRouteMatch $current_route_match, KillSwitch $kill_switch) {
  //   $this->configFactory = $config_factory;
  //   $this->currentRouteMatch = $current_route_match;
  //   $this->killSwitch = $kill_switch;
  // }

  // /**
  //  * {@inheritdoc}
  //  */
  // public static function create(ContainerInterface $container) {
  //   return new static(
  //     $container->get('config.factory'),
  //     $container->get('current_route_match')
  //   );
  // }




  /**
   * Event handler for KernelEvents::REQUEST events, specifically to support
   * seamless login by checking if a non-authenticated user already has already
   * been through seamless login.
   *
   * Logic:
   *  - if user already authenticated and if there is no cookie, logout.
   *    They must have logged out on another ACCESS subdomain. 
   *    Otherwise return.
   *  - if cilogon_auth module not installed, just return
   *  - if the the seamless_cilogon cookie does not exist, just return
   *  - otherwise, redirect to CILogon.
   * 
   * 
   */
  public function onRequest(RequestEvent $event) {

    // TODO consider this:
    // this url includes the following:
    // https://drupal.stackexchange.com/questions/274485/cant-find-cookie-for-validation-in-eventsubscriber
    // they also user a constructor and changes to service.yml to set the class member routeMatch 
    // if (!$this->routeMatch->getRouteName() == 'entity.node.canonical') {
    //   return;
    // }


    $is_master_event = $event->isMasterRequest();
    $seamless_debug = \Drupal::state()->get('drupal_seamless_cilogon.seamless_cookie_debug', TRUE);
    $seamless_login_enabled = \Drupal::state()->get('drupal_seamless_cilogon.seamless_login_enabled', TRUE);
    $domain_verified = verify_domain_is_asp();
    $route_name = \Drupal::routeMatch()->getRouteName();

    if (!$domain_verified || !$seamless_login_enabled || !$is_master_event) {
      return;
    }

    // Don't attempt to redirect if the cilogon_auth module is not installed.
    $moduleHandler = \Drupal::service('module_handler');
    if (!$moduleHandler->moduleExists('cilogon_auth')) {
      return;
    }

    $user_is_authenticated = \Drupal::currentUser()->isAuthenticated();
    
    $cookie_name = \Drupal::state()->get('drupal_seamless_cilogon.seamlesscookiename', self::SEAMLESSCOOKIENAME);
    // which way is best to check for cookie?
    $cookie_exists = NULL !== \Drupal::service('request_stack')->getCurrentRequest()->cookies->get($cookie_name);
    // $cookie_exists = isset($_COOKIE[$cookie_name]);

    if ($seamless_debug) {
      $msg = __FUNCTION__ . "() ------- redirect to cilogon is "
        . ($seamless_login_enabled ? "ENABLED" : "DISABLED")
        . ', is_master_event = ' . ($is_master_event ? "TRUE" : "FALSE")
        . ", routename = $route_name"
        . ", domain_verified = " . ($domain_verified ? "TRUE" : "FALSE")
        . ", user_is_authenticated = " . ($user_is_authenticated ? "TRUE" : "FALSE")
        . ", \$_COOKIE[$cookie_name] "
        . ($cookie_exists ? ('*exists* (with value ' . print_r($_COOKIE[$cookie_name], TRUE) . ')') : ' <not set>')
        . ' -- ' . basename(__FILE__) . ':' . __LINE__;
      \Drupal::messenger()->addStatus($msg);
      \Drupal::logger('seamless_cilogon')->debug($msg);
    }

    // if coming back from cilogon, set the cookie
    if ($route_name === 'cilogon_auth.redirect_controller_redirect') {
      if (!$cookie_exists) {  // TODO necessary?  could cookie ever exist?
        $this->doSetCookie($event, $seamless_debug, $cookie_name);
      }
      return;
    } 


    // If the user is authenticated, no need to redirect to CILogin, unless cookie doesn't exist, in 
    // which case, logout
    if ($user_is_authenticated) {
      // Unless cookie doesn't exist. In this case, logout.
      if (!$cookie_exists && 
          // TODO  -- necessary??
          $route_name !== 'user.logout' && 
          $route_name !== 'user.login') {
            
        if ($seamless_debug) {
          $msg = __FUNCTION__ . "() - user authenticated but no cookie found"
            . ' -- ' . basename(__FILE__) . ':' . __LINE__;
          \Drupal::messenger()->addStatus($msg);
          \Drupal::logger('seamless_cilogon')->debug($msg);

          $timeofday=gettimeofday(); 
          $timestamp = sprintf("%s.%06d", date('Y-m-d H:i:s', $timeofday['sec']), $timeofday['usec']);

          $msg = __FUNCTION__ . "() - route_name = $route_name, LOGOUT"
            . ' -- ' . basename(__FILE__) . ':' . __LINE__ . ' ' . $timestamp;
          \Drupal::messenger()->addStatus($msg);
          \Drupal::logger('seamless_cilogon')->debug($msg);
        }

        $destination = "/user/logout/";
        $redir = new TrustedRedirectResponse($destination, '302');
        $redir->headers->set('Cache-Control', 'public, max-age=0');
        $redir->addCacheableDependency($destination);
        $event->setResponse($redir);

      }
      return;
    }

    // if here -- user is unauthenticated.  If cookie exists, redirect to cilogon
    if ($cookie_exists) {
        $this->doRedirectToCilogon($event, $seamless_debug);
    }
  }

  /**
   * Add the cookie, via a redirect
   * 
   * @param \Symfony\Component\HttpKernel\Event\RequestEvent $event
   *   Response event.

   */
  protected function doSetCookie(RequestEvent $event, $seamless_debug, $cookie_name) {

    $site_name = \Drupal::config('system.site')->get('name');
    $cookie_value = \Drupal::state()->get('drupal_seamless_cilogon.seamless_cookie_value', $site_name);

    $cookie_expiration = \Drupal::state()->get('drupal_seamless_cilogon.seamless_cookie_expiration', '+18 hours');
    $cookie_expiration = strtotime($cookie_expiration);  // use value from form
    $cookie_domain = \Drupal::state()->get('drupal_seamless_cilogon.seamless_cookie_domain', '.access-ci.org');

    $cookie = new Cookie($cookie_name, $cookie_value, $cookie_expiration, '/', $cookie_domain);

    $request = $event->getRequest();
    $destination = $request->getRequestUri();

    // TODO -- confirm this
    \Drupal::service('page_cache_kill_switch')->trigger();

    // TODO -- need the trusted redirect?  or see pattern in doRedirectToCilogon()
    $redir = new TrustedRedirectResponse($destination, '302');
    $redir->headers->setCookie($cookie);
    $redir->headers->set('Cache-Control', 'public, max-age=0');
    $redir->addCacheableDependency($destination);
    $redir->addCacheableDependency($cookie);

    $event->setResponse($redir);

    if ($seamless_debug) {
      $msg =  __FUNCTION__ . "() - destination = $destination ---- set cookie:  name = $cookie_name, value = $cookie_value, expiration = $cookie_expiration "
        . " = " . date("Y-m-d H:i:s", $cookie_expiration) . ", domain = $cookie_domain"
        . ' -- ' . basename(__FILE__) . ':' . __LINE__ ;
      \Drupal::messenger()->addStatus($msg);
      \Drupal::logger('seamless_cilogon')->debug($msg);
    }
  }

  /**
   * Redirect to Cilogon 
   * 
   * @param \Symfony\Component\HttpKernel\Event\RequestEvent $event
   *   Response event.

   */
  protected function doRedirectToCilogon(RequestEvent $event, $seamless_debug) {

    $request = $event->getRequest();
    $destination = $request->getRequestUri();

    // TODO -- consider following
    //
    // MUST use service to turn of Internal Page Cache,
    // or else anonymous users will not ever be able to reach source page.

    // not sure about this
    // $this->killSwitch->trigger();

    // from https://www.drupal.org/project/adv_varnish/issues/3127566:
    // Another documented way is to call the killSwitch in your code:

    \Drupal::service('page_cache_kill_switch')->trigger();
    
    // Setup redirect to CILogon flow.
    // @todo could any of the following be moved to a constructor for this class?
    $container = \Drupal::getContainer();
    $client_name = 'cilogon';
    $config_name = 'cilogon_auth.settings.' . $client_name;
    $configuration = $container->get('config.factory')->get($config_name)->get('settings');
    $pluginManager = $container->get('plugin.manager.cilogon_auth_client.processor');
    $claims = $container->get('cilogon_auth.claims');
    $client = $pluginManager->createInstance($client_name, $configuration);
    $scopes = $claims->getScopes();
    $_SESSION['cilogon_auth_op'] = 'login';
    $response = $client->authorize($scopes);
    $response->headers->set('Cache-Control', 'public, max-age=0');

    // TODO -- need something like following??
    // $response->addCacheableDependency($destination);
    // $response->addCacheableDependency($cookie);

    $event->setResponse($response);

    if ($seamless_debug) {
      $msg =  __FUNCTION__ . "() - destination = $destination ---- "
        . ' -- ' . basename(__FILE__) . ':' . __LINE__ ;
      \Drupal::messenger()->addStatus($msg);
      \Drupal::logger('seamless_cilogon')->debug($msg);
    }
  }

  /**
   * Subscribe to onRequest events.  This allows checking if a CILogon redirect is needed any time
   * a page is requested.
   *
   * {@inheritdoc}
   */
  public static function getSubscribedEvents() {

    // return [KernelEvents::REQUEST => 'onRequest'];

    // splash-redirect does this this way:
    $events[KernelEvents::REQUEST][] = ['onRequest', 31];
    return $events;

  }

}
