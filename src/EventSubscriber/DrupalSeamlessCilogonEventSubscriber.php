<?php

namespace Drupal\drupal_seamless_cilogon\EventSubscriber;

use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpFoundation\RedirectResponse;

/**
 * Event Subscriber DrupalSeamlessCilogonEventSubscriber.
 */
class DrupalSeamlessCilogonEventSubscriber implements EventSubscriberInterface {

  const SEAMLESSCOOKIENAME = 'access_ci_sso';

  /**
   * Event handler for KernelEvents::REQUEST events, specifically to support
   * seamless login by checking if a non-authenticated user already has already
   * been through seamless login.
   *
   * Logic:
   *  - if user already authenticated and if there is no cookie, logout.
   *    They must have logged out on another ACCESS subdomain. Otherwise return.
   *  - if cilogon_auth module not installed, just return
   *  - if the the seamless_cilogon cookie does not exist, just return
   *  - otherwise, redirect to CILogon.
   */
  public function onRequest(RequestEvent $event) {

    $seamless_debug = \Drupal::state()->get('drupal_seamless_cilogon.seamless_cookie_debug', TRUE);

    $cookie_name = \Drupal::state()->get('drupal_seamless_cilogon.seamlesscookiename', self::SEAMLESSCOOKIENAME);
    $cookie_exists = NULL !== \Drupal::service('request_stack')->getCurrentRequest()->cookies->get($cookie_name);

    // If the user is authenticated, no need to redirect to CILogin.
    if (\Drupal::currentUser()->isAuthenticated()) {

      // Unless cookie doesn't exist. In this case, logout.
      if (!$cookie_exists && \Drupal::routeMatch()->getRouteName() !== 'user.logout') {
        $redirect = new RedirectResponse("/user/logout/");
        $event->setResponse($redirect->send());
      }

      if ($seamless_debug) {
        $msg = __FUNCTION__ . "() - user already authenticated, no need to redirect, returning"
          . ' -- ' . basename(__FILE__) . ':' . __LINE__;
        \Drupal::messenger()->addStatus($msg);
        \Drupal::logger('seamless_cilogon')->debug($msg);
      }

      return;
    }

    // Don't attempt to redirect if the cilogon_auth module is not installed.
    $moduleHandler = \Drupal::service('module_handler');
    if (!$moduleHandler->moduleExists('cilogon_auth')) {
      return;
    }

    if ($seamless_debug) {
      $msg = __FUNCTION__ . "() - \$_COOKIE[$cookie_name] = "
        . ($cookie_exists ? print_r($_COOKIE[$cookie_name], TRUE) : ' <not set>')
        . ' -- ' . basename(__FILE__) . ':' . __LINE__;
      \Drupal::messenger()->addStatus($msg);
      \Drupal::logger('seamless_cilogon')->debug($msg);
    }

    // If cookie is set, redirect to CILogon flow
    // if no cookie, do nothing, just return.
    if (!$cookie_exists) {
      return;
    }

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

    // Not sure how this is used - following pattern in cilogon_auth/src/Form/CILogonAuthLoginForm.php.
    $_SESSION['cilogon_auth_op'] = 'login';

    $response = $client->authorize($scopes);

    $seamless_login_enabled = \Drupal::state()->get('drupal_seamless_cilogon.seamless_login_enabled', TRUE);

    if ($seamless_login_enabled) {

      if ($seamless_debug) {
        $msg = __FUNCTION__ . "() - cookie exists, redirecting to cilogon is "
          . ($seamless_login_enabled ? "ENABLED" : "DISABLED")
          . ' -- ' . basename(__FILE__) . ':' . __LINE__;
        \Drupal::messenger()->addStatus($msg);
        \Drupal::logger('seamless_cilogon')->debug($msg);
      }

      $event->setResponse($response);
    }
  }

  /**
   * Subscribe to onRequest events.  This allows checking if a CILogon redirect is needed any time
   * a page is requested.
   *
   * {@inheritdoc}
   */
  public static function getSubscribedEvents() {
    return [KernelEvents::REQUEST => 'onRequest'];
  }

}
