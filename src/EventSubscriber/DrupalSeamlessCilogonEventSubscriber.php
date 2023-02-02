<?php

/**
 * @file
 * Contains Drupal\drupal_seamless_cilogon\EventSubscriber\DrupalSeamlessCilogonEventSubscriber
 */

namespace Drupal\drupal_seamless_cilogon\EventSubscriber;

use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\RequestEvent;

/**
 * Event Subscriber DrupalSeamlessCilogonEventSubscriber
 */
class DrupalSeamlessCilogonEventSubscriber implements EventSubscriberInterface {

  const seamlessCookieName = 'access_ci_sso';

  // TODO implement a constructor to initialize statics?

  /**
   * Event handler for KernelEvents::REQUEST events, specifically to support seamless login by
   * checking if a non-authenticated user already has the seamless cilogon flow set.
   */
  public function onRequest(RequestEvent $event) {
    $cookie_name = \Drupal::state()->get('drupal_seamless_cilogon.seamless_cookie_name', self::seamlessCookieName);

    $cookie_exists = isset($_COOKIE[$cookie_name]);

    $seamless_debug = \Drupal::state()->get('drupal_seamless_cilogon.seamless_cookie_debug', true);
    
    if ($seamless_debug) {
      $msg =  __FUNCTION__ . "() - \$_COOKIE[$cookie_name] = " 
        . ($cookie_exists ? print_r($_COOKIE[$cookie_name], true) : ' <not set>')
        . ' -- ' . basename(__FILE__) . ':' . __LINE__ ;  
      \Drupal::messenger()->addStatus($msg);
      \Drupal::logger('seamless_cilogon')->debug($msg);
    }


    //  If the user is authenticated,no need to redirect to CILogin
    if (\Drupal::currentUser()->isAuthenticated()) {
      return;
    }

    // Don't attempt to redirect if the cilogon_auth module is not installed
    $moduleHandler = \Drupal::service('module_handler');
    if (!$moduleHandler->moduleExists('cilogon_auth')) {
      return;
    }

    // if cookie is set, redirect to CILogon flow
    // if no cookie, do nothing, just return
    if (!$cookie_exists) {
      return;
    }

    // setup redirect to CILogon flow

    // TODO -- could any of the following be moved to a constructor for this class?
    
    $container = \Drupal::getContainer();

    $client_name = 'cilogon';
    $config_name = 'cilogon_auth.settings.' . $client_name;
    $configuration = $container->get('config.factory')->get($config_name)->get('settings');
    $pluginManager = $container->get('plugin.manager.cilogon_auth_client.processor');
    $claims = $container->get('cilogon_auth.claims');
    $client = $pluginManager->createInstance($client_name, $configuration);
    $scopes = $claims->getScopes();

    // not sure how this is used - following pattern in cilogon_auth/src/Form/CILogonAuthLoginForm.php
    $_SESSION['cilogon_auth_op'] = 'login';

    $response = $client->authorize($scopes);

    $seamless_login_enabled = \Drupal::state()->get('drupal_seamless_cilogon.seamless_login_enabled', true);
    
    if ($seamless_debug) {
      $msg =  __FUNCTION__ . "() - cookie exists, redirecting to cilogon is "
        . ($seamless_login_enabled ? "ENABLED" : "DISABLED")
        . ' -- ' . basename(__FILE__) . ':' . __LINE__ ;  
      \Drupal::messenger()->addStatus($msg);
      \Drupal::logger('seamless_cilogon')->debug($msg);
    }

    if ($seamless_login_enabled) {
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