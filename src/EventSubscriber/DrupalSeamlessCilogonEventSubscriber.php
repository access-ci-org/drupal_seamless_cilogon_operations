<?php

/**
 * @file
 * Contains Drupal\drupal_seamless_cilogon\EventSubscriber\DrupalSeamlessCilogonEventSubscriber
 */

namespace Drupal\drupal_seamless_cilogon\EventSubscriber;

use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
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

    //  If the user is authenticated, nothing is needed and we can just return
    if (\Drupal::currentUser()->isAuthenticated()) {
      return;
    }

    $moduleHandler = \Drupal::service('module_handler');
    if (!$moduleHandler->moduleExists('cilogon_auth')) {
      return;
    }

    // 
    $cookie_exists = isset($_COOKIE[self::seamlessCookieName]);

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

    $event->setResponse($response);
  }

  /**
   * {@inheritdoc}
   */
  public static function getSubscribedEvents() {
    return [KernelEvents::REQUEST => 'onRequest'];
  }

}