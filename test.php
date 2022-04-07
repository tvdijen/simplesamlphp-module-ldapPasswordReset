<?php

try {
$whitelist = [
  'https://engine.broker.accrijk.rijksweb.nl/authentication/sp/metadata',
  'https://engine.sson.accsscict.rijksweb.nl/authentication/sp/metadata',
  'https://acceptatie-rijksportaal.overheid-i.nl/site/saml/metadata',
  'https://rijksadresgids.acc.rijksweb.nl/shibboleth',
];

$requesters = $requestObj->getRequesterIds();
if (empty($requesters)) {
  // Non-proxied request - The request originates from a directly connected SP
  $requesters = [$requestObj->getIssuer()];
}

foreach ($requesters as $requester) {
  if (!in_array($requester, $whitelist, true)) {
    $policyDecision = new \OpenConext\EngineBlockBundle\Pdp\PolicyDecision();
    throw \EngineBlock_Corto_Exception_PEPNoAccess::basedOn($policyDecision);
  }
}
} catch (\Exception $e) {
  $attributes['debug'] = [0 => $e->getMessage()];
}
