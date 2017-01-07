<?php

namespace YitianProviders\Weixin;

use SocialiteProviders\Manager\SocialiteWasCalled;

class WeixinExtendSocialite
{
    /**
     * Register the provider.
     *
     * @param \SocialiteProviders\Manager\SocialiteWasCalled $socialiteWasCalled
     */
    public function handle(SocialiteWasCalled $socialiteWasCalled)
    {
        $socialiteWasCalled->extendSocialite(
            'qywx', __NAMESPACE__.'\QiyeWeixinProvider'
        );
    }
}
