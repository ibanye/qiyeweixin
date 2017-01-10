<?php

namespace YitianProviders\QiyeWeixin;

use SocialiteProviders\Manager\SocialiteWasCalled;

class QYWXExtendSocialite
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
