package com.gu.pandomainauth.model

import com.gu.pandomainauth.{PrivateKey, PublicKey, Secret}

case class PanDomainAuthSettings(
  publicKey: PublicKey,
  privateKey: PrivateKey,
  cookieSettings: CookieSettings,
  oAuthSettings: OAuthSettings,
  ppSettings: PartnerPlatformSettings,
  google2FAGroupSettings: Option[Google2FAGroupSettings]
)

case class CookieSettings(
  cookieName: String
)

case class OAuthSettings(
  clientId: String,
  clientSecret: String,
  discoveryDocumentUrl: String
)

case class PartnerPlatformSettings(
  ppEnabled: Boolean,
  ppUrl: Option[String],
  ppApiKey: Option[String]
)

case class Google2FAGroupSettings(
  serviceAccountId: String,
  serviceAccountCert: String,
  adminUserEmail: String,
  multifactorGroupId: String
)

object PanDomainAuthSettings{
  private val legacyCookieNameSetting = "assymCookieName"

  def apply(settingMap: Map[String, String]): PanDomainAuthSettings = {
    val cookieSettings = CookieSettings(
      cookieName = settingMap.getOrElse(legacyCookieNameSetting, settingMap("cookieName"))
    )

    val oAuthSettings = OAuthSettings(
      settingMap("clientId"),
      settingMap("clientSecret"),
      settingMap("discoveryDocumentUrl")
    )

    val ppSettings: PartnerPlatformSettings = {
      settingMap.getOrElse("partnerPlatformEnabled", "false").toBoolean match {
        case false =>
          PartnerPlatformSettings(false, None, None)
        case true =>
          PartnerPlatformSettings(true, settingMap.get("partnerPlatformUrl"), settingMap.get("partnerPlatformApiKey"))
      }
    }

    val google2faSettings = for(
      serviceAccountId   <- settingMap.get("googleServiceAccountId");
      serviceAccountCert <- settingMap.get("googleServiceAccountCert");
      adminUser          <- settingMap.get("google2faUser");
      group              <- settingMap.get("multifactorGroupId")
    ) yield {
      Google2FAGroupSettings(serviceAccountId, serviceAccountCert, adminUser, group)
    }

    PanDomainAuthSettings(
      PublicKey(settingMap("publicKey")),
      PrivateKey(settingMap("privateKey")),
      cookieSettings,
      oAuthSettings,
      ppSettings,
      google2faSettings
    )
  }
}