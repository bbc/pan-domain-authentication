package controllers

import com.gu.pandomainauth.PanDomain
import com.gu.pandomainauth.action.AuthActions
import com.gu.pandomainauth.model.AuthenticatedUser
import play.api.{Configuration, Logger}

trait ExampleAuthActions extends AuthActions {

  def config: Configuration

  override def validateUser(authedUser: AuthenticatedUser): Boolean = {
    Logger.info(s"validating user $authedUser")
    PanDomain.guardianValidation(authedUser)
  }

  /**
    * By default, the user validation method is called every request. If your validation
    * method has side-effects or is expensive (perhaps hitting a database), setting this
    * to true will ensure that validateUser is only called when the OAuth session is refreshed
    */
  override def cacheValidation = false

  override def authCallbackUrl: String = "https://" + config.get[String]("host") + "/oauthCallback"
}
