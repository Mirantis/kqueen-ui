from kqueen_ui.config import current_config


class AuthModules():
    """
    Authentication Modules

    To define new module, need to specify it as dictionary, where:

    self.auth_option_lower_case = {"label": "EqualsToCommonLabelNaming",
                                   "notify": bool_value_enable_email_notifications
                                   }
    """

    def __init__(self):

        config = current_config()

        self.local = {"label": "Local",
                      "notify": config.get("LOCAL_AUTH_NOTIFY")
                      }
        self.ldap = {"label": "LDAP",
                     "notify": config.get("LDAP_AUTH_NOTIFY")
                     }
