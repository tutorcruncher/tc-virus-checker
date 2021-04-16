import logging
import logging.config


def setup_logging(verbose: bool = False):
    """
    setup logging config by updating the arq logging config
    """
    log_level = 'DEBUG' if verbose else 'INFO'
    config = {
        'version': 1,
        'disable_existing_loggers': False,
        'formatters': {'tcav': {'format': '%(levelname)s %(name)s %(message)s'}},
        'handlers': {
            'tcav': {'level': log_level, 'class': 'logging.StreamHandler', 'formatter': 'tcav'},
            'sentry': {'level': 'WARNING', 'class': 'sentry_sdk.integrations.logging.SentryHandler'},
        },
        'loggers': {
            'tcav': {'handlers': ['tcav', 'sentry'], 'level': log_level},
            'uvicorn.error': {'handlers': ['sentry'], 'level': 'ERROR'},
        },
    }
    logging.config.dictConfig(config)
