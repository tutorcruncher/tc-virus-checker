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
        'formatters': {'tc-av': {'format': '%(levelname)s %(name)s %(message)s'}},
        'handlers': {
            'tc-av': {'level': log_level, 'class': 'logging.StreamHandler', 'formatter': 'tc-av'},
            'sentry': {'level': 'WARNING', 'class': 'sentry_sdk.integrations.logging.SentryHandler'},
        },
        'loggers': {
            'tc-av': {'handlers': ['tc-av', 'sentry'], 'level': log_level},
            'uvicorn.error': {'handlers': ['sentry'], 'level': 'ERROR'},
        },
    }
    logging.config.dictConfig(config)
