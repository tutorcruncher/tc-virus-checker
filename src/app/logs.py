import logging
import logging.config


def setup_logging(verbose: bool = False) -> None:
    log_level = 'DEBUG' if verbose else 'INFO'
    logging.config.dictConfig(
        {
            'version': 1,
            'disable_existing_loggers': False,
            'formatters': {'tcav': {'format': '%(levelname)s %(name)s %(message)s'}},
            'handlers': {
                'tcav': {'level': log_level, 'class': 'logging.StreamHandler', 'formatter': 'tcav'},
            },
            'loggers': {
                'tcav': {'handlers': ['tcav'], 'level': log_level},
            },
        }
    )
