validation_dict = {
    'account': {
        'remember_login': {
            'default': 0,
            'type': 'int',
            'range': [1, 1],
            're': r'^[0,1]$'
        },
        'auto_login': {
            'default': 0,
            'type': 'int',
            'range': [1, 1],
            're': r'^[0,1]$'
        },
    },
    'keyring': {
        'username': {
            'default': '',
            'type': 'str',
            'range': [5, 360],
            're': r'^[a-zA-Z0-9.! #$%&\'*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*$'
        }
    },
    'build': {
        'base_url': {
            'default': 'https://test.kovaaks.praetoros.com/',
            'type': 'str',
            'range': [30, 35],
            're': r'^https://(?:test\.){0,1}kovaaks\.praetoros\.com/$'
        }
    },
    'user': {
        'last_tab': {
            'default': 'display_account',
            'type': 'str',
            'range': [1, 64],
            're': r'^display_[a-z0-9_]+$'
        },
        'csv_directory': {
            'default': '',
            'type': 'str',
            'range': [1, 360],
            're': r'^[A-Z]:/(?:/*[\w ]*)*$'
        },
    },
    'settings': {
        'upload_auto': {
            'default': 0,
            'type': 'int',
            'range': [1, 1],
            're': r'^[0-9]$'
        },
        'upload_delete_after': {
            'default': 0,
            'type': 'int',
            'range': [1, 1],
            're': r'^[0,1]$'
        },
    },
}
