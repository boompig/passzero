module.exports = {
    'env': {
        'browser': true,
        'es2021': true,
    },
    'extends': [
        'plugin:react/recommended',
        'google',
    ],
    'parser': '@typescript-eslint/parser',
    'parserOptions': {
        'ecmaFeatures': {
            'jsx': true,
        },
        'ecmaVersion': 'latest',
    },
    'plugins': [
        'react',
        '@typescript-eslint',
    ],
    'rules': {
        'indent': ['error', 4, {
            'SwitchCase': 1,
        }],
        'object-curly-spacing': ['error', 'always'],
        'valid-jsdoc': 0,
        'require-jsdoc': 0,
        'max-len': ['error', 300],
    },
};
