// @ts-check

import tseslint from 'typescript-eslint';
import globals from 'globals';
import pluginSecurity from 'eslint-plugin-security';

export default tseslint.config(
  // Global ignores
  {
    ignores: [
      '**/node_modules/**',
      '**/dist/**',
      '**/build/**',
      '**/coverage/**',
      // Machine-local pipeline scratch (scripts/ci): the unpacked CodeQL bundle
      // and its database. Thousands of files; never linted, never traversed.
      '.cache/**',
      '**/*.js',
      '**/*.mjs',
      '**/*.cjs',
    ],
  },

  // Base config for all TypeScript files
  {
    files: ['packages/*/src/**/*.{ts,tsx}'],
    extends: [...tseslint.configs.strictTypeChecked, ...tseslint.configs.stylisticTypeChecked],
    plugins: {
      security: pluginSecurity,
    },
    languageOptions: {
      parser: tseslint.parser,
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
      globals: {
        ...globals.es2022,
      },
    },
    rules: {
      // Downgrade some strict rules to warnings for practical development
      '@typescript-eslint/no-unused-vars': [
        'warn',
        {
          argsIgnorePattern: '^_',
          varsIgnorePattern: '^_',
          caughtErrorsIgnorePattern: '^_',
        },
      ],
      '@typescript-eslint/no-floating-promises': 'error',
      '@typescript-eslint/no-misused-promises': 'error',
      '@typescript-eslint/await-thenable': 'error',
      '@typescript-eslint/require-await': 'warn',
      '@typescript-eslint/no-unnecessary-condition': 'warn',
      '@typescript-eslint/restrict-template-expressions': ['warn', { allowNumber: true }],
      '@typescript-eslint/no-confusing-void-expression': ['warn', { ignoreArrowShorthand: true }],

      // Allow empty interfaces/object types for extending patterns
      '@typescript-eslint/no-empty-object-type': [
        'warn',
        { allowInterfaces: 'with-single-extends' },
      ],

      // Security plugin rules
      'security/detect-bidi-characters': 'warn',
      'security/detect-buffer-noassert': 'warn',
      'security/detect-child-process': 'warn',
      'security/detect-disable-mustache-escape': 'warn',
      'security/detect-eval-with-expression': 'warn',
      'security/detect-new-buffer': 'warn',
      'security/detect-no-csrf-before-method-override': 'warn',
      'security/detect-non-literal-fs-filename': 'warn',
      'security/detect-non-literal-regexp': 'warn',
      'security/detect-non-literal-require': 'warn',
      // detect-object-injection disabled: too many false positives on bracket access
      'security/detect-object-injection': 'off',
      'security/detect-possible-timing-attacks': 'warn',
      'security/detect-pseudoRandomBytes': 'warn',
      'security/detect-unsafe-regex': 'warn',
    },
  },

  // Server-specific config (Node.js environment)
  {
    files: ['packages/server/src/**/*.ts'],
    languageOptions: {
      globals: {
        ...globals.node,
      },
    },
  },

  // Client-specific config (Browser + DOM environment)
  {
    files: ['packages/client/src/**/*.{ts,tsx}'],
    languageOptions: {
      globals: {
        ...globals.browser,
      },
    },
  },

  // Shared package config (environment-agnostic)
  {
    files: ['packages/shared/src/**/*.ts'],
    languageOptions: {
      globals: {
        ...globals.es2022,
      },
    },
  },

  // Test files config (relaxed type-checked rules since tests aren't in tsconfig includes)
  {
    files: ['packages/*/tests/**/*.{ts,tsx}'],
    extends: [...tseslint.configs.strict, ...tseslint.configs.stylistic],
    languageOptions: {
      parser: tseslint.parser,
      parserOptions: {
        projectService: false,
      },
      globals: {
        ...globals.es2022,
        ...globals.node,
      },
    },
    rules: {
      '@typescript-eslint/no-unused-vars': [
        'warn',
        {
          argsIgnorePattern: '^_',
          varsIgnorePattern: '^_',
          caughtErrorsIgnorePattern: '^_',
        },
      ],
      '@typescript-eslint/no-empty-object-type': [
        'warn',
        { allowInterfaces: 'with-single-extends' },
      ],
      // Relax rules that are overly strict in test contexts
      '@typescript-eslint/no-unsafe-assignment': 'off',
      '@typescript-eslint/no-unsafe-member-access': 'off',
      '@typescript-eslint/no-unsafe-call': 'off',
      '@typescript-eslint/no-unsafe-argument': 'off',
      '@typescript-eslint/no-explicit-any': 'warn',
      '@typescript-eslint/no-non-null-assertion': 'off',
      '@typescript-eslint/no-empty-function': 'off',
    },
  },

  // E2E test files config (Playwright, relaxed rules)
  {
    files: ['e2e/**/*.ts'],
    extends: [...tseslint.configs.strict, ...tseslint.configs.stylistic],
    languageOptions: {
      parser: tseslint.parser,
      parserOptions: {
        projectService: false,
      },
      globals: {
        ...globals.es2022,
        ...globals.node,
      },
    },
    rules: {
      '@typescript-eslint/no-unused-vars': [
        'warn',
        {
          argsIgnorePattern: '^_',
          varsIgnorePattern: '^_',
          caughtErrorsIgnorePattern: '^_',
        },
      ],
      '@typescript-eslint/no-empty-object-type': [
        'warn',
        { allowInterfaces: 'with-single-extends' },
      ],
      '@typescript-eslint/no-unsafe-assignment': 'off',
      '@typescript-eslint/no-unsafe-member-access': 'off',
      '@typescript-eslint/no-unsafe-call': 'off',
      '@typescript-eslint/no-unsafe-argument': 'off',
      '@typescript-eslint/no-explicit-any': 'warn',
      '@typescript-eslint/no-non-null-assertion': 'off',
      '@typescript-eslint/no-empty-function': 'off',
    },
  },
);
